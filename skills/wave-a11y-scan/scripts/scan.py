#!/usr/bin/env python3
"""Scan accessibility problems in source code (HTML, templates, JSX/TSX, Vue, Svelte, Astro) and write a client-ready report.

Usage:
  python scan.py PATH [PATH ...] [--out DIR] [--format md,html,json]

PATH is a file or a directory (scanned recursively). No browser, network or install is needed.
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):      # never crash on characters the console encoding cannot show (e.g. cp1252 on Windows)
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from source_checks import IMPLEMENTED, Project, check_file  # noqa: E402
from source_css import parse_css  # noqa: E402
from source_parser import El, parse, static  # noqa: E402

SKILL = HERE.parent
CATALOG = json.loads((SKILL / "references" / "wave-rule-catalog.json").read_text(encoding="utf-8"))
VERSION = "0.2.0"

CATEGORIES = [  # (key, report label, how to read it)
    ("error", "Errors", "Fail. Problems that will block some users."),
    ("contrast", "Contrast Errors", "Fail. Text below WCAG 1.4.3 contrast ratio."),
    ("alert", "Alerts", "Needs manual review. Not a confirmed failure."),
    ("feature", "Features", "Accessibility features that are present."),
    ("structure", "Structural Elements", "Headings, landmarks, lists and tables found."),
    ("aria", "ARIA", "ARIA found in the code. Presence only; not a correctness check."),
]
LABEL = {k: l for k, l, _ in CATEGORIES}
RULES = {r["name"]: r for r in CATALOG}

# Success criteria added after WCAG 2.0. Revised Section 508 (E205.4) incorporates WCAG 2.0 A and AA only.
WCAG_21_PLUS = {"1.3.4", "1.3.5", "1.4.10", "1.4.11", "1.4.12", "1.4.13", "2.1.4", "2.2.6", "2.3.3", "2.5.1", "2.5.2", "2.5.3",
                "2.5.4", "2.5.5", "2.5.6", "2.4.11", "2.4.12", "2.4.13", "2.5.7", "2.5.8", "3.2.6", "3.3.7", "3.3.8", "3.3.9", "4.1.3"}

MARKUP_EXT = {".html", ".htm", ".xhtml", ".jsx", ".tsx", ".vue", ".svelte", ".astro", ".php", ".erb", ".ejs", ".hbs", ".handlebars",
              ".njk", ".liquid", ".twig", ".jinja", ".jinja2", ".j2", ".cshtml", ".razor", ".blade.php", ".mustache"}
JS_MAYBE_JSX = {".js", ".mjs"}
HTML_LIKE = MARKUP_EXT - {".jsx", ".tsx", ".vue", ".svelte", ".astro"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".nuxt", ".output", "out", "coverage", "vendor", "__pycache__", ".venv", "venv",
             ".svelte-kit", "target", "obj", "storybook-static", ".cache", ".turbo", "bower_components", "__tests__", "__snapshots__"}
SKIP_NAME = re.compile(r"\.(test|spec|stories|story|min)\.|\.min\.|\.d\.ts$")
GLOBAL_CSS = {"global", "globals", "index", "app", "main", "style", "styles", "base", "reset", "normalize"}
MAX_BYTES = 1_000_000


def sc_list(rule_id):
    out = []
    for g in RULES.get(rule_id, {}).get("guidelines", []):
        m = re.match(r"(\d+\.\d+\.\d+) (.*) \(Level (A+)\)", g["name"])
        if m:
            out.append({"sc": m[1], "name": m[2], "level": m[3]})
    return out


def sc_text(rule_id):
    s = sc_list(rule_id)
    return ", ".join(f"{x['sc']} ({x['level']})" for x in s) if s else "none listed in the catalog"


def s508(rule_id):
    s = sc_list(rule_id)
    if not s:
        return "n/a"
    req = [x["sc"] for x in s if x["sc"] not in WCAG_21_PLUS]
    return "Yes (WCAG 2.0 " + "/".join(sorted({x["level"] for x in s if x["sc"] in req})) + ")" if req else "No (WCAG 2.1+ only)"


# ---------------------------------------------------------------- file discovery
def ext_of(p):
    n = p.name.lower()
    return ".blade.php" if n.endswith(".blade.php") else p.suffix.lower()


def collect(paths, include_tests):
    """Returns (markup files, css files, skipped count)."""
    files, css, skipped = [], [], 0
    def take(f):
        nonlocal skipped
        e = ext_of(f)
        if SKIP_NAME.search(f.name) and not include_tests:
            return
        if e == ".css":
            css.append(f)
        elif e in MARKUP_EXT or e in JS_MAYBE_JSX:
            files.append(f)
    for p in paths:
        p = Path(p)
        if p.is_file():
            take(p)
        elif p.is_dir():
            for d, dirs, names in os.walk(p):
                dirs[:] = [x for x in dirs if x not in SKIP_DIRS or include_tests and x in ("__tests__", "__snapshots__")]
                for n in names:
                    take(Path(d) / n)
    return sorted(set(files)), sorted(set(css)), skipped


def read(f):
    if f.stat().st_size > MAX_BYTES:
        return None
    return f.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------- CSS pool
_css_cache = {}


def load_css(path, depth=0):
    """Rules and custom properties of one stylesheet and the stylesheets it @imports."""
    path = Path(path)
    if path in _css_cache:
        return _css_cache[path]
    rules, vars_ = [], {}
    _css_cache[path] = (rules, vars_)
    try:
        if path.is_file() and path.stat().st_size < 2_000_000:
            r, v, imports = parse_css(path.read_text(encoding="utf-8", errors="replace"), base_order=0)
            if depth < 3:
                for i in imports:
                    ir, iv = load_css(path.parent / i, depth + 1)
                    rules += ir
                    vars_.update(iv)
            rules += r
            vars_.update(v)
    except OSError:
        pass
    return rules, vars_


def build_pool(f, text, root, style_blocks, css_by_name, is_doc):
    rules, vars_ = [], {}
    wanted = []
    for m in re.finditer(r"""(?:href|from|import|src)\s*=?\s*['"]([^'"]+\.css)['"]|import\s+['"]([^'"]+\.css)['"]""", text):
        wanted.append(m[1] or m[2])
    for rel in wanted:
        if re.match(r"[a-z]+:", rel):
            continue
        cand = (Path(f).parent / rel) if not rel.startswith("/") else (Path(root) / rel.lstrip("/"))
        if cand.is_file():
            r, v = load_css(cand)
            rules += r
            vars_.update(v)
    if not is_doc:                          # components inherit global styles from the app shell
        for name, p in css_by_name.items():
            if name in GLOBAL_CSS:
                r, v = load_css(p)
                rules += r
                vars_.update(v)
    base = len(rules)
    for css, _line in style_blocks:
        r, v, _ = parse_css(css, base_order=base)
        rules += r
        vars_.update(v)
        base += len(r)
    return rules, vars_


def _normalise_order(rules):
    for i, r in enumerate(rules):
        r.order = i
    return rules


# ---------------------------------------------------------------- scanning
def element_label(el):
    if el is None:
        return None
    s = el.tag
    if el.id:
        s += "#" + el.id
    elif el.classes:
        s += "." + sorted(el.classes)[0]
    return s


def scan_all(paths, include_tests=False):
    files, css_files, _ = collect(paths, include_tests)
    root = Path(paths[0]).resolve() if Path(paths[0]).is_dir() else Path(paths[0]).resolve().parent
    css_by_name = {}
    for c in css_files:
        css_by_name.setdefault(re.sub(r"\.css$", "", c.name.lower()), c)
    parsed, skipped = [], []
    project = Project()
    for f in files:
        e = ext_of(f)
        text = read(f)
        if text is None:
            skipped.append((f, "file larger than 1 MB"))
            continue
        if e in JS_MAYBE_JSX and not re.search(r"from\s+['\"]react['\"]|@jsx|React\.createElement|require\(['\"]react['\"]\)", text):
            continue
        if e in (".jsx", ".tsx") or e in JS_MAYBE_JSX:
            pass
        try:
            tree, styles, _ = parse(text, e)
        except RecursionError:
            skipped.append((f, "markup nested too deeply to parse"))
            continue
        if not any(isinstance(c, El) for c in tree.children) and not any(True for _ in tree.walk()):
            continue
        project.collect(tree)
        parsed.append((f, e, text, tree, styles))
    findings = {k: {} for k, _, _ in CATEGORIES}
    per_file, meta = {}, Counter()
    for f, e, text, tree, styles in parsed:
        is_doc = any(True for x in tree.walk() if x.tag == "html")
        pool = build_pool(f, text, root, styles, css_by_name, is_doc)
        pool = (_normalise_order(pool[0]), pool[1])
        try:
            res, m = check_file(tree, pool, e, e in HTML_LIKE, project)
        except RecursionError:
            skipped.append((f, "markup nested too deeply to check"))
            continue
        try:
            rel = str(f.resolve().relative_to(root))
        except ValueError:
            rel = str(f)
        rel = rel.replace("\\", "/")
        cnt = Counter()
        for cat, rid, el, extra in res:
            findings[cat].setdefault(rid, []).append(
                {"file": rel, "line": el.line if el else None, "sel": element_label(el), "html": el.raw if el else None, **extra})
            cnt[cat] += 1
        per_file[rel] = {k: cnt.get(k, 0) for k, _, _ in CATEGORIES}
        meta["checkedForContrast"] += m["checkedForContrast"]
        meta["contrastUndetermined"] += m["contrastUndetermined"]
    return {"root": str(root), "scanned_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "files_scanned": len(parsed),
            "css_files": len(css_files), "skipped": [(str(a), b) for a, b in skipped], "per_file": per_file,
            "meta": dict(meta), "results": findings}


def counts(scan):
    return {k: sum(len(v) for v in scan["results"].get(k, {}).values()) for k, _, _ in CATEGORIES}


# ---------------------------------------------------------------- report
def sc_rollup(scan):
    roll = {}
    for k in ("error", "contrast", "alert"):
        for rid, inst in scan["results"].get(k, {}).items():
            for x in sc_list(rid):
                e = roll.setdefault(x["sc"], {"name": x["name"], "level": x["level"], "fail": 0, "review": 0, "rules": set()})
                e["fail" if k != "alert" else "review"] += len(inst)
                e["rules"].add(rid)
    return dict(sorted(roll.items(), key=lambda kv: [int(p) for p in kv[0].split(".")]))


def build_md(scan, a):
    r, c = scan["results"], counts(scan)
    o = [f"# Accessibility scan report{': ' + a.title if a.title else ''}", "",
         f"Generated {dt.date.today().isoformat()} by wave-a11y-scan {VERSION}. Static analysis of source code against WCAG 2.x A/AA, with a Section 508 mapping.", "",
         "## How to read this report", "",
         "- **Errors** and **Contrast Errors** are failures. **Alerts** need a person to confirm. Features, Structure and ARIA are informational.",
         "- This is a source-code scan. Anything decided only at runtime (expressions, props, content from other files, utility-class styling) is skipped, not guessed.",
         "- Automated checks cover only part of WCAG. Code with no findings is not proven accessible. Manual keyboard and screen-reader testing is still required.",
         "- Every finding lists its file and line, and the WCAG success criteria it maps to. Section 508 (revised, 2017) incorporates WCAG 2.0 Level A and AA, so criteria added in WCAG 2.1+ are marked as not required by 508.", "",
         "## Scope", "", f"- Path: `{scan['root']}`", f"- Source files analysed: {scan['files_scanned']}  ·  stylesheets available for contrast: {scan['css_files']}"]
    if scan["skipped"]:
        o += ["- Not analysed: " + "; ".join(f"`{f}` ({why})" for f, why in scan["skipped"][:10])]
    o += ["", "| Category | Items | Meaning |", "|---|---:|---|"] + [f"| {l} | {c[k]} | {m} |" for k, l, m in CATEGORIES] + [""]
    worst = sorted(((f, v) for f, v in scan["per_file"].items() if v["error"] + v["contrast"] + v["alert"]),
                   key=lambda kv: (-(kv[1]["error"] + kv[1]["contrast"]), -kv[1]["alert"], kv[0]))
    if worst:
        o += ["## Files with the most findings", "", "| File | Errors | Contrast Errors | Alerts |", "|---|---:|---:|---:|"]
        o += [f"| `{f}` | {v['error']} | {v['contrast']} | {v['alert']} |" for f, v in worst[:a.max_files]]
        if len(worst) > a.max_files:
            o.append(f"| … {len(worst) - a.max_files} more files (see JSON) | | | |")
        o.append("")
    roll = sc_rollup(scan)
    o += ["## WCAG success criteria affected", "", "| SC | Name | Level | Failures | To review | Rules |", "|---|---|---|---:|---:|---|"]
    o += [f"| {sc} | {e['name']} | {e['level']} | {e['fail']} | {e['review']} | {', '.join(sorted(e['rules']))} |" for sc, e in roll.items()] or ["| – | none | | | | |"]
    o.append("")
    for k, l, m in CATEGORIES:
        if not r.get(k):
            continue
        o += [f"## {l} ({c[k]})", f"_{m}_", ""]
        for rid, inst in sorted(r[k].items(), key=lambda kv: -len(kv[1])):
            rule = RULES.get(rid, {})
            nfiles = len({i["file"] for i in inst})
            o += [f"**{rule.get('title', rid)}** (`{rid}`) — {len(inst)} in {nfiles} file{'s' if nfiles != 1 else ''}  ", f"{rule.get('summary', '')}  ",
                  f"WCAG: {sc_text(rid)} · Section 508: {s508(rid)}", ""]
            if k in ("error", "contrast", "alert"):
                for i in inst[:a.max_instances]:
                    extra = ""
                    if k == "contrast":
                        extra = f" — ratio {i['ratio']}:1 (needs {i['min']}:1), text {i['fg']} on {i['bg']}, {i['size']}"
                    elif i.get("note"):
                        extra = f" — {i['note']}"
                    o.append(f"- `{i['file']}:{i['line']}`{extra}  \n  `{(i['html'] or '')[:120]}`")
                if len(inst) > a.max_instances:
                    o.append(f"- … {len(inst) - a.max_instances} more (see JSON)")
                o.append("")
    und = scan["meta"].get("contrastUndetermined", 0)
    chk = scan["meta"].get("checkedForContrast", 0)
    impl = set(IMPLEMENTED)
    missing = [x["name"] for x in CATALOG if x["name"] not in impl]
    o += ["## Coverage and limitations", "",
          f"- Rules in the catalog: {len(CATALOG)}; implemented: {len(CATALOG) - len(missing)}. Not implemented (need a rendered page): {', '.join(missing) or 'none'}.",
          f"- Contrast was computed for {chk} text element(s) whose colours and background could be resolved from CSS and inline styles. {und} element(s) were skipped because a value comes from runtime code, a dynamic class, a background image or gradient, a utility framework, or another file.",
          "- Elements built by components defined elsewhere are not expanded; their content is treated as unknown. References by id are resolved across all scanned files.",
          "- Content that only exists after the app runs (data-driven lists, dialogs, tabs) is checked only to the extent it appears in the source.", ""]
    return "\n".join(o)


def build_html(md_text):
    """Small Markdown-subset renderer (headings, tables, lists, code, bold/italic) so the report has no dependencies."""
    inline = lambda s: re.sub(r"_(.+?)_", r"<em>\1</em>", re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(s, quote=False))))
    out, tbl, ul = [], [], False

    def flush():
        nonlocal tbl, ul
        if tbl:
            rows = [x for x in tbl if not re.match(r"^\|[-: |]+\|$", x)]
            cell = lambda x: [c.strip() for c in x.strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cell(rows[0])) + "</tr></thead><tbody>" +
                       "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cell(x)) + "</tr>" for x in rows[1:]) + "</tbody></table>")
            tbl = []
        if ul:
            out.append("</ul>")
            ul = False

    for line in md_text.split("\n"):
        if line.startswith("|"):
            tbl.append(line)
            continue
        flush()
        m = re.match(r"^(#{1,3}) (.*)", line)
        if m:
            out.append(f"<h{len(m[1])}>{inline(m[2])}</h{len(m[1])}>")
        elif line.startswith("- "):
            if not ul:
                out.append("<ul>")
                ul = True
            out.append(f"<li>{inline(line[2:])}</li>")
        elif line.startswith("  `"):
            out.append(f"<li class='snip'>{inline(line.strip())}</li>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    flush()
    css = ("body{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1b1f23;background:#fff}"
           "table{border-collapse:collapse;margin:1rem 0;width:100%}th,td{border:1px solid #c8ccd0;padding:.35rem .6rem;text-align:left;vertical-align:top}"
           "th{background:#eef1f4}code{background:#f1f3f5;padding:0 .25em;word-break:break-all}"
           "li.snip{list-style:none;color:#555}h2{border-bottom:1px solid #c8ccd0;padding-bottom:.2rem;margin-top:2rem}")
    return f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Accessibility scan report</title><style>{css}</style></head><body><main>{''.join(out)}</main></body></html>"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="source files or directories")
    ap.add_argument("--out", default="a11y-report")
    ap.add_argument("--format", default="md,html,json")
    ap.add_argument("--title", default="", help="Client or project name for the report heading")
    ap.add_argument("--max-instances", type=int, default=10, help="examples listed per rule in md/html")
    ap.add_argument("--max-files", type=int, default=25, help="files listed in the per-file summary")
    ap.add_argument("--include-tests", action="store_true", help="also scan test, spec and story files")
    a = ap.parse_args()
    fmts = {f.strip() for f in a.format.split(",") if f.strip()}
    if not fmts or fmts - {"md", "html", "json"}:
        ap.error(f"--format must be a comma-separated subset of md,html,json (got '{a.format}')")
    missing = [p for p in a.paths if not Path(p).exists()]
    if missing:
        print("scan: path not found: " + ", ".join(missing), file=sys.stderr)
        return 3
    print("Scanning source files ...", file=sys.stderr)
    scan = scan_all(a.paths, a.include_tests)
    if not scan["files_scanned"]:
        print("scan: no markup files found (looked for .html, .jsx, .tsx, .vue, .svelte, .astro and common template types). No report written.", file=sys.stderr)
        return 3
    c = counts(scan)
    print(f"  {scan['files_scanned']} files  " + "  ".join(f"{LABEL[k]}={c[k]}" for k in c), file=sys.stderr)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    md = build_md(scan, a)
    if "json" in fmts:
        (out / "results.json").write_text(json.dumps(scan, indent=1), encoding="utf-8")
    if "md" in fmts:
        (out / "report.md").write_text(md, encoding="utf-8")
    if "html" in fmts:
        (out / "report.html").write_text(build_html(md), encoding="utf-8")
    print(f"Report written to {out.resolve()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
