#!/usr/bin/env python3
"""Validate a README against the repository: sections, links, anchors, file refs, commands, Mermaid, secrets.

Static checks only; nothing is executed. Exit code 1 if any ERROR is found.

Usage: python validate_readme.py [README_PATH] [--root REPO] [--json] [--strict]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote

REQUIRED = [  # (label, regex matched against heading text)
    ("Project Overview", r"overview|about|introduction"),
    ("Technology Stack", r"tech(nology)? stack|built with|technolog"),
    ("High-Level Logical Architecture", r"architecture"),
    ("Component Inventory", r"component"),
    ("Repository Structure", r"(repository|repo|project|directory|folder) (structure|layout)|structure"),
    ("Application Execution Flow", r"execution flow|application flow|startup|data flow|request flow|how it works"),
    ("Development Prerequisites", r"prerequisite|requirements"),
    ("Local Development Setup", r"(local )?(development )?setup|getting started|installation"),
    ("Build Instructions", r"build"),
    ("Running the Application", r"running|run the|usage"),
    ("Testing", r"test"),
    ("Configuration", r"configuration|environment variable"),
    ("APIs and Interfaces", r"api|interface|endpoint"),
    ("Deployment Architecture", r"deploy"),
    ("Troubleshooting", r"troubleshoot|faq|common issues"),
    ("Development Guidelines", r"guideline|convention|contributing|code style"),
    ("Known Limitations and Future Work", r"limitation|future work|roadmap|known issues"),
]
MERMAID_TYPES = ("flowchart", "graph", "sequenceDiagram", "classDiagram", "stateDiagram", "erDiagram", "gantt", "journey", "pie", "gitGraph", "mindmap",
                 "timeline", "C4Context", "C4Container", "C4Component", "C4Deployment", "architecture-beta", "block-beta", "quadrantChart", "requirementDiagram")
SECRETS = [(r"AKIA[0-9A-Z]{16}", "AWS access key"), (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "private key"),
           (r"gh[pousr]_[A-Za-z0-9]{30,}", "GitHub token"), (r"sk-[A-Za-z0-9]{20,}", "API key (sk-)"), (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
           (r"(?i)\b(secret|token|passw(?:or)?d|api[_-]?key)\b\s*[=:]\s*['\"]?(?!<|\$|\{|your|changeme|example|xxx|\*|TBD|none|null|true|false)[A-Za-z0-9/+_\-]{16,}", "possible hard-coded credential")]
GENERATED = {"node_modules", "dist", "build", "target", "coverage", ".venv", "venv", "__pycache__", ".next", ".cache", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "Pipfile.lock", "go.sum", "bin", "obj"}
SHELL_LANGS = {"bash", "sh", "shell", "console", "zsh", "powershell", "ps1", "cmd", "bat"}
PATH_EXT = r"(?:md|json|ya?ml|toml|py|js|jsx|ts|tsx|go|rs|java|kt|cs|rb|php|sh|ps1|sql|tf|txt|cfg|ini|env|html|css|xml|lock|gradle|properties|conf|dockerfile)"

for _stream in (sys.stdout, sys.stderr):      # never crash on characters the console encoding cannot show (e.g. cp1252 on Windows)
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass


class R:
    def __init__(self):
        self.items = []
    def add(self, level, check, msg, line=None):
        self.items.append({"level": level, "check": check, "message": msg, "line": line})


def slugify(h):
    h = re.sub(r"<[^>]+>", "", h.strip().lower())
    h = re.sub(r"[^\w\- ]", "", h, flags=re.U)
    return h.replace(" ", "-")


def parse(md):
    """Return (headings, fences, prose_lines). fences: list of (lang, start_line, [lines], closed)."""
    heads, fences, prose = [], [], []
    cur = None
    for i, line in enumerate(md.splitlines(), 1):
        m = re.match(r"^\s*(```+|~~~+)\s*([\w+-]*)", line)
        if m and cur is None:
            cur = [m.group(2).lower(), i, [], False, m.group(1)[0]]
            continue
        if cur is not None:
            if re.match(r"^\s*" + re.escape(cur[4]) + r"{3,}\s*$", line):
                cur[3] = True; fences.append(tuple(cur[:4])); cur = None
            else:
                cur[2].append(line)
            continue
        if prose and re.match(r"^(=+|-{2,})\s*$", line):                # Setext heading: previous text line is the title
            pi, pl = prose[-1]
            if pl.strip() and not re.match(r"^\s*([#>|*+]|-\s|\d+[.)]\s)", pl) and not pl.lstrip().startswith("```"):
                heads.append((1 if line.startswith("=") else 2, pl.strip(), pi))
                prose.append((i, line))
                continue
        prose.append((i, line))
        h = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if h:
            heads.append((len(h.group(1)), h.group(2), i))
    if cur is not None:
        fences.append(tuple(cur[:3]) + (False,))
    return heads, fences, prose


def check_sections(heads, r):
    h1 = [h for h in heads if h[0] == 1]
    if len(h1) != 1:
        r.add("WARN", "structure", f"Expected exactly one H1, found {len(h1)}")
    names = [h[1].lower() for h in heads if h[0] in (2, 3)]
    used = set()                      # each required section needs its own heading ("Running tests" cannot satisfy both Running and Testing)
    for label, pat in REQUIRED:
        hit = next((i for i, n in enumerate(names) if i not in used and re.search(pat, n)), None)
        if hit is None:
            r.add("WARN", "sections", f"Missing section: {label}")
        else:
            used.add(hit)


def check_toc_and_anchors(md, heads, prose, r, toc_required=True):
    slugs, seen = set(), {}
    for _, text, _ in heads:
        s = slugify(text)
        n = seen.get(s, 0); seen[s] = n + 1
        slugs.add(s if n == 0 else f"{s}-{n}")
    slugs |= {x.lower() for x in re.findall(r"""(?:id|name)=["']([^"']+)["']""", md)}      # <a id="x"> / <a name="x"> targets
    anchors = [(i, m.group(1)) for i, l in prose for m in re.finditer(r"\]\(#([^)\s]+)\)", l)]
    anchors += [(i, m.group(1)) for i, l in prose for m in re.finditer(r"^\s{0,3}\[[^\]]+\]:\s*<?#(\S+?)>?\s*$", l)]
    if toc_required and len(anchors) < 5:
        r.add("WARN", "toc", "No clickable table of contents detected (expected several in-page `](#anchor)` links)")
    for i, a in anchors:
        if a.lower() not in slugs:
            r.add("ERROR", "anchor", f"Anchor #{a} does not match any heading", i)


def known_paths(root):
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", ".next", "site-packages"}
    out = set()
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip]
        base = Path(dp).relative_to(root)
        for n in dns + fns:
            out.add((base / n).as_posix())
        if len(out) > 60000:
            break
    return out


def gitignored(root):
    """Top-level names listed in .gitignore (simple entries only); such paths are legitimately absent from a checkout."""
    out = set()
    try:
        for line in (root / ".gitignore").read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip().strip("/")
            if line and not line.startswith(("#", "!")) and not any(c in line for c in "*?[]"):
                out.add(line.split("/")[0])
    except OSError:
        pass
    return out


def check_links_and_paths(prose, root, readme_dir, r):
    known = known_paths(root)
    ignored = gitignored(root)
    for i, line in prose:
        targets = [m.group(1) for m in re.finditer(r"(?<!\!)\[[^\]]*\]\(<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\)", line)]
        targets += [m.group(1) for m in re.finditer(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+[\"'(].*)?$", line)]    # reference-style definitions
        for t in targets:
            if re.match(r"^(https?:|mailto:|tel:|#)", t) or t.startswith("//"):
                continue
            p = unquote(t.split("#")[0].split("?")[0])
            if p and not (readme_dir / p).exists() and not (root / p.lstrip("/")).exists():
                r.add("ERROR", "link", f"Relative link target not found: {t}", i)
        for m in re.finditer(r"!\[[^\]]*\]\(([^)\s]+)\)", line):
            t = m.group(1)
            if not re.match(r"^(https?:|data:)", t) and not (readme_dir / t.split("?")[0]).exists():
                r.add("ERROR", "image", f"Image not found: {t}", i)
        for m in re.finditer(r"`([^`\s]+)`", line):
            t = m.group(1).rstrip(".,:;")
            if re.match(r"^(https?:|\$|-|<|\.\.\.|~|/)", t) or t.startswith(".env") or any(c in t for c in "*{}<>=|()[]$"):
                continue  # URLs, flags, routes (/health), absolute paths, env files, globs, templates
            if not re.match(r"^[\w.\-/]+$", t) or t.startswith("@") or re.match(r"^\d", t):
                continue
            if not ("/" in t or re.search(r"\.%s$" % PATH_EXT, t, re.I)):
                continue
            cand = t.rstrip("/")
            cand = cand[2:] if cand.startswith("./") else cand
            bare = re.sub(r"^(\.\./)+", "", cand)          # config defaults like ../data/train are relative to a subfolder
            if cand.split("/")[0] in GENERATED or cand in GENERATED or bare.split("/")[0] in ignored or bare.split("/")[0] in GENERATED:
                continue  # dependency folders, build output, lockfiles and .gitignore entries are legitimately absent
            if bare != cand and (bare in known or any(k.endswith("/" + bare) for k in known)):
                continue
            if (root / cand).exists() or (readme_dir / cand).exists() or cand in known or any(k.endswith("/" + cand) for k in known):
                continue
            r.add("WARN", "path-ref", f"Path-like reference not found in repo: `{t}` (fine if it is generated output or external)", i)


def check_fences(fences, r):
    for lang, start, lines, closed in fences:
        if not closed:
            r.add("ERROR", "fence", "Code fence is never closed", start)


def check_mermaid(fences, r, require=True):
    blocks = [f for f in fences if f[0] == "mermaid"]
    if not blocks and require:
        r.add("WARN", "mermaid", "No Mermaid diagram found (an architecture diagram is expected)")
    for _, start, lines, _ in blocks:
        body = [l for l in lines if l.strip() and not l.strip().startswith("%%")]
        if not body:
            r.add("ERROR", "mermaid", "Empty Mermaid block", start); continue
        first = body[0].strip()
        if not first.startswith(MERMAID_TYPES):
            r.add("ERROR", "mermaid", f"First line is not a Mermaid diagram type: '{first[:40]}'", start); continue
        kind = first.split()[0]
        if kind in ("flowchart", "graph") and len(first.split()) < 2:
            r.add("WARN", "mermaid", "flowchart without direction (use TB, LR, ...)", start)
        opens = closes = 0
        flow = kind in ("flowchart", "graph")
        opener = r"^subgraph\b" if flow else (r"^(alt|loop|opt|par|critical|break|rect|box)\b" if kind == "sequenceDiagram" else None)
        for off, l in enumerate(lines, 1):
            s = l.strip()
            if not s or s.startswith("%%"):
                continue
            ln = start + off
            if opener and re.match(opener, s):
                opens += 1
            if opener and re.match(r"^end\s*$", s):
                closes += 1
            plain = re.sub(r'"[^"]*"', '""', s)
            if flow:      # bracket balance is only meaningful for flowchart syntax; ER/class/state use braces as blocks, sequence text is free-form
                for a, b in ("[]", "()", "{}"):
                    if plain.count(a) != plain.count(b):
                        r.add("ERROR", "mermaid", f"Unbalanced '{a}{b}' in: {s[:70]}", ln); break
            # unquoted label containing parentheses/special chars is a classic GitHub render failure
            for m in (re.finditer(r"\b[\w-]+\[([^\]\"\[]*[()/:;,&#<>][^\]\"]*)\]", plain) if flow else []):
                if m.group(1).startswith(("(", "/", "\\")):
                    continue                    # shape markers: [(cylinder)], [/parallelogram/], [\\alt\\]
                r.add("WARN", "mermaid", f"Label with special characters should be quoted: [{m.group(1)[:40]}] -> [\"...\"]", ln)
            if kind in ("flowchart", "graph") and re.search(r"(^|\s|-->|---)end(\s|$|\[|\()", s) and not re.match(r"^end\s*$", s):
                r.add("WARN", "mermaid", "A node id/label named 'end' breaks Mermaid; rename or quote it", ln)
        if opener and opens != closes:
            r.add("ERROR", "mermaid", f"Block/'end' mismatch: {opens} opener(s) vs {closes} 'end'", start)
        if kind in ("flowchart", "graph"):
            ids = set(re.findall(r"^\s*([A-Za-z_][\w-]*)\s*(?:[\[({>]|-->|---|-\.|==)", "\n".join(lines), re.M))
            if len(ids) < 3:
                r.add("WARN", "mermaid", "Flowchart has very few nodes; an architecture diagram should cover all major components", start)


def load_scripts(root):
    out = {"npm": set(), "make": set(), "compose": set()}
    for pj in list(root.glob("package.json")) + list(root.glob("*/package.json")):
        try:
            out["npm"] |= set(json.loads(pj.read_text(encoding="utf-8")).get("scripts", {}))
        except Exception:
            pass
    for mk in list(root.glob("Makefile")) + list(root.glob("makefile")):
        out["make"] |= set(re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", mk.read_text(encoding="utf-8", errors="replace"), re.M))
    for cf in list(root.glob("docker-compose*.y*ml")) + list(root.glob("compose*.y*ml")):
        t = cf.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^services:\s*\n((?:[ \t]+.*\n?|\n)+)", t, re.M)
        if m:
            out["compose"] |= set(re.findall(r"^  ([A-Za-z0-9_.-]+):\s*$", m.group(1), re.M))
    return out


def check_commands(fences, root, r):
    sc = load_scripts(root)
    for lang, start, lines, _ in fences:
        if lang not in SHELL_LANGS:
            continue
        for off, raw in enumerate(lines, 1):
            ln = start + off
            cmd = re.sub(r"^\s*(\$|>|PS [^>]*>)\s*", "", raw).strip()
            if not cmd or cmd.startswith("#") or "TBD" in cmd:
                continue
            m = re.match(r"^npm (?:run(?:-script)? )([\w:.-]+)", cmd) or re.match(r"^(?:yarn|pnpm)(?: run)? ([\w:.-]+)$", cmd)
            if m and (root / "package.json").exists():
                if m.group(1) not in sc["npm"] and m.group(1) not in {"install", "add", "init", "ci", "start", "test", "exec", "dlx", "i", "audit", "outdated", "build"}:
                    r.add("ERROR", "command", f"`{cmd}`: script '{m.group(1)}' not in package.json scripts", ln)
                elif m.group(1) in {"start", "test", "build"} and m.group(1) not in sc["npm"] and cmd.startswith("npm run"):
                    r.add("ERROR", "command", f"`{cmd}`: script '{m.group(1)}' not in package.json scripts", ln)
            m = re.match(r"^make ([A-Za-z0-9_.-]+)", cmd)
            if m and sc["make"] and m.group(1) not in sc["make"]:
                r.add("ERROR", "command", f"`{cmd}`: target '{m.group(1)}' not in Makefile", ln)
            elif m and not sc["make"] and not list(root.glob("[Mm]akefile")):
                r.add("ERROR", "command", f"`{cmd}`: no Makefile in repo root", ln)
            m = re.match(r"^docker[ -]compose (?:.* )?(?:up|run|start|logs|restart|exec)\b(?: -[\w-]+)*\s+([A-Za-z0-9][A-Za-z0-9_.-]*)\s*$", cmd)
            if m and sc["compose"] and m.group(1) not in sc["compose"]:
                r.add("WARN", "command", f"`{cmd}`: service '{m.group(1)}' not defined in compose file", ln)
            m = re.match(r"^cd\s+([\w./-]+)\s*$", cmd)
            if m and not m.group(1).startswith("..") and not (root / m.group(1)).exists() and m.group(1) not in ("~", "$HOME"):
                r.add("WARN", "command", f"`{cmd}`: directory not found (ok if created by an earlier step, e.g. git clone)", ln)
            m = re.match(r"^(?:python3?|node|bash|sh|\./|pwsh -File|powershell -File)\s*([\w./-]+\.(?:py|js|sh|ps1|mjs|ts))\b", cmd) or re.match(r"^(\./[\w./-]+)", cmd)
            if m:
                target = m.group(1)
                if not (root / target.lstrip("./")).exists() and not (root / target).exists():
                    r.add("WARN", "command", f"`{cmd}`: file '{target}' not found", ln)


def check_secrets(md, r):
    for i, line in enumerate(md.splitlines(), 1):
        for pat, label in SECRETS:
            if re.search(pat, line):
                r.add("ERROR", "secret", f"Possible secret ({label}); remove it or use a placeholder", i)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("readme", nargs="?", default="README.md")
    ap.add_argument("--root", help="repo root (default: README's directory)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    a = ap.parse_args()
    rp = Path(a.readme).resolve()
    if not rp.exists():
        print(f"README not found: {rp}", file=sys.stderr); return 2
    root = Path(a.root).resolve() if a.root else rp.parent
    md = rp.read_text(encoding="utf-8", errors="replace")
    heads, fences, prose = parse(md)
    r = R()
    check_sections(heads, r)
    check_toc_and_anchors(md, heads, prose, r)
    check_links_and_paths(prose, root, rp.parent, r)
    check_fences(fences, r)
    check_mermaid(fences, r)
    check_commands(fences, root, r)
    check_secrets(md, r)
    tbd = len(re.findall(r"\b(TBD|Planned)\b", md))
    r.add("INFO", "labels", f"{tbd} TBD/Planned marker(s) in the README")
    if a.json:
        print(json.dumps(r.items, indent=1))
    else:
        order = {"ERROR": 0, "WARN": 1, "INFO": 2}
        for it in sorted(r.items, key=lambda x: (order[x["level"]], x["line"] or 0)):
            loc = f" (line {it['line']})" if it["line"] else ""
            print(f"{it['level']:5} [{it['check']}]{loc} {it['message']}")
        n = {k: sum(1 for i in r.items if i["level"] == k) for k in order}
        print(f"\n{n['ERROR']} error(s), {n['WARN']} warning(s). Static checks only; commands were not executed and Mermaid was not rendered.")
    bad = any(i["level"] == "ERROR" or (a.strict and i["level"] == "WARN") for i in r.items)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
