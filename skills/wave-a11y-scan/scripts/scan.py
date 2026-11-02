#!/usr/bin/env python3
"""Scan pages with WAVE-style accessibility checks and write a client-ready report.

Usage:
  python scan.py URL [URL ...] [--out DIR] [--format md,html,json]
"""
import argparse
import datetime as dt
import html
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
SKILL = HERE.parent
CATALOG = json.loads((SKILL / "references" / "wave-rule-catalog.json").read_text(encoding="utf-8"))
CHECKS_JS = (HERE / "wave_checks.js").read_text(encoding="utf-8")
VERSION = "0.1.0"

CATEGORIES = [  # (key, report label, how to read it)
    ("error", "Errors", "Fail. Problems that will block some users."),
    ("contrast", "Contrast Errors", "Fail. Text below WCAG 1.4.3 contrast ratio."),
    ("alert", "Alerts", "Needs manual review. Not a confirmed failure."),
    ("feature", "Features", "Accessibility features that are present."),
    ("structure", "Structural Elements", "Headings, landmarks, lists and tables found."),
    ("aria", "ARIA", "ARIA found on the page. Presence only; not a correctness check."),
]
LABEL = {k: l for k, l, _ in CATEGORIES}
READ = {k: r for k, _, r in CATEGORIES}

# Success criteria added after WCAG 2.0. Revised Section 508 (E205.4) incorporates WCAG 2.0 A and AA only.
WCAG_21_PLUS = {"1.3.4", "1.3.5", "1.4.10", "1.4.11", "1.4.12", "1.4.13", "2.1.4", "2.2.6", "2.3.3", "2.5.1", "2.5.2", "2.5.3",
                "2.5.4", "2.5.5", "2.5.6", "2.4.11", "2.4.12", "2.4.13", "2.5.7", "2.5.8", "3.2.6", "3.3.7", "3.3.8", "3.3.9", "4.1.3"}

RULES = {r["name"]: r for r in CATALOG}


def sc_list(rule_id):
    out = []
    for g in RULES.get(rule_id, {}).get("guidelines", []):
        m = re.match(r"(\d+\.\d+\.\d+)\s+(.*?)\s+\(Level (A+)\)", g["name"])
        if m:
            out.append({"sc": m.group(1), "name": m.group(2), "level": m.group(3), "link": g["link"]})
    return out


def sc_text(rule_id):
    s = sc_list(rule_id)
    return ", ".join(f"{x['sc']} ({x['level']})" for x in s) if s else "none listed by WAVE"


def s508(rule_id):
    s = sc_list(rule_id)
    if not s:
        return "n/a"
    req = [x["sc"] for x in s if x["sc"] not in WCAG_21_PLUS]
    return "Yes (WCAG 2.0 " + "/".join(sorted({x["level"] for x in s if x["sc"] in req})) + ")" if req else "No (WCAG 2.1+ only)"


def scan(url, a):
    from playwright.sync_api import sync_playwright
    w, h = (int(x) for x in a.viewport.split("x"))
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--disable-blink-features=AutomationControlled"])
        ctx = b.new_context(viewport={"width": w, "height": h}, locale="en-US",
                            storage_state=a.storage_state or None, user_agent=a.user_agent or None)
        pg = ctx.new_page()
        pg.goto(url, wait_until="load", timeout=a.timeout * 1000)
        pg.wait_for_timeout(a.wait)
        res = pg.evaluate(CHECKS_JS)
        b.close()
    meta = res.pop("_meta")
    blocked = bool(re.match(r"(just a moment|attention required|access denied)", meta["title"], re.I))
    return {"url": url, "scanned_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "viewport": a.viewport, "blocked": blocked, "meta": meta, "results": res}


def counts(page):
    return {k: sum(len(v) for v in page["results"].get(k, {}).values()) for k, _, _ in CATEGORIES}


def md_page(page, n):
    r, c = page["results"], counts(page)
    o = [f"## {page['meta']['title'] or page['url']}", f"`{page['url']}` · scanned {page['scanned_at']} · viewport {page['viewport']}", ""]
    if page["blocked"]:
        o += ["> **Warning:** the page returned a bot-protection or access-denied screen. Results below are NOT for the real page.", ""]
    o += ["| Category | Items | Meaning |", "|---|---:|---|"] + [f"| {l} | {c[k]} | {m} |" for k, l, m in CATEGORIES] + [""]
    for k, l, m in CATEGORIES:
        if not r.get(k):
            continue
        o += [f"### {l} ({c[k]})", f"_{m}_", ""]
        for rid, inst in sorted(r[k].items(), key=lambda kv: -len(kv[1])):
            rule = RULES.get(rid, {})
            o += [f"**{rule.get('title', rid)}** (`{rid}`) — {len(inst)}  ", f"{rule.get('summary', '')}  ",
                  f"WCAG: {sc_text(rid)} · Section 508: {s508(rid)}", ""]
            if k in ("error", "contrast", "alert"):
                for i in inst[:n]:
                    extra = ""
                    if k == "contrast":
                        extra = f" — ratio {i['ratio']}:1 (needs {i['min']}:1), text {i['fg']} on {i['bg']}, {i['size']}"
                    o.append(f"- `{i['sel']}`{extra}  \n  `{(i['html'] or '')[:120]}`")
                if len(inst) > n:
                    o.append(f"- … {len(inst) - n} more (see JSON)")
                o.append("")
    u = page["meta"]["contrastUndeterminedBgImage"]
    if u:
        o += [f"_Contrast could not be computed for {u} text element(s) over background images. Check these manually._", ""]
    return o


def sc_rollup(pages):
    roll = {}
    for pg in pages:
        for k in ("error", "contrast", "alert"):
            for rid, inst in pg["results"].get(k, {}).items():
                for x in sc_list(rid):
                    e = roll.setdefault(x["sc"], {"name": x["name"], "level": x["level"], "fail": 0, "review": 0, "rules": set()})
                    e["fail" if k != "alert" else "review"] += len(inst)
                    e["rules"].add(rid)
    return dict(sorted(roll.items(), key=lambda kv: [int(p) for p in kv[0].split(".")]))


def build_md(pages, a):
    o = [f"# Accessibility scan report{': ' + a.title if a.title else ''}", "",
         f"Generated {dt.date.today().isoformat()} by wave-a11y-scan {VERSION} (WAVE-style checks, WCAG 2.x A/AA, Section 508 mapping).", "",
         "## How to read this report", "",
         "- **Errors** and **Contrast Errors** are failures. **Alerts** need a person to confirm. Features, Structure and ARIA are informational.",
         "- Automated checks cover only part of WCAG. A page with no errors is not proven accessible. Manual keyboard and screen-reader testing is still required.",
         "- Every finding lists the WCAG success criteria WAVE associates with it. Section 508 (revised, 2017) incorporates WCAG 2.0 Level A and AA, so criteria added in WCAG 2.1+ are marked as not required by 508.", ""]
    if len(pages) > 1:
        o += ["## Summary across pages", "", "| Page | " + " | ".join(l for _, l, _ in CATEGORIES) + " |", "|---|" + "---:|" * len(CATEGORIES)]
        for pg in pages:
            c = counts(pg)
            o.append(f"| {pg['url']} | " + " | ".join(str(c[k]) for k, _, _ in CATEGORIES) + " |")
        o.append("")
    roll = sc_rollup(pages)
    o += ["## WCAG success criteria affected", "", "| SC | Name | Level | Failures | To review | Rules |", "|---|---|---|---:|---:|---|"]
    o += [f"| {sc} | {e['name']} | {e['level']} | {e['fail']} | {e['review']} | {', '.join(sorted(e['rules']))} |" for sc, e in roll.items()] or ["| – | none | | | | |"]
    o.append("")
    for pg in pages:
        o += md_page(pg, a.max_instances)
    impl = set(pages[0]["meta"]["implemented"])
    missing = [r["name"] for r in CATALOG if r["name"] not in impl]
    o += ["## Coverage and limitations", "",
          f"- Rules in WAVE catalog: {len(CATALOG)}; implemented here: {len(CATALOG) - len(missing)}. Not implemented: {', '.join(missing) or 'none'}.",
          "- This tool reproduces WAVE's rule set and approximates its detection thresholds. Counts can differ slightly from the WAVE extension; run `compare.py` against a WAVE run to quantify.",
          "- Hidden content is evaluated, as WAVE does. Content that only appears after interaction (menus, dialogs, tabs) is not seen unless it is in the DOM at scan time.",
          "- Contrast over background images and gradients is not computed.", ""]
    return "\n".join(o)


def build_html(md_text, a):
    """Small Markdown-subset renderer (headings, tables, lists, code, bold/italic) so the report has no dependencies."""
    inline = lambda s: re.sub(r"_(.+?)_", r"<em>\1</em>", re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(s, quote=False))))
    out, tbl, ul = [], [], False
    def flush():
        nonlocal tbl, ul
        if tbl:
            rows = [r for r in tbl if not re.match(r"^\|[-: |]+\|$", r)]
            cell = lambda r: [c.strip() for c in r.strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cell(rows[0])) + "</tr></thead><tbody>" +
                       "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cell(r)) + "</tr>" for r in rows[1:]) + "</tbody></table>")
            tbl = []
        if ul:
            out.append("</ul>"); ul = False
    for line in md_text.split("\n"):
        if line.startswith("|"):
            tbl.append(line); continue
        flush()
        m = re.match(r"^(#{1,3}) (.*)", line)
        if m:
            out.append(f"<h{len(m[1])}>{inline(m[2])}</h{len(m[1])}>")
        elif line.startswith("- "):
            if not ul: out.append("<ul>"); ul = True
            out.append(f"<li>{inline(line[2:])}</li>")
        elif line.startswith("> "):
            out.append(f"<p class='warn'>{inline(line[2:])}</p>")
        elif line.startswith("  `"):
            out.append(f"<li class='snip'>{inline(line.strip())}</li>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    flush()
    css = ("body{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1b1f23;background:#fff}"
           "table{border-collapse:collapse;margin:1rem 0;width:100%}th,td{border:1px solid #c8ccd0;padding:.35rem .6rem;text-align:left;vertical-align:top}"
           "th{background:#eef1f4}code{background:#f1f3f5;padding:0 .25em;word-break:break-all}.warn{background:#fff3cd;border:1px solid #e0c36a;padding:.6rem}"
           "li.snip{list-style:none;color:#555}h2{border-bottom:1px solid #c8ccd0;padding-bottom:.2rem;margin-top:2rem}")
    return f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Accessibility scan report</title><style>{css}</style></head><body><main>{''.join(out)}</main></body></html>"


def slug(url):
    u = urlparse(url)
    return re.sub(r"[^a-z0-9]+", "-", (u.netloc + u.path).lower()).strip("-") or "page"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("urls", nargs="+")
    ap.add_argument("--out", default="a11y-report")
    ap.add_argument("--format", default="md,html,json")
    ap.add_argument("--title", default="", help="Client or project name for the report heading")
    ap.add_argument("--viewport", default="1280x900")
    ap.add_argument("--wait", type=int, default=2000, help="ms to wait after load")
    ap.add_argument("--timeout", type=int, default=60, help="navigation timeout in seconds")
    ap.add_argument("--max-instances", type=int, default=10, help="examples listed per rule in md/html")
    ap.add_argument("--storage-state", help="Playwright storage-state JSON for logged-in scans")
    ap.add_argument("--user-agent")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    fmts = set(a.format.split(","))
    pages = []
    for u in a.urls:
        print(f"Scanning {u} ...", file=sys.stderr)
        pg = scan(u, a)
        pages.append(pg)
        if pg["blocked"]:
            print(f"  WARNING: {u} returned a bot-protection/denied page ('{pg['meta']['title']}').", file=sys.stderr)
        c = counts(pg)
        print("  " + "  ".join(f"{LABEL[k]}={c[k]}" for k in c), file=sys.stderr)
        if "json" in fmts:
            (out / f"{slug(u)}.json").write_text(json.dumps(pg, indent=1), encoding="utf-8")
    md = build_md(pages, a)
    if "md" in fmts:
        (out / "report.md").write_text(md, encoding="utf-8")
    if "html" in fmts:
        (out / "report.html").write_text(build_html(md, a), encoding="utf-8")
    print(f"Report written to {out.resolve()}", file=sys.stderr)
    return 2 if any(p["blocked"] for p in pages) else 0


if __name__ == "__main__":
    sys.exit(main())
