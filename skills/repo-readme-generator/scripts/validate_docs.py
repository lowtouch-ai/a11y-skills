#!/usr/bin/env python3
"""Validate a documentation suite: README.md, AGENTS.md and docs/**/*.md plus SVG diagrams.

Runs the README checks (links, anchors, referenced files, commands, Mermaid, fences, secrets) on every
Markdown file, then suite checks: docs linked from the README, template leftovers, SVG safety and
accessibility, diagram specs vs rendered SVGs, AGENTS.md size. Static only; nothing is executed.

Usage: python validate_docs.py [--root REPO] [--docs-dir docs] [--json] [--strict]
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_readme as vr  # noqa: E402

for _stream in (sys.stdout, sys.stderr):      # never crash on characters the console encoding cannot show (e.g. cp1252 on Windows)
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

AGENTS_LIMIT = 32 * 1024     # Codex reads AGENTS.md up to project_doc_max_bytes (32 KiB by default); longer files are truncated
LEFTOVER = re.compile(r"\{\{[^}]*\}\}|<(?:PLACEHOLDER|REPLACE[ _-]?ME|project[ -]name|your[ -][\w -]+)>|\bREPLACE_ME\b|\bLorem ipsum\b|\bTODO: fill", re.I)


def md_files(root, docs_dir):
    out = [p for p in (root / "README.md", root / "AGENTS.md", root / "CLAUDE.md", root / "CONTRIBUTING.md") if p.exists()]
    d = root / docs_dir
    if d.is_dir():
        out += sorted(d.rglob("*.md"))
    return out


def check_svg(p, root, referenced, items):
    rel = p.relative_to(root).as_posix()
    def add(level, check, msg):
        items.append({"level": level, "check": check, "message": msg, "file": rel, "line": None})
    try:
        txt = p.read_text(encoding="utf-8")
        tree = ET.fromstring(txt)
    except Exception as e:
        add("ERROR", "svg", f"Not well-formed XML: {e}"); return
    if not tree.tag.endswith("svg"):
        add("ERROR", "svg", "Root element is not <svg>"); return
    if len(txt) > 1_000_000:
        add("WARN", "svg", "SVG larger than 1 MB")
    if not tree.get("viewBox"):
        add("WARN", "svg", "Missing viewBox (diagram will not scale)")
    names = {el.tag.split("}")[-1] for el in tree.iter()}
    if "title" not in names:
        add("WARN", "svg", "No <title>; screen readers get no name for the diagram")
    if "desc" not in names:
        add("WARN", "svg", "No <desc>; add a text description of what the diagram shows")
    if "script" in names or any(a.lower().startswith("on") for el in tree.iter() for a in el.attrib):
        add("ERROR", "svg", "SVG contains <script> or event-handler attributes (GitHub strips them; unsafe elsewhere)")
    if "foreignObject" in names:
        add("WARN", "svg", "<foreignObject> is not rendered consistently (GitHub, image viewers); use plain <text>")
    for el in tree.iter():
        for k, v in el.attrib.items():
            if k.split("}")[-1] == "href" and re.match(r"^https?:", v):
                add("WARN", "svg", f"External reference in SVG: {v[:60]}")
    if not any((el.text or "").strip() for el in tree.iter() if el.tag.split("}")[-1] == "text"):
        add("WARN", "svg", "SVG has no text labels")
    if rel not in referenced:
        add("WARN", "svg", "Diagram is not referenced from any Markdown file")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--docs-dir", default="docs")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    files = md_files(root, a.docs_dir)
    if not files:
        print("No README.md, AGENTS.md or docs/ found.", file=sys.stderr); return 2
    items = []
    referenced = set()
    link_re = re.compile(r"!?\[[^\]]*\]\(([^)\s#]+)(?:#[^)\s]*)?(?:\s+\"[^\"]*\")?\)")
    texts = {}
    for p in files:
        rel = p.relative_to(root).as_posix()
        md = p.read_text(encoding="utf-8", errors="replace")
        texts[rel] = md
        heads, fences, prose = vr.parse(md)
        r = vr.R()
        is_readme = p.name == "README.md" and p.parent == root
        if is_readme:
            vr.check_sections(heads, r)
        elif len([h for h in heads if h[0] == 1]) != 1:
            r.add("WARN", "structure", f"Expected exactly one H1, found {len([h for h in heads if h[0] == 1])}")
        vr.check_toc_and_anchors(md, heads, prose, r, toc_required=is_readme)
        vr.check_links_and_paths(prose, root, p.parent, r)
        vr.check_fences(fences, r)
        vr.check_mermaid(fences, r, require=is_readme)
        vr.check_commands(fences, root, r)
        vr.check_secrets(md, r)
        for m in LEFTOVER.finditer(md):
            line = md[:m.start()].count("\n") + 1
            r.add("ERROR", "template", f"Unreplaced template text: {m.group(0)[:40]}", line)
        if p.parent != root and len(md.strip().splitlines()) < 12:
            r.add("WARN", "stub", "Very short document; fill it or remove it and its link")
        if p.name == "AGENTS.md":
            if len(md.encode("utf-8")) > AGENTS_LIMIT:
                r.add("WARN", "agents", f"AGENTS.md is {len(md.encode('utf-8'))//1024} KiB; Codex reads only the first 32 KiB by default. Move detail into docs/ and link it")
            if "```" not in md and not re.search(r"\|\s*`[^`]+`\s*\|", md):
                r.add("WARN", "agents", "AGENTS.md has no command blocks; agents need exact build/test/lint commands")
        for it in r.items:
            if it["check"] == "labels":
                continue
            items.append({**it, "file": rel})
        for m in link_re.finditer(md):
            t = m.group(1)
            if not re.match(r"^(https?:|mailto:|tel:)", t):
                referenced.add((Path(rel).parent / t).as_posix().replace("./", "") if not t.startswith("/") else t.lstrip("/"))
    referenced = {os.path.normpath(r_).replace("\\", "/") for r_ in referenced}     # resolve "a/../b"
    # suite: every docs page reachable from the README or docs index
    for rel in texts:
        if rel.startswith(a.docs_dir + "/") and os.path.normpath(rel) not in referenced:
            items.append({"level": "WARN", "check": "index", "message": "Not linked from README.md or any other doc", "file": rel, "line": None})
    # SVGs and diagram specs
    d = root / a.docs_dir
    svgs = sorted(p for p in root.rglob("*.svg") if not (set(p.relative_to(root).parts) & {"node_modules", ".git", "dist", "build"})
                  and p.relative_to(root).as_posix() in referenced | {q.relative_to(root).as_posix() for q in (d.rglob("*.svg") if d.is_dir() else [])})
    for p in svgs:
        check_svg(p, root, referenced, items)
    for spec in (sorted(d.rglob("src/*.json")) if d.is_dir() else []):
        svg = spec.parent.parent / (spec.stem + ".svg")
        rel = spec.relative_to(root).as_posix()
        if not svg.exists():
            items.append({"level": "ERROR", "check": "diagram-spec", "message": f"No rendered SVG for this spec (expected {svg.relative_to(root).as_posix()}); run make_svg.py", "file": rel, "line": None})
        elif spec.stat().st_mtime > svg.stat().st_mtime + 1:
            items.append({"level": "WARN", "check": "diagram-spec", "message": "Spec is newer than its SVG; re-run make_svg.py", "file": rel, "line": None})
    n = {k: sum(1 for i in items if i["level"] == k) for k in ("ERROR", "WARN")}
    if a.json:
        print(json.dumps(items, indent=1))
    else:
        order = {"ERROR": 0, "WARN": 1, "INFO": 2}
        for it in sorted(items, key=lambda x: (order[x["level"]], x["file"], x["line"] or 0)):
            loc = f":{it['line']}" if it["line"] else ""
            print(f"{it['level']:5} [{it['check']}] {it['file']}{loc} {it['message']}")
        print(f"\n{len(files)} markdown file(s), {len(svgs)} SVG(s): {n['ERROR']} error(s), {n['WARN']} warning(s). Static checks only; commands were not executed and Mermaid was not rendered.")
    return 1 if n["ERROR"] or (a.strict and n["WARN"]) else 0


if __name__ == "__main__":
    sys.exit(main())
