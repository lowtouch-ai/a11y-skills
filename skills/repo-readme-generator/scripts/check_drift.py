#!/usr/bin/env python3
"""Report where the README has fallen behind the repository (for incremental updates).

Compares discover.py facts with README text, and lists architecture-relevant files changed
since the README was last verified (commit recorded in the README footer comment, else the
README's last commit). Read-only.

Usage: python check_drift.py [README_PATH] [--root REPO] [--docs docs] [--fail-on-drift]

With a docs folder, mentions in README.md, AGENTS.md and docs/**/*.md all count as documented.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):      # never crash on characters the console encoding cannot show (e.g. cp1252 on Windows)
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
RELEVANT = re.compile(r"(^|/)(package\.json|pyproject\.toml|requirements.*\.txt|go\.mod|Cargo\.toml|pom\.xml|build\.gradle(\.kts)?|Gemfile|composer\.json|Makefile|justfile|"
                      r"Dockerfile.*|docker-compose.*|compose.*\.ya?ml|\.env\.example|\.env\.sample|openapi.*|swagger.*|\.github/workflows/.*|.*\.tf|Chart\.yaml|"
                      r"main\.\w+|app\.\w+|server\.\w+|index\.\w+|AGENTS\.md)$|(^|/)(src|app|lib|cmd|services|api|server|backend|frontend|packages|infra|deploy|k8s|helm)/")
import validate_readme as vr  # noqa: E402  (same folder)

SYSTEM_VARS = {"HOME", "PATH", "PWD", "USER", "SHELL", "TERM", "LANG", "TMPDIR", "TEMP", "HOSTNAME", "UID", "OLDPWD", "LOGNAME", "EDITOR", "DISPLAY", "IFS", "PS1", "SHLVL"}
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", ".next", "site-packages"}
MARK = re.compile(r"<!--\s*repo-readme-generator:.*?commit=([0-9a-f]{7,40}).*?-->")


def git(root, *args):
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def mentioned(text, token):
    return re.search(r"(?<![\w-])" + re.escape(token) + r"(?![\w-])", text) is not None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("readme", nargs="?", default="README.md")
    ap.add_argument("--root")
    ap.add_argument("--docs", default="docs", help="documentation folder to include (ignored if missing)")
    ap.add_argument("--fail-on-drift", action="store_true")
    a = ap.parse_args()
    rp = Path(a.readme).resolve()
    root = Path(a.root).resolve() if a.root else rp.parent
    if not rp.exists():
        print("No README yet: run in create mode."); return 0
    text = rp.read_text(encoding="utf-8", errors="replace")
    readme_text = text
    extra = [root / "AGENTS.md"] + (sorted((root / a.docs).rglob("*.md")) if (root / a.docs).is_dir() else [])
    docs_used = [p for p in extra if p.exists() and p != rp]
    for p in docs_used:
        text += "\n" + p.read_text(encoding="utf-8", errors="replace")
    facts = json.loads(subprocess.run([sys.executable, str(HERE / "discover.py"), str(root)], capture_output=True, text=True, check=True).stdout)
    drift = []

    for d in facts["top_level_dirs"]:
        if not mentioned(text, d):
            drift.append(("structure", f"Top-level directory `{d}/` is not mentioned"))
    m = facts["manifests"]
    for pj in m.get("package.json", []):
        for s in pj["scripts"]:
            if not mentioned(text, s):
                drift.append(("commands", f"npm script `{s}` ({pj['file']}) is not documented"))
    for mk in m.get("make", []):
        for t in mk["targets"]:
            if not mentioned(text, t) and t not in ("all", "default", "FORCE"):
                drift.append(("commands", f"make target `{t}` ({mk['file']}) is not documented"))
    for py in m.get("pyproject", []):
        for s in py.get("scripts", {}):
            if not mentioned(text, s):
                drift.append(("commands", f"console script `{s}` ({py['file']}) is not documented"))
    for c in m.get("compose", []):
        for svc in c["services"]:
            if not mentioned(text, svc):
                drift.append(("architecture", f"Compose service `{svc}` ({c['file']}) is not mentioned"))
    for ci in m.get("ci", []):
        if not mentioned(text, Path(ci["file"]).name) and "CI" not in text and "GitHub Actions" not in text:
            drift.append(("deployment", f"CI workflow {ci['file']} is not mentioned"))
    for v in facts["env_vars"]:
        if v not in SYSTEM_VARS and not mentioned(text, v):
            drift.append(("configuration", f"Environment variable `{v}` (used in {facts['env_vars'][v][0]}) is not documented"))
    for e in facts["entry_points"]:
        if e not in text and Path(e).name not in text:
            drift.append(("architecture", f"Entry point `{e}` is not mentioned"))
    for sp in m.get("api_specs", []):
        if sp not in text:
            drift.append(("apis", f"API spec `{sp}` is not linked"))

    # stale references inside the README's directory tree block
    names = set()
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP]
        names.update(dns); names.update(fns)
    ignored = vr.gitignored(root) | vr.GENERATED
    for _lang, _start, blk_lines, _closed in vr.parse(readme_text)[1]:
        connectors = [l for l in blk_lines if re.search(r"[├└]──|\|--|`--", l)]
        if len(connectors) < 2:
            continue                                   # not a directory tree
        for line in connectors:
            n = re.search(r"(?:[├└]──|\|--|`--)\s+([\w.\-@]+/?)", line)
            if n:
                nm = n.group(1).rstrip("/")
                if nm not in names and nm not in ignored:
                    drift.append(("structure", f"Tree entry `{n.group(1)}` no longer exists"))

    base = None
    mk = MARK.search(readme_text)
    if mk and git(root, "cat-file", "-t", mk.group(1)) == "commit":
        base = mk.group(1)
    elif git(root, "rev-parse", "--is-inside-work-tree") == "true":
        base = git(root, "log", "-1", "--format=%H", "--", str(rp.relative_to(root)))
    changed = []
    if base:
        names = git(root, "diff", "--name-only", f"{base}..HEAD") or ""
        changed = [n for n in names.splitlines() if RELEVANT.search(n) and n != rp.name]
        dirty = git(root, "status", "--porcelain") or ""
        changed += [l[3:] for l in dirty.splitlines() if RELEVANT.search(l[3:]) and l[3:] != rp.name]
    print(f"README: {rp}\nAlso read: {len(docs_used)} file(s) (AGENTS.md, {a.docs}/**)\nBaseline commit: {base or 'unknown (not a git repo or README never committed)'}\n")
    if changed:
        print(f"Architecture-relevant files changed since baseline ({len(changed)}):")
        for c in sorted(set(changed))[:60]:
            print(f"  - {c}")
        print()
    if drift:
        print(f"Drift found ({len(drift)}):")
        for area, msg in drift:
            print(f"  [{area}] {msg}")
    else:
        print("No drift detected by static comparison.")
    print("\nHeuristic check: it finds missing mentions, not wrong prose. Re-read changed components before editing.")
    return 1 if (a.fail_on_drift and (drift or changed)) else 0


if __name__ == "__main__":
    sys.exit(main())
