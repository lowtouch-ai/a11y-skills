#!/usr/bin/env python3
"""Scan the source fixtures and check the main rule families fire, and that failures are readable. Run: python tests/smoke_test.py"""
import json, subprocess, sys, tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
scan = str(root / "skills/wave-a11y-scan/scripts/scan.py")
fixtures = root / "tests" / "fixtures"
out = Path(tempfile.mkdtemp())


def sc(*args):
    return subprocess.run([sys.executable, scan, *args], capture_output=True, text=True)


problems = []
r = sc(str(fixtures), "--out", str(out / "ok"))
if r.returncode != 0:
    problems.append(f"scan failed: {r.stderr[-300:]}")
res = json.loads((out / "ok/results.json").read_text())["results"] if (out / "ok/results.json").exists() else {}
by_file = {}
for cat in res.values():
    for rid, inst in cat.items():
        for i in inst:
            by_file.setdefault(i["file"], set()).add(rid)
expect = {
    "violations.html": {"title_invalid", "language_missing", "alt_missing", "alt_suspicious", "link_suspicious", "link_empty", "button_empty",
                        "label_missing", "label_orphaned", "contrast", "text_small", "table_layout", "aria_reference_broken",
                        "heading_skipped", "region_missing", "link_internal_broken", "h1_missing"},
    "violations.jsx": {"alt_missing", "alt_suspicious", "link_empty", "link_suspicious", "button_empty", "label_missing", "contrast",
                       "text_small", "heading_skipped", "tabindex"},
}
for f, rules in expect.items():
    miss = rules - by_file.get(f, set())
    if miss:
        problems.append(f"{f}: missing {sorted(miss)}")
# values only known at runtime must never be reported: violations.jsx line 11 is <img src={src} alt={desc}>
for cat in ("error", "alert", "contrast"):
    for inst in res.get(cat, {}).values():
        if any(i["file"] == "violations.jsx" and i["line"] == 11 for i in inst):
            problems.append("violations.jsx:11 has a runtime alt and must not be reported")
print("OK" if not problems else "PROBLEMS: " + "; ".join(problems))

# error handling: readable failures, bad options rejected
r = sc(str(out / "does-not-exist"))
if r.returncode != 3 or "Traceback" in r.stderr:
    problems.append("a missing path must exit 3 with a one-line message")
empty = out / "empty"
empty.mkdir()
(empty / "a.txt").write_text("nothing")
r = sc(str(empty), "--out", str(out / "none"))
if r.returncode != 3 or "Traceback" in r.stderr or (out / "none/report.md").exists():
    problems.append("when no markup is found: exit 3, a one-line message, no report")
if sc(str(fixtures), "--format", "pdf").returncode != 2:
    problems.append("an unknown --format must be rejected")
print("OK (error handling)" if len(problems) == 0 else "PROBLEMS: " + "; ".join(problems))
sys.exit(1 if problems else 0)
