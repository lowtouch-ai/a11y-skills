#!/usr/bin/env python3
"""Scan the violations fixture and check the main rule families fire. Run: python tests/smoke_test.py"""
import json, subprocess, sys, tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
fixture = (root / "tests" / "fixtures" / "violations.html").as_uri()
out = Path(tempfile.mkdtemp())
subprocess.run([sys.executable, str(root / "skills/wave-a11y-scan/scripts/scan.py"), fixture, "--out", str(out)], check=True)
res = json.loads(next(out.glob("*.json")).read_text())["results"]
found = {rid for cat in res.values() for rid in cat}
expect = {"title_invalid", "language_missing", "alt_missing", "alt_suspicious", "link_suspicious", "link_empty", "button_empty",
          "label_missing", "label_orphaned", "contrast", "text_small", "table_layout", "aria_reference_broken",
          "heading_skipped", "region_missing", "link_internal_broken", "h1_missing"}
missing = expect - found
print("OK" if not missing else f"MISSING: {sorted(missing)}")

# error handling: readable failures, partial results kept, bad options rejected
scan = str(root / "skills/wave-a11y-scan/scripts/scan.py")
def sc(*args):
    return subprocess.run([sys.executable, scan, *args], capture_output=True, text=True)
problems = []
r = sc(fixture, "http://127.0.0.1:1/", "--out", str(out / "partial"), "--timeout", "5")
rep = (out / "partial/report.md").read_text(encoding="utf-8") if (out / "partial/report.md").exists() else ""
if r.returncode != 3 or "Pages that could not be scanned" not in rep or "Traceback" in r.stderr:
    problems.append("a failing URL must not abort the run: expected exit 3 and a report listing the failed page")
r = sc("http://127.0.0.1:1/", "--out", str(out / "none"), "--timeout", "5")
if r.returncode != 3 or "Traceback" in r.stderr or (out / "none/report.md").exists():
    problems.append("when no page loads: exit 3, a one-line error, no report")
if sc(fixture, "--format", "pdf").returncode != 2:
    problems.append("an unknown --format must be rejected")
if sc(fixture, "--viewport", "big").returncode != 2:
    problems.append("a malformed --viewport must be rejected")
names = [p.name for p in (out / "partial").glob("*.json")]
if any(len(n) > 90 for n in names):
    problems.append("JSON file names must stay short")
cmp_ = subprocess.run([sys.executable, str(root / "skills/wave-a11y-scan/scripts/compare.py"), "nope.json", "nope2.json"], capture_output=True, text=True)
if "Traceback" in cmp_.stderr or cmp_.returncode == 0:
    problems.append("compare.py must fail with a readable message on bad input")
print("OK (error handling)" if not problems else "PROBLEMS: " + "; ".join(problems))
sys.exit(1 if (missing or problems) else 0)
