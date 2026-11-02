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
sys.exit(1 if missing else 0)
