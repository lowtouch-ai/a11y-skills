#!/usr/bin/env python3
"""Compare a scan JSON against counts taken from the WAVE extension.

Usage: python compare.py scan.json wave_counts.json

wave_counts.json maps WAVE item IDs (see references/wave-rule-catalog.json) to counts, e.g.
  {"alt_missing": 29, "link_empty": 3, "contrast": 2, "h1": 1}
Items WAVE did not show can be omitted (treated as 0).
"""
import json
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):      # never crash on characters the console encoding cannot show (e.g. cp1252 on Windows)
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

def load(path, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"compare: cannot read {what} '{path}': {e}")


if len(sys.argv) != 3:
    raise SystemExit("usage: compare.py SCAN.json WAVE_COUNTS.json")
scan = load(sys.argv[1], "scan result")
wave = load(sys.argv[2], "WAVE counts")
if not isinstance(scan, dict) or "results" not in scan:
    raise SystemExit("compare: the first file is not a scan result written by scan.py (no 'results' key)")
if not isinstance(wave, dict) or not all(isinstance(v, int) for v in wave.values()):
    raise SystemExit('compare: WAVE counts must be a JSON object of item id to integer, e.g. {"alt_missing": 29}')
mine = {rid: len(v) for cat in scan["results"].values() for rid, v in cat.items()}
ids = sorted(set(mine) | set(wave))
same = 0
print(f"{'item':26}{'ours':>6}{'WAVE':>6}  status")
for i in ids:
    o, w = mine.get(i, 0), wave.get(i, 0)
    st = "match" if o == w else ("we over-report" if o > w else "we under-report")
    same += o == w
    print(f"{i:26}{o:>6}{w:>6}  {st}")
print(f"\n{same}/{len(ids)} items match exactly ({100 * same // max(len(ids), 1)}%)")
