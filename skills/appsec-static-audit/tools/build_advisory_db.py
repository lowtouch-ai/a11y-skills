#!/usr/bin/env python3
"""Maintainer tool: build references/advisory-db.json.gz from OSV.dev bulk dumps.

NOT part of the audit run. The audit itself never touches the network; it only reads the snapshot this tool
writes. Run it from a connected machine, review the diff, commit the result, and refresh it regularly
(the report warns when the snapshot is older than 90 days).

    python3 tools/build_advisory_db.py            # all supported ecosystems
    python3 tools/build_advisory_db.py npm PyPI   # a subset (keeps the other ecosystems from the existing file)

What is kept per advisory: id, aliases (CVE/GHSA), severity, a short summary and the affected version ranges
(ECOSYSTEM / SEMVER events, or explicit version lists). Malware reports (MAL-*) and withdrawn advisories are dropped.
"""
import gzip
import io
import json
import math
import os
import re
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone

BASE = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"
# OSV ecosystem name -> the ecosystem key used by deps.py
ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "golang", "RubyGems": "rubygems",
              "Packagist": "packagist", "NuGet": "nuget", "crates.io": "cargo"}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "references", "advisory-db.json.gz")


# ---- CVSS v3.x base score (enough to rank severity when the advisory has no label) ----
def cvss3(vector):
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
        ac = {"L": .77, "H": .44}[m["AC"]]
        scope_changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[m["PR"]]
        ui = {"N": .85, "R": .62}[m["UI"]]
        cia = {"H": .56, "L": .22, "N": 0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return math.ceil(raw * 10) / 10
    except (KeyError, ValueError):
        return None


def severity_of(v):
    label = str((v.get("database_specific") or {}).get("severity", "")).upper()
    if label in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        return {"MODERATE": "Medium", "MEDIUM": "Medium"}.get(label, label.title())
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss3(s.get("score", ""))
            if score is not None:
                return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
    return "Medium"  # unknown: do not silently drop, do not overstate


def ranges_of(aff):
    """-> list of [introduced, fixed|None, last_affected|None] or an explicit versions list."""
    out = []
    for r in aff.get("ranges") or []:
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        cur = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                cur = [ev["introduced"], None, None]
                out.append(cur)
            elif "fixed" in ev and cur is not None:
                cur[1] = ev["fixed"]
                cur = None
            elif "last_affected" in ev and cur is not None:
                cur[2] = ev["last_affected"]
                cur = None
    return out


def process(eco_osv, eco_key):
    url = BASE.format(eco_osv)
    print(f"  downloading {url}", flush=True)
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        with urllib.request.urlopen(url, timeout=300) as r:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                tmp.write(chunk)
        tmp.flush()
        db = {}
        n = 0
        with zipfile.ZipFile(tmp.name) as z:
            for name in z.namelist():
                if not name.endswith(".json") or os.path.basename(name).startswith("MAL-"):
                    continue
                try:
                    v = json.loads(z.read(name))
                except ValueError:
                    continue
                if v.get("withdrawn") or str(v.get("id", "")).startswith("MAL-"):
                    continue
                sev = severity_of(v)
                ids = [v["id"]] + [a for a in v.get("aliases", []) if a.startswith("CVE-")][:2]
                summary = (v.get("summary") or (v.get("details") or "").split("\n")[0])[:140]
                for aff in v.get("affected", []):
                    pkg = aff.get("package") or {}
                    if pkg.get("ecosystem", "").split(":")[0] != eco_osv:
                        continue
                    pname = pkg.get("name", "")
                    if not pname:
                        continue
                    rng = ranges_of(aff)
                    vers = aff.get("versions") or []
                    if not rng and not vers:
                        continue
                    entry = [ids, sev, summary, rng]
                    if not rng:
                        entry.append(vers[:200])
                    key = pname.lower() if eco_key in ("npm", "pypi", "nuget", "packagist", "rubygems", "cargo") else pname
                    if eco_key == "pypi":
                        key = re.sub(r"[-_.]+", "-", key)
                    db.setdefault(key, []).append(entry)
                    n += 1
        print(f"  kept {n} package advisories for {len(db)} packages", flush=True)
        return db


def main():
    want = sys.argv[1:] or list(ECOSYSTEMS)
    existing = {}
    path = os.path.abspath(OUT)
    if os.path.exists(path):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            existing = json.load(fh).get("ecosystems", {})
    eco = dict(existing)
    for e in want:
        if e not in ECOSYSTEMS:
            sys.exit(f"unknown ecosystem {e}; choose from {', '.join(ECOSYSTEMS)}")
        print(e, flush=True)
        eco[ECOSYSTEMS[e]] = process(e, ECOSYSTEMS[e])
    out = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "source": "OSV.dev bulk export (https://osv.dev)",
           "format": "ecosystems[eco][package] = [[ids, severity, summary, [[introduced, fixed|null, last_affected|null]...], explicit_versions?]]",
           "ecosystems": eco}
    raw = json.dumps(out, separators=(",", ":")).encode()
    with gzip.GzipFile(path, "wb", compresslevel=9, mtime=0) as fh:
        fh.write(raw)
    print(f"wrote {path}: {len(raw)/1e6:.1f} MB raw, {os.path.getsize(path)/1e6:.1f} MB gz")


if __name__ == "__main__":
    main()
