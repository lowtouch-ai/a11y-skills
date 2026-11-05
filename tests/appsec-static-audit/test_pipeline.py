"""Pipeline tests for appsec-static-audit: stable IDs, suppressions, scan-to-scan comparison, excludes, parallel scanning,
verification, checklist behaviour, SARIF and the CI gate.

Run:  python3 -m pytest tests/appsec-static-audit/test_pipeline.py     (or run this file directly)
"""
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import date, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.abspath(os.path.join(HERE, "..", "..", "skills", "appsec-static-audit"))
AUDIT = os.path.join(SKILL, "scripts", "audit.py")
RENDER = os.path.join(SKILL, "scripts", "render_report.py")

VULN_A = 'from flask import request\ndef a():\n    cur.execute("SELECT * FROM t WHERE id=" + request.args["id"])\n'
VULN_B = 'import os\nfrom flask import request\ndef b():\n    os.system("ping " + request.args["h"])\n'


def py(*args, ok=True):
    r = subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True)
    if ok:
        assert r.returncode == 0, f"{args}\n{r.stdout}\n{r.stderr}"
    return r


def write(repo, files):
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)


def audit(repo, out, *extra):
    py(AUDIT, repo, "--out", out, "--no-git-history", *extra)
    with open(os.path.join(out, "scan.json"), encoding="utf-8") as fh:
        return json.load(fh)


def triage_all_confirmed(path, extra=None):
    t = {"meta": {"customer": "T", "assessor": "pytest"}, "bulk": [{"rule": "*", "decision": "confirmed", "reason": "test"}]}
    t.update(extra or {})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(t, fh)
    return path


def render(out, tri, *extra, ok=True):
    r = py(RENDER, "--scan", os.path.join(out, "scan.json"), "--triage", tri, *extra, ok=ok)
    md = None
    if r.returncode == 0:
        path = sorted(glob.glob(os.path.join(out, "security-audit-report_*.md")))[-1]
        md = open(path, encoding="utf-8").read()
    return r, md


def ids_by_rule(scan):
    return {(f["rule"], f["file"]): f["id"] for f in scan["findings"]}


def test_ids_are_stable_across_rescans_and_edits():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A})
        s1 = audit(repo, out)
        id_a = ids_by_rule(s1)[("INJ-SQL-1", "a.py")]
        # shift the line numbers and add another finding: the first keeps its ID, the new one gets a new ID
        write(repo, {"a.py": "# header\n# header\n" + VULN_A, "b.py": VULN_B})
        s2 = audit(repo, out)
        m2 = ids_by_rule(s2)
        assert m2[("INJ-SQL-1", "a.py")] == id_a
        new_id = m2[("INJ-CMD-1", "b.py")]
        assert new_id != id_a and int(new_id.split("-")[1]) > int(id_a.split("-")[1])
        # remove the first: the second keeps its ID (a gap, not a renumber)
        os.remove(os.path.join(repo, "a.py"))
        s3 = audit(repo, out)
        assert ids_by_rule(s3)[("INJ-CMD-1", "b.py")] == new_id


def test_previous_scan_comparison():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A})
        s1 = audit(repo, out)
        assert s1["changes"] is None
        write(repo, {"b.py": VULN_B})
        os.remove(os.path.join(repo, "a.py"))
        s2 = audit(repo, out)
        ch = s2["changes"]
        assert ch["new"] >= 1 and any(g["file"] == "a.py" for g in ch["no_longer_detected"])
        assert {f["delta"] for f in s2["findings"]} == {"new"}
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"))
        _, md = render(out, tri)
        assert "### 3.4 Changes Since the Previous Scan" in md and "No longer detected" in md and "| Since previous scan | New |" in md


def test_suppression_policy():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A, "b.py": VULN_B, "c.py": VULN_B.replace("def b", "def c")})
        supp = os.path.join(tmp, "supp.json")
        soon = (date.today() + timedelta(days=60)).isoformat()
        past = (date.today() - timedelta(days=3)).isoformat()
        json.dump({"suppressions": [
            {"rule": "INJ-SQL-1", "file_regex": "^a\\.py$", "type": "accepted_risk", "reason": "Internal admin tool, input is validated upstream", "owner": "appsec team", "expires": soon},
            {"rule": "INJ-CMD-1", "file_regex": "^b\\.py$", "type": "accepted_risk", "reason": "expired entry", "owner": "x", "expires": past},
            {"rule": "INJ-CMD-1", "file_regex": "^c\\.py$", "type": "false_positive", "reason": "hardcoded host list"},
            {"rule": "INJ-CMD-1", "type": "accepted_risk", "reason": "no expiry given, must be rejected"},
            {"rule": "X", "type": "accepted_risk", "expires": soon}]}, open(supp, "w"))
        s = audit(repo, out, "--suppressions", supp)
        by = {(f["rule"], f["file"]): f for f in s["findings"]}
        assert by[("INJ-SQL-1", "a.py")]["suppression"]["owner"] == "appsec team"
        assert "suppression" not in by[("INJ-CMD-1", "b.py")] and "expired on" in by[("INJ-CMD-1", "b.py")]["detail"]
        assert by[("INJ-CMD-1", "c.py")]["suppression"]["type"] == "false_positive"
        assert s["suppression"]["applied"] == 2 and s["suppression"]["expired"] == 1 and len(s["suppression"]["problems"]) == 2
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"))
        _, md = render(out, tri)
        assert "### 3.3 Accepted Risks and Suppressions" in md and "appsec team" in md
        assert "Suppressed by policy" in md and "hardcoded host list" in md
        confirmed = re.search(r"\| \*\*Total\*\* \| \*\*(\d+)\*\*", md)
        assert confirmed and int(confirmed.group(1)) == len(s["findings"]) - 2, "the two suppressed candidates must not be counted as findings"
        assert by[("INJ-SQL-1", "a.py")]["id"] not in re.search(r"### 3\.2 Findings Register.*?### 3\.3", md, re.S).group(0)


def test_exclude_components_and_metadata():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"services/api/a.py": VULN_A, "services/web/b.py": VULN_B, "tools/c.py": "x = 1\n", "vendor/lib/d.py": VULN_A, "third_party/e.py": VULN_B})
        s = audit(repo, out, "--exclude", "vendor", "--exclude", "third_*")
        names = [c["component"] for c in s["components"]]
        assert "services/api" in names and "services/web" in names and "tools" in names
        assert not any(c.startswith(("vendor", "third")) for c in names)
        assert not any(f["file"].startswith(("vendor/", "third_party/")) for f in s["findings"])
        assert any("Excluded from the scan by request" in l for l in s["limitations"])
        assert s["components"][0]["candidates"] >= 1                      # highest-risk component first
        run = s["meta"]["run"]
        assert len(run["scanner_sha256"]) == 64 and run["options"]["excludes"] == ["vendor", "third_*"]
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"meta": {"customer": "T", "review_coverage": {"services/api": {"status": "Reviewed", "notes": "all routes read"}}}})
        _, md = render(out, tri)
        assert "### A.2 Coverage by Component" in md and "`services/api`" in md and "Reviewed: all routes read" in md
        assert "Manual code review coverage recorded" in md and "Scanner build fingerprint" in md and "Excluded paths" in md


def test_parallel_scan_matches_sequential():
    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "repo")
        files = {f"pkg{i % 7}/m{i}.py": (VULN_A if i % 9 == 0 else "x = %d\n" % i) for i in range(330)}
        files["pkg1/app.js"] = 'app.get("/x", (req, res) => { const id = req.query.id; db.query("SELECT " + id); });\n'
        write(repo, files)
        key = lambda s: [(f["id"], f["rule"], f["file"], f["line"], f["fingerprint"]) for f in s["findings"]]
        a = audit(repo, os.path.join(tmp, "o1"), "--jobs", "1")
        b = audit(repo, os.path.join(tmp, "o4"), "--jobs", "4")
        assert b["meta"]["run"]["jobs"] == 4 and a["meta"]["run"]["jobs"] == 1
        assert key(a) == key(b) and a["inventory"]["files_scanned"] == b["inventory"]["files_scanned"] == 331
        assert a["components"] == b["components"] and a["routes"] == b["routes"]


def test_checklist_is_lenient_by_default_and_strict_on_request():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A})
        audit(repo, out)
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"))
        r, md = render(out, tri)
        assert "NOT ASSESSED" in md and "**FAIL**" in md                        # linked confirmed finding -> FAIL; the rest -> NOT ASSESSED
        assert "checklist item(s) were not assessed" in r.stderr
        bad, _ = render(out, tri, "--strict-checklist", ok=False)
        assert bad.returncode == 2 and "is still" in bad.stderr


def test_patch_snippet_and_status_override_render():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A})
        s = audit(repo, out)
        fid = s["findings"][0]["id"]
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"overrides": {fid: {"patch": "--- a/a.py\n+++ b/a.py\n@@\n-cur.execute(q + x)\n+cur.execute(q, (x,))", "status": "In remediation"}}})
        _, md = render(out, tri)
        assert "```diff" in md and "+cur.execute(q, (x,))" in md and "In remediation" in md


def test_verification_flow():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A, "cfg.py": 'password = "Winter2024Pass"\n'})
        s = audit(repo, out)
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"overrides": {f["id"]: {"description": "ORIGINAL REASONING TEXT", "impact": "x"} for f in s["findings"]}})
        packets = os.path.join(out, "work", "verify")
        py(RENDER, "--scan", os.path.join(out, "scan.json"), "--triage", tri, "--packets", packets, "--repo", repo)
        pk = glob.glob(os.path.join(packets, "FND-*.md"))
        assert pk and os.path.exists(os.path.join(packets, "INDEX.md"))
        text = "\n".join(open(p, encoding="utf-8").read() for p in pk)
        assert "ORIGINAL REASONING TEXT" not in text, "packets must not leak the first reviewer's reasoning"
        assert "Winter2024Pass" not in text and "cur.execute" in text
        # no verification yet: report says so
        _, md = render(out, tri)
        assert "Not re-checked by a second pass" in md
        # a disagreement blocks rendering until the assessor responds
        high = [f for f in s["findings"] if f["severity"] in ("Critical", "High")]
        v = {"verifications": {high[0]["id"]: {"verdict": "disagree", "verifier": "agent-2", "independence": "independent", "notes": "input is int-cast in the caller"}}}
        vp = os.path.join(out, "work", "verification.json")
        json.dump(v, open(vp, "w"))
        bad, _ = render(out, tri, ok=False)
        assert bad.returncode == 2 and "verifier disagrees" in bad.stderr
        tri2 = triage_all_confirmed(os.path.join(tmp, "t2.json"), {"verification_resolution": {high[0]["id"]: "Caller does not cast; verified at views.py:12"}})
        _, md = render(out, tri2)
        assert "Disputed (independent reviewer: agent-2)" in md and "Assessor resolution: Caller does not cast" in md
        # agreement from the same assessor is labelled as weaker than an independent review
        v["verifications"][high[0]["id"]] = {"verdict": "agree", "verifier": "me", "independence": "self", "notes": "re-read, still true"}
        json.dump(v, open(vp, "w"))
        _, md = render(out, tri)
        assert "same assessor, second pass" in md and "Independent verification:" in md and "by the same assessor rather than an independent reviewer" in md


def test_sarif_and_ci_gate():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A, "b.py": VULN_B})
        s = audit(repo, out)
        fp_b = next(f for f in s["findings"] if f["file"] == "b.py")
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"decisions": {fp_b["id"]: {"decision": "false_positive", "reason": "constant host"}}})
        r, _ = render(out, tri, "--emit-sarif")
        sarif = json.load(open(glob.glob(os.path.join(out, "*.sarif"))[0]))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        res = run["results"]
        assert any(x["ruleId"] == "INJ-SQL-1" and "suppressions" not in x for x in res)
        sup = [x for x in res if x.get("suppressions")]
        assert sup and sup[0]["suppressions"][0]["justification"].endswith("constant host")
        assert all(x["partialFingerprints"]["appsecAudit/v1"] for x in res)
        assert {r_["id"] for r_ in run["tool"]["driver"]["rules"]} >= {x["ruleId"] for x in res}
        assert all("security-severity" in r_["properties"] for r_ in run["tool"]["driver"]["rules"])
        # CI gate: High+ present -> exit 10; gate above the worst severity -> exit 0
        gated, _ = render(out, tri, "--fail-on", "High", ok=False)
        assert gated.returncode == 10 and "CI gate FAILED" in gated.stderr
        only_unconfirmed = triage_all_confirmed(os.path.join(tmp, "t3.json"), {"bulk": [{"rule": "*", "decision": "needs_review"}]})
        passed, _ = render(out, only_unconfirmed, "--fail-on", "Critical")
        assert "CI gate passed" in passed.stdout
        gated2, _ = render(out, only_unconfirmed, "--fail-on", "High", "--fail-on-unconfirmed", ok=False)
        assert gated2.returncode == 10


if __name__ == "__main__":
    bad = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS ", name)
            except AssertionError as e:
                bad += 1
                print("FAIL ", name, "\n", str(e)[:1200])
    sys.exit(1 if bad else 0)
