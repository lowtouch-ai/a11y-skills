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
        assert "Disputed (independence reported by the reviewer; not tied to a verification packet: agent-2)" in md and "Assessor resolution: Caller does not cast" in md
        # agreement from the same assessor is labelled as weaker than an independent review
        v["verifications"][high[0]["id"]] = {"verdict": "agree", "verifier": "me", "independence": "self", "notes": "re-read, still true"}
        json.dump(v, open(vp, "w"))
        _, md = render(out, tri)
        assert "same assessor, second pass" in md and "Independent verification:" in md and "by the same assessor rather than an independent reviewer" in md
        # an independent verdict that echoes the packet hash is shown as tied to that packet; a stale hash is called out
        manifest = json.load(open(os.path.join(packets, "manifest.json")))
        v["verifications"][high[0]["id"]] = {"verdict": "agree", "verifier": "agent-3", "independence": "independent", "session": "model-x",
                                             "packet_sha256": manifest[high[0]["id"]]["sha256"], "notes": "confirmed from the packet"}
        json.dump(v, open(vp, "w"))
        r, md = render(out, tri)
        assert "response tied to the verification packet: agent-3, model-x" in md
        v["verifications"][high[0]["id"]]["packet_sha256"] = "0" * 64
        json.dump(v, open(vp, "w"))
        r, md = render(out, tri)
        assert "packet changed since the review" in md and "older version of the packet" in r.stderr


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


def test_manual_citations_are_checked_and_corrected_against_the_source():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        pad = "".join(f"# filler line {i}\n" for i in range(25))          # evidence ends up far from the (wrong) cited line
        write(repo, {"svc/api.py": "import os\n" + pad + "\ndef handler(req):\n    token = os.environ['T']\n    data = open(req.args['f']).read()\n    return data\n"})
        audit(repo, out)
        nf = [{"title": "Handler reads arbitrary files", "domain": "owasp", "severity": "High", "cwe": "CWE-22", "file": "svc/api.py", "line": 2,
               "evidence": "data = open(req.args['f']) ... return data", "description": "d", "impact": "i", "exploit_scenario": "e", "fix": "f"},
              {"title": "Wrong file", "domain": "owasp", "severity": "Low", "cwe": "CWE-1", "file": "svc/gone.py", "line": 1, "evidence": "x", "fix": "f"},
              {"title": "Phantom evidence", "domain": "owasp", "severity": "Low", "cwe": "CWE-2", "file": "svc/api.py", "line": 4, "evidence": "this text is nowhere in the file", "fix": "f"}]
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"new_findings": nf})
        r, md = render(out, tri, "--repo", repo)
        assert "cited line 2 but the quoted evidence is at line 30; corrected" in r.stderr
        assert "'svc/gone.py' is not in the working tree" in r.stderr and "quoted evidence was not found" in r.stderr
        assert "`svc/api.py:30`" in md, "the corrected line is what the report cites"
        bad, _ = render(out, tri, "--repo", repo, "--strict-evidence", ok=False)
        assert bad.returncode == 2 and "was not found in the file" in bad.stderr
        none, _ = render(out, tri)
        assert "were not checked against the source" in none.stderr


def test_manual_finding_ids_are_stable_when_severity_or_title_changes():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": "x = 1\n"})
        audit(repo, out)

        def nf(title_a, sev_a, title_b="Second issue"):
            return [{"title": title_a, "domain": "access", "severity": sev_a, "cwe": "CWE-306", "file": "a.py", "line": 1, "fix": "f"},
                    {"title": title_b, "domain": "crypto", "severity": "Medium", "cwe": "CWE-327", "file": "a.py", "line": 1, "fix": "f"}]

        def ids(tri_extra):
            tri = triage_all_confirmed(os.path.join(tmp, "t.json"), tri_extra)
            _, md = render(out, tri)
            return dict(re.findall(r"^\| 5\.\d+ \| (FND-M\d+) \| \w+ \| [^|]+ \| ([^|]+) \|", md, re.M))
        first = ids({"new_findings": nf("First issue", "Low")})
        by_title = {v.strip(): k for k, v in first.items()}
        # raise the first finding to Critical (it now sorts above the other) and reword its title: IDs must not move
        second = ids({"new_findings": nf("First issue, reworded", "Critical")})
        by_title2 = {v.strip(): k for k, v in second.items()}
        assert by_title["First issue"] == by_title2["First issue, reworded"]
        assert by_title["Second issue"] == by_title2["Second issue"]
        # an explicit id is honoured and two findings may not share one
        dup = nf("A", "Low")
        dup[0]["id"], dup[1]["id"] = "FND-M42", "FND-M42"
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"new_findings": dup})
        bad, _ = render(out, tri, ok=False)
        assert bad.returncode == 2 and "share the ID FND-M42" in bad.stderr


def test_identical_rejection_reasons_are_called_out():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {f"m{i}.py": VULN_A for i in range(6)})
        s = audit(repo, out)
        decisions = {f["id"]: {"decision": "false_positive", "reason": "Reviewed the code: constant value, not attacker controlled."} for f in s["findings"] if f["rule"] == "INJ-SQL-1"}
        assert len(decisions) >= 5
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"decisions": decisions})
        r, md = render(out, tri)
        assert "rejected with the identical reason" in r.stderr and "**Review note.**" in md
        # a deliberate bulk rule with the same wording is not flagged
        bulk = {"bulk": [{"rule": "INJ-SQL-1", "decision": "false_positive", "reason": "Reviewed the code: constant value, not attacker controlled."}]}
        tri2 = triage_all_confirmed(os.path.join(tmp, "t2.json"), bulk)
        tri2_data = json.load(open(tri2))
        tri2_data["bulk"] = bulk["bulk"] + [{"rule": "*", "decision": "confirmed", "reason": "t"}]
        json.dump(tri2_data, open(tri2, "w"))
        r2, md2 = render(out, tri2)
        assert "rejected with the identical reason" not in r2.stderr


def test_api3_and_flow_findings_appear_in_a_rendered_report_with_real_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"svc/a.py": 'import requests\nfrom fastapi import APIRouter\nr = APIRouter()\n\n@r.post("/html/{u}")\ndef up(u: str):\n    return requests.get(u).text\n',
                     "requirements.txt": "httpx\npyyaml==5.3\n"})
        s = audit(repo, out)
        rules = {f["rule"] for f in s["findings"]}
        assert {"API-3", "SSRF-1", "DEP-1", "DEP-3"} <= rules
        _, md = render(out, triage_all_confirmed(os.path.join(tmp, "t.json")))
        assert "pyyaml==5.3" in md and "Data flow: untrusted input from route parameter `u`" in md


def test_bulk_dispositions_are_disclosed_and_repeated_bulk_reasons_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {f"svc/m{i:02d}.py": VULN_A for i in range(26)})
        s = audit(repo, out)
        sql = [f for f in s["findings"] if f["rule"] == "INJ-SQL-1"]
        assert len(sql) == 26
        same = "Related lead; evidence kept in scan.json."
        bulk = [{"rule": "INJ-SQL-1", "file_regex": f"m{i:02d}\\.py$", "decision": "needs_review", "reason": same} for i in range(26)]
        bulk += [{"rule": "*", "decision": "confirmed", "reason": "t"}]
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"))
        td = json.load(open(tri))
        td["bulk"] = bulk
        json.dump(td, open(tri, "w"))
        r, md = render(out, tri)
        assert "Critical/High candidates were dispositioned by bulk rules rather than one by one" in r.stderr
        assert "rejected with the identical reason" not in r.stderr, "unconfirmed (not rejected) leads are not 'rejections'"
        assert "| Candidates dispositioned individually / by bulk rule / by suppression policy | 0 / " in md
        assert "dispositioned by bulk rules, not individually" in md and "**Review note.**" in md
        # the same sentence used to REJECT 26 candidates through bulk rules is called out
        bulk2 = [{"rule": "INJ-SQL-1", "file_regex": f"m{i:02d}\\.py$", "decision": "false_positive", "reason": same} for i in range(26)] + [{"rule": "*", "decision": "confirmed", "reason": "t"}]
        td["bulk"] = bulk2
        json.dump(td, open(tri, "w"))
        r2, md2 = render(out, tri)
        assert "rejected with the identical reason" in r2.stderr and "by bulk rules" in r2.stderr


def test_consolidation_into_an_unconfirmed_finding_is_noted():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        write(repo, {"a.py": VULN_A, "b.py": VULN_A.replace("def a", "def b")})
        s = audit(repo, out)
        sql = sorted((f for f in s["findings"] if f["rule"] == "INJ-SQL-1"), key=lambda f: f["file"])
        decisions = {sql[0]["id"]: {"decision": "needs_review"}, sql[1]["id"]: {"decision": "consolidated", "into": sql[0]["id"], "reason": "same root cause"}}
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"decisions": decisions})
        _, md = render(out, tri)
        assert "consolidated into findings that are themselves unconfirmed" in md


def test_previous_triage_lists_what_was_confirmed_before_and_is_not_now():
    with tempfile.TemporaryDirectory() as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        prev_dir = os.path.join(tmp, "prev")
        write(repo, {"a.py": VULN_A, "b.py": VULN_B, "c.py": 'import yaml\nfrom flask import request\ndef c():\n    return yaml.load(request.data)\n'})
        s1 = audit(repo, out)
        manual = [{"title": "Export skips the ownership check", "domain": "access", "severity": "High", "cwe": "CWE-639", "file": "a.py", "line": 3, "fix": "f"}]
        t1 = triage_all_confirmed(os.path.join(tmp, "t1.json"), {"new_findings": manual})
        render(out, t1)
        os.makedirs(prev_dir)
        for f in ("scan.json", "finding-ids.json"):
            open(os.path.join(prev_dir, f), "w").write(open(os.path.join(out, f)).read())
        open(os.path.join(prev_dir, "triage.json"), "w").write(open(t1).read())
        # second review: b.py is fixed, the yaml finding is now judged a false positive, the manual finding is not re-raised
        write(repo, {"b.py": "x = 1\n"})
        s2 = audit(repo, out, "--previous", "none")
        yaml_id = next(f["id"] for f in s2["findings"] if f["rule"] == "DESER-2")
        t2 = triage_all_confirmed(os.path.join(tmp, "t2.json"), {"decisions": {yaml_id: {"decision": "false_positive", "reason": "input is a constant"}}})
        r, md = render(out, t2, "--previous-triage", os.path.join(prev_dir, "triage.json"))
        assert "### 3.5 Comparison with the Previous Review" in md
        sec = md[md.index("### 3.5"):md.index("## 4. Security Control Checklist")]
        assert "now rejected as a false positive" in sec and "no longer detected in this scan" in sec and "not re-raised" in sec, sec
        assert "Export skips the ownership check" in sec and "Compared with previous review" in md
        assert "findings confirmed in the previous review are not confirmed in this one" in r.stderr
        # nothing dropped when the same findings are confirmed again
        t3 = triage_all_confirmed(os.path.join(tmp, "t3.json"))
        r3, md3 = render(out, t3, "--previous-triage", os.path.join(prev_dir, "triage.json"), "--previous-scan", os.path.join(prev_dir, "scan.json"))
        assert "### 3.5" in md3


def _git_repo(path, files):
    write(path, files)
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "init"]):
        subprocess.run(["git", "-C", path, "-c", "user.email=t@t", "-c", "user.name=t", *cmd], check=True, capture_output=True)
    return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()


def test_multi_repository_workspace_scan():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out")
        alpha, beta = os.path.join(tmp, "alpha"), os.path.join(tmp, "beta")
        sha_a = _git_repo(alpha, {"app/a.py": "".join(f"# filler {i}\n" for i in range(25)) + VULN_A, "requirements.txt": "pyyaml==5.3\n",
                                  "svc/api.py": 'from fastapi import APIRouter\nr = APIRouter()\n@r.get("/items")\ndef items():\n    return []\n'})
        sha_b = _git_repo(beta, {"b.py": VULN_B, "requirements.txt": "pyyaml==5.3\n", "docker-compose.yml": 'services:\n  r:\n    image: redis\n    ports:\n      - "6379:6379"\n'})
        py(AUDIT, alpha, beta, "--out", out, "--no-git-history", "--name", "Two repo workspace")
        s = json.load(open(os.path.join(out, "scan.json")))
        files = {f["file"] for f in s["findings"]}
        assert any(f.startswith("alpha/") for f in files) and any(f.startswith("beta/") for f in files) and not any(f.startswith(("app/", "svc/")) for f in files), files
        # the same vulnerable dependency in both repositories is reported once per repository
        dep1 = sorted(f["file"] for f in s["findings"] if f["rule"] == "DEP-1")
        assert dep1 == ["alpha/requirements.txt", "beta/requirements.txt"], dep1
        assert s["meta"]["git"] == {} and set(s["meta"]["repositories"]) == {"alpha", "beta"}
        assert s["meta"]["repositories"]["alpha"]["commit_full"] == sha_a and s["meta"]["repositories"]["beta"]["commit_full"] == sha_b
        assert s["meta"]["repository"].startswith("2 repositories") and s["limitations"][0].startswith("Workspace scan of 2 repositories")
        comps = {c["component"] for c in s["components"]}
        assert {"alpha/app", "alpha/svc", "beta/(repository root)"} <= comps, comps
        assert all(r["file"].startswith("alpha/") for r in s["routes"]) and s["routes"]
        api3 = next(f for f in s["findings"] if f["rule"] == "API-3")
        assert api3["file"] == "alpha/svc/api.py" and api3["locations"][0]["snippet"] == '@r.get("/items")'
        assert next(f for f in s["findings"] if f["rule"] == "DKR-4")["file"] == "beta/docker-compose.yml"
        sbom = json.load(open(os.path.join(out, "sbom.cdx.json")))
        yml = [c for c in sbom["components"] if c["name"] == "pyyaml"]
        assert len(yml) == 1 and [p["value"] for p in yml[0]["properties"] if p["name"] == "source"] == ["beta/requirements.txt", "alpha/requirements.txt"] or len(yml[0]["properties"]) >= 2
        # IDs are stable on a re-scan of the same workspace
        ids1 = {(f["rule"], f["file"]): f["id"] for f in s["findings"]}
        s2 = audit_multi(out, [alpha, beta])
        assert {(f["rule"], f["file"]): f["id"] for f in s2["findings"]} == ids1
        assert s2["changes"] and s2["changes"]["new"] == 0
        # render: both revisions are shown, and manual citations resolve through the repository prefix
        nf = [{"title": "Handler reads input", "domain": "owasp", "severity": "High", "cwe": "CWE-89", "file": "alpha/app/a.py", "line": 1,
               "evidence": 'cur.execute("SELECT * FROM t WHERE id=" + request.args["id"])', "fix": "f"}]
        tri = triage_all_confirmed(os.path.join(tmp, "t.json"), {"new_findings": nf})
        r, md = render(out, tri, "--repo", alpha, "--repo", beta)
        assert f"alpha: " in md and sha_a in md and sha_b in md and "| Repository revisions |" in md
        assert "cited line 1 but the quoted evidence is at line 28; corrected" in r.stderr
        assert "Source revision | alpha:" in md
        # inputs must be bound to a repository when there are several
        bad = py(AUDIT, alpha, beta, "--out", out, "--no-git-history", "--sarif", os.path.join(tmp, "x.sarif"), ok=False)
        assert bad.returncode != 0 and "NAME=FILE" in (bad.stderr + bad.stdout)


def audit_multi(out, repos, *extra):
    py(AUDIT, *repos, "--out", out, "--no-git-history", *extra)
    return json.load(open(os.path.join(out, "scan.json")))


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
