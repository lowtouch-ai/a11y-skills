"""End-to-end test for appsec-static-audit: scan a vulnerable fixture, triage, render, check the report.

Run: python3 tests/appsec-static-audit/test_skill.py
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.abspath(os.path.join(HERE, "..", "..", "skills", "appsec-static-audit"))
SCRIPTS = os.path.join(SKILL, "scripts")
FIXTURE = os.path.join(HERE, "fixtures", "vuln-app")


def run(*args, ok=True):
    p = subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True)
    if ok and p.returncode != 0:
        raise AssertionError(f"{args} failed\n{p.stdout}\n{p.stderr}")
    return p


def git(cwd, *a):
    subprocess.run(["git", "-C", cwd, "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)


def main():
    tmp = tempfile.mkdtemp(prefix="appsec-test-")
    try:
        repo = os.path.join(tmp, "vuln-app")
        shutil.copytree(FIXTURE, repo)
        git(repo, "init", "-q")
        with open(os.path.join(repo, "old_config.py"), "w") as fh:
            fh.write('STRIPE = "sk_live_' + "a1B2c3D4e5F6g7H8i9J0k1L2" + '"\n')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init")
        os.remove(os.path.join(repo, "old_config.py"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "remove secret")

        out = os.path.join(tmp, "out")
        p = run(os.path.join(SCRIPTS, "audit.py"), repo, "--out", out, "--name", "Fixture App")
        scan = json.load(open(os.path.join(out, "scan.json")))
        rules = {f["rule"] for f in scan["findings"]}
        expect = {"INJ-SQL-1", "INJ-SQL-2", "INJ-CMD-1", "INJ-CMD-2", "SSRF-1", "DESER-1", "XSS-1", "SSO-JWT-2", "SSO-SAML-1", "SSO-BYP-1",
                  "SES-1", "SES-1B", "SES-3", "DESER-2", "API-3", "CRY-1", "CRY-3", "CRY-4", "CRY-5", "CRY-6", "DATA-2", "DATA-4", "DATA-1", "API-1", "CFG-1", "CFG-2",
                  "IAC-1", "IAC-2", "IAC-3", "IAC-4", "IAC-5", "K8S-1", "DKR-1", "DKR-2", "DEP-1", "DEP-2", "DEP-3", "ERR-1", "ACC-2",
                  "MISC-PROMPT-1", "SEC-HIST-1", "SEC-AWS-ACCESS-KEY-ID", "PATH-1", "REDIR-1", "ACC-1"}
        missing = expect - rules
        assert not missing, f"scanner missed: {sorted(missing)}"
        assert any(r.startswith("SEC-") and r not in ("SEC-HIST-1",) for r in rules), "no secret findings"
        noisy = [(f["rule"], f["file"]) for f in scan["findings"] if f["file"] in ("app/benign.py", "app/health.sh")]
        assert not noisy, f"benign code raised findings: {noisy}"
        assert len(scan["routes"]) >= 8 and any(r["auth"] == "none seen" for r in scan["routes"]), scan["routes"][:3]
        raw = json.dumps(scan)
        for secret in ("Winter2024Pass", "hunter2hunter2", "s3cr3t-prod-signing-key-9981", "123-45-6789", "a1B2c3D4e5F6g7H8i9J0k1L2", "AKIAIOSFODNN7EXAMPLE"):
            assert secret not in raw, f"secret leaked into scan.json: {secret}"
        sbom = json.load(open(os.path.join(out, "sbom.cdx.json")))
        assert sbom["bomFormat"] == "CycloneDX" and len(sbom["components"]) >= 6
        assert scan["history"]["ran"] and scan["history"]["hits"] >= 1

        # rendering must refuse an untriaged scan
        tri_path = os.path.join(tmp, "triage.json")
        json.dump({"meta": {"customer": "Test Agency", "assessor": "pytest"}}, open(tri_path, "w"))
        bad = run(os.path.join(SCRIPTS, "render_report.py"), "--scan", os.path.join(out, "scan.json"), "--triage", tri_path, ok=False)
        assert bad.returncode == 2 and "no decision" in bad.stderr, bad.stderr

        decisions = {f["id"]: "confirmed" for f in scan["findings"] if f["rule"] not in ("MISC-PROMPT-1", "CFG-4", "ERR-2")}
        dup = next(f for f in scan["findings"] if f["rule"] == "CFG-4")
        decisions[dup["id"]] = {"decision": "consolidated", "into": "FND-M01", "reason": "same missing-hardening theme"}
        checklist = {}
        for it in scan["checklist"]:
            if it["scanner_hits"]:
                checklist[it["key"]] = {"status": "Fail", "evidence": "see findings"}
            else:
                checklist[it["key"]] = {"status": "Not Verified", "evidence": "requires runtime/IdP confirmation"}
        # a PASS with a linked confirmed finding must be rejected
        first_hit = next(it for it in scan["checklist"] if it["scanner_hits"])
        tri = {"meta": {"customer": "Test Agency", "assessor": "pytest"}, "decisions": decisions,
               "new_findings": [{"title": "Manual: missing ownership check on case export", "domain": "access", "severity": "High", "cwe": "CWE-639",
                                 "file": "app/views.py", "line": 12, "description": "Export route returns any case by ID.", "fix": "Filter by owner.",
                                 "evidence": 'headers = {"User-Agent": "Mozilla/5.0"}'}],
               "bulk": [{"rule": "MISC-PROMPT-1", "decision": "false_positive", "reason": "bulk rule test"},
                                       {"rule": "ERR-2", "file_regex": "(views\\.py|server\\.js)$", "decision": "false_positive", "reason": "bulk file_regex test"}],
               "checklist": {**checklist, first_hit["key"]: {"status": "Pass", "evidence": "x"}}}
        tri["meta"].update({"application_description": "a multi-service test appliance", "fti_in_scope": False,
                            "architecture_md": "```mermaid\nflowchart LR\n  A-->B\n```", "immediate_actions": ["Rotate the exposed credentials first."]})
        json.dump(tri, open(tri_path, "w"))
        bad = run(os.path.join(SCRIPTS, "render_report.py"), "--scan", os.path.join(out, "scan.json"), "--triage", tri_path, ok=False)
        assert bad.returncode == 2 and "PASS but confirmed findings" in bad.stderr, bad.stderr
        tri["checklist"][first_hit["key"]] = checklist[first_hit["key"]]
        json.dump(tri, open(tri_path, "w"))

        p = run(os.path.join(SCRIPTS, "render_report.py"), "--scan", os.path.join(out, "scan.json"), "--triage", tri_path)
        reports = glob.glob(os.path.join(out, "security-audit-report_*.md"))
        assert len(reports) == 1 and re.search(r"_\d{8}-\d{6}\.md$", reports[0]), reports
        md = open(reports[0], encoding="utf-8").read()
        for h in ["## 1. Executive Summary", "### 1.2 Overall Risk Rating", "## 2. Scope and Methodology", "## 3. Findings Summary",
                  "## 4. Security Control Checklist by Domain", "### 4.1 OWASP Top 10 in Code", "### 4.13 Error Handling", "## 5. Detailed Findings",
                  "## 6. Compliance Mapping", "### 6.2 IRS Publication 1075", "## 7. Dependencies", "## 8. Remediation Roadmap", "Appendix B"]:
            assert h in md, f"missing section {h}"
        assert "| No. | Control / Issue | Status | Evidence |" in md
        assert "**CRITICAL**" in md
        assert "FND-M01" in md and "9.3.1" in md and "IS.003" in md
        assert "Static analysis identified: Manual" not in md, "manual finding description must not be prefixed with boilerplate"
        assert '"User-Agent": "Mozilla/5.0"' in md, "manual evidence must not be over-masked"
        assert "a multi-service test appliance" in md and "public-facing application that handles" not in md
        assert "FTI handling was not established" in md and "### 2.7 Architecture" in md and "1. Rotate the exposed credentials first." in md
        assert "Route inventory" in md and "Consolidated into FND-M01" in md and "bulk rule test" in md and "OWASP Top 10 (2021) | A01" in md
        for secret in ("Winter2024Pass", "hunter2hunter2", "s3cr3t-prod-signing-key-9981", "123-45-6789", "a1B2c3D4e5F6g7H8i9J0k1L2", "AKIAIOSFODNN7EXAMPLE"):
            assert secret not in md, f"secret leaked into report: {secret}"
        print("OK:", os.path.basename(reports[0]), f"({len(md.splitlines())} lines, {len(scan['findings'])} candidates)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
