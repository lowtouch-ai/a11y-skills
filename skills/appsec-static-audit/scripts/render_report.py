#!/usr/bin/env python3
"""Render the enterprise security audit report (Markdown) from scan.json + triage.json.

Output file: <out>/security-audit-report_<YYYYMMDD-HHMMSS>.md  (timestamp suffix, local time)

triage.json (written by the auditor after reading the code):
{
  "meta": {"application": "...", "customer": "...", "assessor": "...", "engagement": "...",
           "executive_commentary": "optional paragraph", "scope_in": ["..."], "scope_out": ["..."], "fti_in_scope": true},
  "decisions": {"FND-001": "confirmed" | "false_positive" | "needs_review",
                "FND-002": {"decision": "false_positive", "reason": "value is a documented test constant"}},
  "overrides": {"FND-001": {"severity": "High", "title": "...", "description": "...", "impact": "...",
                            "exploit_scenario": "...", "fix": "...", "controls_extra": {"nist": ["SC-13"]}}},
  "new_findings": [{"title": "...", "domain": "access", "severity": "High", "cwe": "CWE-639", "file": "app/views.py", "line": 88,
                    "description": "...", "evidence": "code excerpt (secrets masked)", "impact": "...", "fix": "...",
                    "exploit_scenario": "..."}],
  "checklist": {"OWASP-01": {"status": "Pass|Fail|Partial|N/A|Not Verified", "evidence": "file:line or what was read", "findings": ["FND-001"]}}
}
"""
import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rules as R  # noqa: E402
from audit import redact_line  # noqa: E402

REF = os.path.join(HERE, "..", "references")
SEV = R.SEV
STATUS_MAP = {"pass": "PASS", "fail": "FAIL", "partial": "PARTIAL", "n/a": "N/A", "na": "N/A", "not applicable": "N/A",
              "not verified": "NOT VERIFIED", "nv": "NOT VERIFIED"}
OPEN_STATES = {"Needs Review", "Not Assessed"}
SEV_DEF = {
    "Critical": "Directly exploitable with severe impact (remote code execution, authentication bypass, exposure of live secrets or bulk SSN/FTI). Fix immediately.",
    "High": "Exploitable weakness likely to lead to compromise or disclosure of sensitive data, or a missing core control. Fix within 30 days.",
    "Medium": "Weakness that needs additional conditions to exploit, or a control gap with partial compensating measures. Fix within 90 days.",
    "Low": "Minor weakness or hardening gap with limited impact. Fix in normal maintenance cycles.",
    "Info": "Observation or best-practice recommendation; no direct exploit path.",
}
STATUS_DEF = [("PASS", "Control evidenced in the code/config reviewed; no deficiency found."),
              ("FAIL", "Control missing or defeated; at least one confirmed finding."),
              ("PARTIAL", "Control present but incomplete, inconsistently applied, or only partly evidenced."),
              ("N/A", "Not applicable to this application (reason given in Evidence)."),
              ("NOT VERIFIED", "Could not be determined from source alone (runtime, IdP or platform setting); needs confirmation.")]


def cell(s):
    s = "" if s is None else str(s)
    return s.replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def first_sentence(s, n=170):
    s = (s or "").strip().replace("\n", " ")
    m = re.match(r"(.+?[.!?])(\s|$)", s)
    s = m.group(1) if m else s
    return s if len(s) <= n else s[:n - 1] + "…"


def loc_str(f, indent=True):
    locs = f.get("locations") or []
    base = f["file"]
    lines = sorted({l["line"] for l in locs}) or [f.get("line", 1)]
    shown = ", ".join(str(x) for x in lines[:6]) + ("…" if len(lines) > 6 else "")
    return f"`{base}:{shown}`"


def load_frameworks(extra):
    fw = []
    for p in sorted(glob.glob(os.path.join(HERE, "..", "frameworks", "*.json"))) + list(extra or []):
        if os.path.basename(p).startswith("_") and p not in (extra or []):
            continue
        try:
            d = json.load(open(p, encoding="utf-8"))
            fw.append(d)
        except (OSError, ValueError) as e:
            print(f"warning: could not load framework {p}: {e}", file=sys.stderr)
    return fw


def main():
    ap = argparse.ArgumentParser(description="Render the Markdown audit report")
    ap.add_argument("--scan", required=True, help="scan.json from audit.py")
    ap.add_argument("--triage", required=True, help="triage.json written by the auditor")
    ap.add_argument("--out", help="output directory (default: directory of scan.json)")
    ap.add_argument("--prefix", default="security-audit-report")
    ap.add_argument("--framework", action="append", default=[], help="extra framework mapping JSON (repeatable)")
    ap.add_argument("--allow-untriaged", action="store_true", help="render even if candidates lack a decision")
    ap.add_argument("--allow-unassessed", action="store_true", help="render even if checklist items are not finalised")
    a = ap.parse_args()

    scan = json.load(open(a.scan, encoding="utf-8"))
    tri = json.load(open(a.triage, encoding="utf-8"))
    cl_spec = json.load(open(os.path.join(REF, "checklist.json"), encoding="utf-8"))
    cmap = json.load(open(os.path.join(REF, "compliance-map.json"), encoding="utf-8"))["domains"]
    frameworks = load_frameworks(a.framework)
    dom_title = {d["key"]: d["title"] for d in cl_spec["domains"]}
    dom_intro = {d["key"]: d.get("intro", "") for d in cl_spec["domains"]}
    dom_order = [d["key"] for d in cl_spec["domains"]]
    meta = {**scan["meta"], **tri.get("meta", {})}
    errors, warnings = [], []

    # ---------------- findings: apply triage
    decisions = {}
    reasons = {}
    for k, v in (tri.get("decisions") or {}).items():
        if isinstance(v, dict):
            decisions[k], reasons[k] = v.get("decision", ""), v.get("reason", "")
        else:
            decisions[k] = v
    overrides = tri.get("overrides") or {}
    findings, rejected = [], []
    by_fp = {f["fingerprint"]: f["id"] for f in scan["findings"]}
    decisions = {by_fp.get(k, k): v for k, v in decisions.items()}
    overrides = {by_fp.get(k, k): v for k, v in overrides.items()}
    for f in scan["findings"]:
        d = decisions.get(f["id"])
        if d is None:
            if not a.allow_untriaged:
                errors.append(f"candidate {f['id']} ({f['rule']} {f['file']}:{f['line']}) has no decision in triage.json")
            d = "needs_review"
        d = d.lower().replace(" ", "_")
        if d not in ("confirmed", "false_positive", "needs_review"):
            errors.append(f"{f['id']}: unknown decision '{d}'")
        f = {**f, **{k: v for k, v in (overrides.get(f["id"]) or {}).items() if k != "controls_extra"}}
        f["controls_extra"] = (overrides.get(f["id"]) or {}).get("controls_extra", {})
        f["decision"] = d
        if d == "false_positive":
            if not reasons.get(f["id"]):
                warnings.append(f"{f['id']} rejected without a reason")
            rejected.append((f, reasons.get(f["id"], "")))
        else:
            findings.append(f)
    for n in tri.get("new_findings") or []:
        loc_line = int(n.get("line", 1) or 1)
        findings.append(dict(id="", rule="MANUAL", domain=n["domain"], severity=n["severity"], cwe=n.get("cwe", ""), owasp=n.get("owasp", ""),
                             title=n["title"], file=n.get("file", "(multiple)"), line=loc_line, detail=n.get("description", ""),
                             fix=n.get("fix", ""), impact=n.get("impact", ""), exploit_scenario=n.get("exploit_scenario", ""),
                             locations=[dict(line=loc_line, snippet=redact_line(n.get("evidence", ""), force=True))] if n.get("evidence") else [],
                             confidence=n.get("confidence", "High"), decision="confirmed", source="manual", status="Open",
                             controls_extra=n.get("controls_extra", {})))
    findings.sort(key=lambda f: (SEV.index(f["severity"]), dom_order.index(f["domain"]) if f["domain"] in dom_order else 99, f["file"], f["line"]))
    n_manual = 0
    for f in findings:
        if not f["id"]:
            n_manual += 1
            f["id"] = f"FND-M{n_manual:02d}"
        if f["domain"] not in dom_title:
            errors.append(f"{f['id']}: unknown domain '{f['domain']}'")
    for f in findings:
        if f["decision"] == "confirmed" and f["severity"] in ("Critical", "High") and not (f.get("impact") or "").strip():
            warnings.append(f"{f['id']} ({f['severity']}) has no 'impact' in overrides; add impact (and exploit_scenario) for the client")
    confirmed = [f for f in findings if f["decision"] == "confirmed"]
    unconfirmed = [f for f in findings if f["decision"] == "needs_review"]
    fid = {f["id"] for f in findings}

    # ---------------- checklist: apply triage
    cl_in = tri.get("checklist") or {}
    checklist = []
    for it in scan["checklist"]:
        t = cl_in.get(it["key"], {})
        raw = (t.get("status") or it["status"]).strip()
        st = STATUS_MAP.get(raw.lower(), raw if raw in OPEN_STATES else "")
        if not st:
            errors.append(f"{it['key']}: invalid status '{raw}'")
            st = "NOT VERIFIED"
        linked = [x for x in (t.get("findings") if "findings" in t else it["finding_ids"]) if x in fid]
        conf_linked = [x for x in linked if any(f["id"] == x and f["decision"] == "confirmed" for f in findings)]
        if st in OPEN_STATES and not a.allow_unassessed:
            errors.append(f"checklist {it['key']} ({it['issue'][:50]}) is still '{st}'; set Pass/Fail/Partial/N/A/Not Verified")
        if st == "PASS":
            if not (t.get("evidence") or "").strip():
                errors.append(f"checklist {it['key']} is PASS but has no evidence (state what you read, with file paths)")
            if conf_linked:
                errors.append(f"checklist {it['key']} is PASS but confirmed findings are linked: {', '.join(conf_linked)}")
        if st in ("FAIL", "PARTIAL") and not conf_linked:
            warnings.append(f"checklist {it['key']} is {st} with no confirmed finding linked")
        ev = (t.get("evidence") or "").strip()
        if linked and st in ("FAIL", "PARTIAL"):
            ev = (ev + " " if ev else "") + "See " + ", ".join(linked) + "."
        if st in OPEN_STATES:
            ev = ev or "Not yet assessed."
        checklist.append({**it, "status": st, "evidence": ev, "linked": linked})
    if errors:
        print("Cannot render, fix triage.json:", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        sys.exit(2)

    # ---------------- helpers for mapping
    def controls(f):
        m = cmap.get(f["domain"], {})
        ex = f.get("controls_extra") or {}
        nist = list(m.get("nist", [])) + [[c, ""] if isinstance(c, str) else c for c in ex.get("nist", [])]
        irs = list(m.get("irs1075", [])) + [[c, ""] if isinstance(c, str) else c for c in ex.get("irs1075", [])]
        eot = list(m.get("eotss", [])) + [dict(id=None, title=c) if isinstance(c, str) else c for c in ex.get("eotss", [])]
        return nist, irs, eot

    def eotss_label(e):
        return f"{e['id']} {e['title']}" if e.get("id") else f"{e['title']}*"

    def sev_counts(fs):
        return {s: sum(1 for f in fs if f["severity"] == s) for s in SEV}

    now = datetime.now().astimezone()
    stamp = now.strftime("%Y%m%d-%H%M%S")
    app = meta.get("application", "Application")
    sc = sev_counts(confirmed)
    overall = next((s for s in SEV[:4] if sc[s]), None)
    rating = overall or "No confirmed findings"
    rid = f"SAR-{stamp}"
    git = meta.get("git", {}) or {}
    L = []
    w = L.append

    w(f"# Application Security Audit Report: {app}\n")
    w(table(["Field", "Value"], [
        ["Report ID", rid],
        ["Customer", meta.get("customer", "—")],
        ["Application", f"{app} ({meta.get('repository', '')})"],
        ["Source revision", f"{git.get('branch', '—')} @ {git.get('commit', '—')}" if git.get("commit") else "Not under git / unknown"],
        ["Assessment type", "Static source-code security analysis (SAST, secrets, dependencies, IaC); no live testing"],
        ["Assessment date", now.strftime("%Y-%m-%d %H:%M %Z")],
        ["Prepared by", meta.get("assessor", "appsec-static-audit (automated scan with manual code review)")],
        ["Engagement", meta.get("engagement", "—")],
        ["Classification", "CONFIDENTIAL: security findings. Secret values are masked; do not distribute outside the engagement."],
    ]))
    w("\n## Table of Contents\n")
    for t in ["1. Executive Summary", "2. Scope and Methodology", "3. Findings Summary", "4. Security Control Checklist by Domain",
              "5. Detailed Findings", "6. Compliance Mapping", "7. Dependencies and Software Bill of Materials",
              "8. Remediation Roadmap", "Appendix A. Scan Coverage and Tooling", "Appendix B. Rejected Candidates (False Positives)"]:
        w(f"- {t}")

    # ================= 1 EXEC SUMMARY
    inv = scan["inventory"]
    w("\n---\n\n## 1. Executive Summary\n")
    w("### 1.1 Overview\n")
    fti = meta.get("fti_in_scope", True)
    dom_hit = {}
    for f in confirmed:
        dom_hit.setdefault(f["domain"], []).append(f)
    top_dom = sorted(dom_hit, key=lambda d: (min(SEV.index(f["severity"]) for f in dom_hit[d]), -len(dom_hit[d])))[:3]
    w(f"This report presents the results of a static security assessment of **{app}**, a public-facing application that handles sensitive personal data"
      + (" (SSNs, financial records and potentially federal tax information)" if fti else "") +
      f". {inv['files_scanned']:,} source and configuration files ({inv['lines']:,} lines) were analysed against 13 control domains covering the OWASP Top 10, access control, "
      "SSO/identity, session management, MFA, secrets, dependencies, cryptography, data protection, API security, infrastructure-as-code, logging and error handling. "
      "Findings are mapped to NIST SP 800-53, IRS Publication 1075 and the Massachusetts EOTSS Enterprise Information Security Standards.\n")
    if confirmed:
        w(f"The review confirmed **{len(confirmed)} finding(s)**: " + ", ".join(f"{sc[s]} {s}" for s in SEV if sc[s]) + ". " +
          (f"The most affected areas are {', '.join(dom_title[d] for d in top_dom)}. " if top_dom else "") +
          (f"A further {len(unconfirmed)} candidate(s) could not be confirmed from source alone and are listed as *Unconfirmed*. " if unconfirmed else ""))
    else:
        w("The review confirmed **no findings** at the depth of a source-only assessment. " +
          (f"{len(unconfirmed)} candidate(s) remain unconfirmed. " if unconfirmed else ""))
    w("This is a static assessment: runtime behaviour, deployed configuration, WAF/gateway and IdP-side policy were not observed (see Section 2.6).\n")
    if meta.get("executive_commentary"):
        w(f"**Assessor commentary.** {meta['executive_commentary']}\n")

    w("### 1.2 Overall Risk Rating\n")
    w(f"**{rating.upper()}**" + (f": {SEV_DEF[overall]}" if overall else "") + "\n")

    w("### 1.3 Findings at a Glance\n")
    w(table(["Severity", "Confirmed", "Unconfirmed", "Definition"],
            [[s, sc[s], sev_counts(unconfirmed)[s], SEV_DEF[s]] for s in SEV] + [["**Total**", f"**{len(confirmed)}**", f"**{len(unconfirmed)}**", ""]]))

    w("\n### 1.4 Posture by Control Domain\n")
    rows = []
    for i, dk in enumerate(dom_order, 1):
        items = [c for c in checklist if c["domain"] == dk]
        cnt = lambda s: sum(1 for c in items if c["status"] == s)
        ds = [f for f in confirmed if f["domain"] == dk]
        worst = next((s for s in SEV if any(f["severity"] == s for f in ds)), "None")
        rows.append([f"4.{i}", dom_title[dk], len(items), cnt("PASS"), cnt("PARTIAL"), cnt("FAIL"), cnt("NOT VERIFIED") + cnt("N/A"), len(ds), worst])
    w(table(["Section", "Domain", "Checks", "Pass", "Partial", "Fail", "N/A or Not verified", "Findings", "Highest severity"], rows))

    w("\n### 1.5 Highest-Priority Issues\n")
    top = [f for f in confirmed if f["severity"] in ("Critical", "High")][:10]
    if top:
        w(table(["ID", "Severity", "Issue", "Location"], [[f["id"], f["severity"], f["title"], loc_str(f)] for f in top]))
    else:
        w("No Critical or High findings were confirmed.")

    w("\n### 1.6 Recommended Immediate Actions\n")
    acts = []
    for f in confirmed:
        if f["severity"] in ("Critical", "High") and len(acts) < 8:
            acts.append(f"1. **{f['id']}** ({f['severity']}): {first_sentence(f['fix'])}")
    w("\n".join(acts) if acts else "No immediate actions required beyond the roadmap in Section 8.")

    # ================= 2 SCOPE
    w("\n---\n\n## 2. Scope and Methodology\n")
    w("### 2.1 Application Under Review\n")
    w(table(["Attribute", "Detail"], [
        ["Application", app], ["Repository", meta.get("repository", "—")],
        ["Files / lines analysed", f"{inv['files_scanned']:,} files / {inv['lines']:,} lines"],
        ["Detected stack and features", ", ".join(inv["frameworks"]) or "—"],
        ["Dependency manifests", ", ".join(f"`{m}`" for m in inv["manifests"][:12]) or "none found"],
        ["Infrastructure-as-code files", str(len(inv["iac_files"])) if inv["iac_files"] else "none found"]]))
    w("\n### 2.2 Scope\n")
    sin = tri.get("meta", {}).get("scope_in") or ["Application source code, configuration files, infrastructure-as-code and container definitions in the repository",
                                                    "Dependency manifests and lockfiles (SBOM generated)", "Local git history (secret exposure)"]
    sout = tri.get("meta", {}).get("scope_out") or ["The live site, deployed environments and any network-based testing (no network calls were made)",
                                                      "Runtime/dynamic behaviour, penetration testing, load testing", "IdP, WAF, gateway and cloud-account configuration not present in the repository",
                                                      "Physical, personnel and process controls"]
    w("**In scope**\n\n" + "\n".join(f"- {x}" for x in sin) + "\n\n**Out of scope**\n\n" + "\n".join(f"- {x}" for x in sout))
    w("\n### 2.3 Approach\n")
    w("1. **Automated static scan.** An offline scanner applied regex-based detection rules per language and file type, scanned local git history for secrets, parsed dependency manifests and generated a CycloneDX SBOM.\n"
      "2. **Manual code review.** Each candidate was read in context and confirmed or rejected. Each control domain was then reviewed by reading the relevant code paths (authentication, authorization, data access, configuration) to assess controls the scanner cannot see.\n"
      "3. **Checklist assessment.** Every control in Section 4 was assigned a status with the evidence examined.\n"
      "4. **Compliance mapping.** Findings were mapped to NIST SP 800-53 Rev. 5, IRS Publication 1075 and EOTSS standards"
      + (", plus " + ", ".join(f["name"] for f in frameworks) if frameworks else "") + ".")
    w("\n### 2.4 Severity Rating Scale\n")
    w(table(["Severity", "Definition"], [[s, SEV_DEF[s]] for s in SEV]))
    w("\n### 2.5 Checklist Status Definitions\n")
    w(table(["Status", "Meaning"], [[a_, b_] for a_, b_ in STATUS_DEF]))
    w("\n### 2.6 Limitations and Assumptions\n")
    w("\n".join(f"- {x}" for x in scan["limitations"]) +
      "\n- Absence of a finding in a domain is not a guarantee of security. Source-only review cannot confirm controls enforced outside the repository.\n"
      "- Severity reflects code-level exploitability and data sensitivity; it should be re-rated with deployment context (network exposure, compensating controls).")

    # ================= 3 SUMMARY
    w("\n---\n\n## 3. Findings Summary\n")
    w("### 3.1 Findings by Domain and Severity\n")
    rows = []
    for i, dk in enumerate(dom_order, 1):
        ds = [f for f in findings if f["domain"] == dk]
        c = sev_counts(ds)
        rows.append([f"4.{i} {dom_title[dk]}"] + [c[s] for s in SEV] + [len(ds)])
    rows.append(["**Total**"] + [f"**{sev_counts(findings)[s]}**" for s in SEV] + [f"**{len(findings)}**"])
    w(table(["Domain"] + SEV + ["Total"], rows))
    w("\n### 3.2 Findings Register\n")
    if findings:
        w(table(["No.", "ID", "Severity", "Domain", "Finding", "Location", "Confirmed", "Status"],
                [[f"5.{i}", f["id"], f["severity"], dom_title[f["domain"]], f["title"], loc_str(f), "Yes" if f["decision"] == "confirmed" else "No, verify", f.get("status", "Open")]
                 for i, f in enumerate(findings, 1)]))
    else:
        w("No findings.")

    # ================= 4 CHECKLIST
    w("\n---\n\n## 4. Security Control Checklist by Domain\n")
    w("Status values are defined in Section 2.5. *Evidence* states what was examined or which finding applies.\n")
    for i, dk in enumerate(dom_order, 1):
        items = [c for c in checklist if c["domain"] == dk]
        w(f"### 4.{i} {dom_title[dk]}\n")
        w(dom_intro[dk] + "\n")
        w(table(["No.", "Control / Issue", "Status", "Evidence"], [[c["number"], c["issue"], f"**{c['status']}**", c["evidence"]] for c in items]))
        ds = [f for f in findings if f["domain"] == dk]
        w("\n**Findings in this domain:** " + (", ".join(f"{f['id']} ({f['severity']})" for f in ds) if ds else "none") + "\n")

    # ================= 5 DETAILED FINDINGS
    w("\n---\n\n## 5. Detailed Findings\n")
    if not findings:
        w("No findings to report.")
    for i, f in enumerate(findings, 1):
        nist, irs, eot = controls(f)
        flag = "" if f["decision"] == "confirmed" else " [UNCONFIRMED: verify manually]"
        w(f"### 5.{i} {f['id']}: {f['title']}{flag}\n")
        w(table(["Attribute", "Detail"], [
            ["Severity", f"**{f['severity']}**"], ["Domain", dom_title[f["domain"]]],
            ["Location", ", ".join(f"`{f['file']}:{l['line']}`" for l in (f.get("locations") or [dict(line=f['line'])])[:8])],
            ["Weakness (CWE)", f.get("cwe") or "—"], ["OWASP Top 10 (2021)", f.get("owasp") or "—"],
            ["Confidence", f.get("confidence", "—")], ["Detected by", f.get("source", "scanner") + (f" rule {f['rule']}" if f["rule"] != "MANUAL" else " (manual review)")],
            ["Status", f.get("status", "Open")]]))
        desc = (f.get("description") or "").strip()
        note = (f.get("detail") or "").strip()
        if not desc:
            desc = f"Static analysis identified: {f['title'].rstrip('.')}. The affected code is quoted in the evidence below."
        w(f"\n**Description.** {desc}" + (f" {note}" if note and note not in desc else "") + "\n")
        if f.get("exploit_scenario"):
            w(f"**Exploit scenario.** {f['exploit_scenario']}\n")
        if f.get("impact"):
            w(f"**Impact.** {f['impact']}\n")
        snips = [l for l in (f.get("locations") or []) if l.get("snippet")]
        if snips:
            w("**Evidence** (secrets masked)\n")
            w("```text\n" + "\n".join(f"{f['file']}:{l['line']}: {redact_line(l['snippet'])}" for l in snips[:6]) + "\n```\n")
        w(f"**Recommendation.** {f['fix']}\n")
        w("**Compliance mapping.** NIST 800-53: " + ", ".join(c for c, _ in nist[:6]) + ". IRS Pub 1075: " + ", ".join(c for c, _ in irs[:4]) +
          ". EOTSS: " + "; ".join(eotss_label(e) for e in eot[:3]) + ".\n")

    # ================= 6 COMPLIANCE
    w("\n---\n\n## 6. Compliance Mapping\n")
    w("Each finding inherits the controls mapped to its domain (`references/compliance-map.json`) plus any control added during review. "
      "Confirm section numbers against the revisions the customer is audited against. IRS Pub 1075 Section 9.3 follows NIST 800-53 families; FTI-specific requirements "
      "(FIPS 140-validated encryption in transit and at rest, audit of every FTI access, MFA for remote/privileged access, disposal) drive the severity of findings in the "
      "access, crypto, data, logging and iac domains.\n")
    inv_n, inv_i, inv_e = {}, {}, {}
    inv_x = {fw["name"]: {} for fw in frameworks}
    for f in findings:
        nist, irs, eot = controls(f)
        for c, t in nist:
            inv_n.setdefault((c, t), []).append(f["id"])
        for c, t in irs:
            inv_i.setdefault((c, t), []).append(f["id"])
        for e in eot:
            inv_e.setdefault(eotss_label(e), []).append(f["id"])
        for fw in frameworks:
            for c, t in (fw.get("domains", {}).get(f["domain"], [])):
                inv_x[fw["name"]].setdefault((c, t), []).append(f["id"])
    uniq = lambda l: ", ".join(dict.fromkeys(l))
    nat = lambda kv: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", kv[0][0])]
    w("### 6.1 NIST SP 800-53 Rev. 5\n")
    w(table(["Control", "Title", "Findings"], [[c, t, uniq(v)] for (c, t), v in sorted(inv_n.items(), key=nat)]) if inv_n else "No findings mapped.")
    w("\n### 6.2 IRS Publication 1075\n")
    w(table(["Reference", "Requirement area", "Findings"], [[c, t, uniq(v)] for (c, t), v in sorted(inv_i.items(), key=nat)]) if inv_i else "No findings mapped.")
    w("\n### 6.3 Massachusetts EOTSS Enterprise Information Security Standards\n")
    w(table(["Standard", "Findings"], [[k, uniq(v)] for k, v in sorted(inv_e.items())]) if inv_e else "No findings mapped.")
    w("\n\\* Standard number to be confirmed against the current EOTSS handbook; topic mapping is as shown.")
    n = 4
    for fw in frameworks:
        w(f"\n### 6.{n} {fw['name']}\n")
        m = inv_x[fw["name"]]
        w(table(["Requirement", "Title", "Findings"], [[c, t, uniq(v)] for (c, t), v in sorted(m.items(), key=nat)]) if m else "No findings mapped.")
        n += 1
    w(f"\n### 6.{n} Finding-to-Control Matrix\n")
    rows = []
    for f in findings:
        nist, irs, eot = controls(f)
        row = [f["id"], f["severity"], ", ".join(c for c, _ in nist), ", ".join(c for c, _ in irs), "; ".join(e["id"] or e["title"] + "*" for e in eot)]
        for fw in frameworks:
            row.append(", ".join(c for c, _ in fw.get("domains", {}).get(f["domain"], [])))
        rows.append(row)
    w(table(["Finding", "Severity", "NIST 800-53", "IRS Pub 1075", "EOTSS"] + [fw["name"] for fw in frameworks], rows) if rows else "No findings.")

    # ================= 7 DEPENDENCIES
    w("\n---\n\n## 7. Dependencies and Software Bill of Materials\n")
    deps = scan["dependencies"]
    w("### 7.1 Inventory\n")
    if deps["ecosystems"]:
        w(table(["Ecosystem", "Components", "Version-pinned", "Dev-only"], [[k, v["total"], v["pinned"], v["dev"]] for k, v in sorted(deps["ecosystems"].items())]))
    else:
        w("No dependency manifests were found.")
    w(f"\nA CycloneDX 1.5 SBOM with {deps['total']} components was generated: `{deps['sbom']}` (deliver alongside this report).\n")
    w("### 7.2 Vulnerable, Unmaintained and Unpinned Dependencies\n")
    dd = [f for f in findings if f["domain"] == "deps"]
    w(table(["ID", "Severity", "Issue", "Detail", "Manifest"], [[f["id"], f["severity"], f["title"], f.get("detail", ""), f"`{f['file']}`"] for f in dd]) if dd else "None identified.")
    w("\n*Coverage note:* CVE matching used a curated offline list; run a connected OSV/NVD scan before release and import results to complete this section.")

    # ================= 8 ROADMAP
    w("\n---\n\n## 8. Remediation Roadmap\n")
    def road(title, sevs, note):
        fs = [f for f in confirmed if f["severity"] in sevs]
        w(f"### {title}\n")
        w(note + "\n")
        w(table(["ID", "Severity", "Action", "Location"], [[f["id"], f["severity"], first_sentence(f["fix"], 220), loc_str(f)] for f in fs]) if fs else "No items.")
        w("")
    road("8.1 Immediate (0-30 days)", ("Critical", "High"), "Rotate any exposed credentials first, then close exploitable weaknesses.")
    road("8.2 Short term (30-90 days)", ("Medium",), "Control gaps and hardening with partial compensating measures.")
    road("8.3 Planned (next release cycles)", ("Low", "Info"), "Hygiene and defence-in-depth.")
    w("### 8.4 Verification and Process Improvements\n")
    w("- Verify unconfirmed candidates and every `NOT VERIFIED` control against deployed configuration (IdP policy, WAF/gateway, cloud account).\n"
      "- Add pre-commit and CI secret scanning, SAST and dependency/SBOM generation; fail builds on Critical/High.\n"
      "- Run a connected CVE scan (OSV/NVD) and a dynamic test (DAST/penetration test) to complement this static review.\n"
      "- Re-run this audit after remediation and compare against this report.")

    # ================= APPENDICES
    w("\n---\n\n## Appendix A. Scan Coverage and Tooling\n")
    h = scan["history"]
    w(table(["Item", "Detail"], [
        ["Scanner", f"{scan['meta']['tool']} {scan['meta']['version']} (offline; no network calls)"],
        ["Scan time", scan["meta"]["scanned_at"]], ["Files analysed", f"{inv['files_scanned']:,}"],
        ["Git history", f"{h['commits_scanned']} commits scanned, {h['hits']} secret hit(s)" if h.get("ran") else h.get("note", "not scanned")],
        ["Detection rules", f"{len(R.RULES)} line rules, {len(R.PRESENCE)} control-presence checks"],
        ["Imported results", f"{scan.get('sarif_imported', 0)} SARIF result(s)"],
        ["Candidates raised / confirmed / rejected / unconfirmed", f"{len(scan['findings'])} / {len(confirmed) - n_manual} / {len(rejected)} / {len(unconfirmed)}"],
        ["Manually added findings", str(n_manual)]]))
    w("\n## Appendix B. Rejected Candidates (False Positives)\n")
    w(table(["ID", "Rule", "Location", "Reason"], [[f["id"], f["rule"], f"`{f['file']}:{f['line']}`", r_] for f, r_ in rejected]) if rejected else "None.")

    text = "\n".join(L) + "\n"
    # defence in depth: never emit a secret value
    leaks = []
    for ln, line in enumerate(text.split("\n"), 1):
        for name, rx, _ in R.SECRET_PATTERNS[:-1]:
            if rx.search(line):
                leaks.append((ln, name))
    if leaks:
        print("Refusing to write report: unmasked secret-like values at report lines " + ", ".join(f"{l} ({n})" for l, n in leaks[:10]), file=sys.stderr)
        sys.exit(4)

    out_dir = a.out or os.path.dirname(os.path.abspath(a.scan))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{a.prefix}_{stamp}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    for wmsg in warnings:
        print("warning: " + wmsg, file=sys.stderr)
    print(f"Report written: {path}")
    print(f"Overall risk: {rating}; confirmed {len(confirmed)}, unconfirmed {len(unconfirmed)}, rejected {len(rejected)}")


if __name__ == "__main__":
    main()
