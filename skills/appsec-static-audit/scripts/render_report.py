#!/usr/bin/env python3
"""Render the enterprise security audit report (Markdown) from scan.json + triage.json.

Output file: <out>/security-audit-report_<YYYYMMDD-HHMMSS>.md  (timestamp suffix, local time)

triage.json (written by the auditor after reading the code):
{
  "meta": {"application": "...", "customer": "...", "assessor": "...", "engagement": "...",
           "executive_commentary": "optional paragraph", "scope_in": ["..."], "scope_out": ["..."], "fti_in_scope": true},
  "decisions": {"FND-001": "confirmed" | "false_positive" | "needs_review" | "consolidated",
                "FND-002": {"decision": "false_positive", "reason": "value is a documented test constant"},
                "FND-003": {"decision": "consolidated", "into": "FND-M01", "reason": "same root cause"}},
  "bulk": [{"rule": "DKR-1", "file_regex": "^docker/", "decision": "false_positive", "reason": "..."}],   (applies only where no explicit decision)
  meta extras: application_description, architecture_md (section 2.7, Markdown/mermaid), immediate_actions (list of strings for 1.6),
               dependency_notes_md (section 7.3), scope_in / scope_out, positive_controls_md, fti_in_scope
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
import hashlib
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
              "not verified": "NOT VERIFIED", "nv": "NOT VERIFIED", "not assessed": "NOT ASSESSED"}
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
              ("NOT VERIFIED", "Could not be determined from source alone (runtime, IdP or platform setting); needs confirmation."),
              ("NOT ASSESSED", "No reviewer decision was recorded for this control in this engagement (it was not reviewed); it must not be read as a pass.")]


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
    files = {l.get("file", f["file"]) for l in locs}
    if len(files) > 1:
        return f"`{f['file']}:{f['line']}` and {len(files) - 1} other file(s)"
    lines = sorted({l["line"] for l in locs}) or [f.get("line", 1)]
    shown = ", ".join(str(x) for x in lines[:6]) + ("…" if len(lines) > 6 else "")
    return f"`{f['file']}:{shown}`"


CWE_OWASP = {}
for _o, _l in {"A01": [22, 200, 269, 284, 285, 352, 425, 601, 639, 862, 863, 915], "A02": [259, 311, 312, 319, 326, 327, 328, 330, 338, 916],
               "A03": [20, 74, 77, 78, 79, 89, 94, 95, 116, 917, 943], "A04": [209, 434, 522, 770, 799, 840], "A05": [16, 489, 611, 614, 693, 942, 1004, 1275],
               "A06": [1104, 1395], "A07": [287, 288, 290, 294, 306, 307, 345, 384, 613, 798, 521], "A08": [345, 347, 494, 502, 829],
               "A09": [117, 223, 532, 778], "A10": [918]}.items():
    for _c in _l:
        CWE_OWASP.setdefault(_c, _o)


def owasp_for(cwe):
    m = re.search(r"(\d+)", cwe or "")
    return CWE_OWASP.get(int(m.group(1)), "") if m else ""


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


def _bulk_match(b, f):
    if b.get("rule") and not (f["rule"] == b["rule"] or (b["rule"].endswith("*") and f["rule"].startswith(b["rule"][:-1]))):
        return False
    if b.get("file_regex") and not re.search(b["file_regex"], f["file"]):
        return False
    if b.get("snippet_regex") and not re.search(b["snippet_regex"], " ".join(l.get("snippet", "") for l in f["locations"])):
        return False
    return bool(b.get("rule") or b.get("file_regex") or b.get("snippet_regex"))


def previous_confirmed(ptri, pscan):
    """What an earlier review confirmed: scanner candidates (with overrides applied) and hand-written findings."""
    byfp = {f["fingerprint"]: f["id"] for f in pscan["findings"] if f.get("fingerprint")}
    explicit = {byfp.get(k, k): (v.get("decision") if isinstance(v, dict) else v) for k, v in (ptri.get("decisions") or {}).items()}
    ov = {byfp.get(k, k): v for k, v in (ptri.get("overrides") or {}).items()}
    out = []
    for f in pscan["findings"]:
        d = explicit.get(f["id"])
        if d is None and f.get("suppression"):
            d = "accepted_risk" if f["suppression"].get("type") == "accepted_risk" else "false_positive"
        if d is None:
            d = next((b["decision"] for b in (ptri.get("bulk") or []) if _bulk_match(b, f)), None)
        if str(d or "").lower().replace(" ", "_") != "confirmed":
            continue
        o = ov.get(f["id"]) or {}
        out.append(dict(kind="scanner", id=f["id"], fp=f.get("fingerprint"), rule=f["rule"], title=o.get("title") or f["title"], severity=o.get("severity") or f["severity"],
                        file=o.get("file") or f["file"], line=o.get("line") or f["line"], cwe=f.get("cwe") or o.get("cwe", "")))
    for n in ptri.get("new_findings") or []:
        out.append(dict(kind="manual", id=n.get("id", ""), key=n.get("key") or f"{n.get('file', '')}|{n.get('cwe', '')}|{n['domain']}", title=n["title"],
                        severity=n["severity"], file=n.get("file", ""), line=n.get("line", 1), cwe=n.get("cwe", "")))
    return out


def source_revision(meta, git):
    repos = meta.get("repositories")
    if repos:
        items = [f"{n}: {(g or {}).get('branch') or '—'} @ {(g or {}).get('commit') or 'not under git'}" for n, g in repos.items()]
        return "; ".join(items[:8]) + (f" (+{len(items) - 8} more, see Appendix A)" if len(items) > 8 else "")
    return f"{git.get('branch', '—')} @ {git.get('commit', '—')}" if git.get("commit") else "Not under git / unknown"


def repository_revisions(meta, git):
    repos = meta.get("repositories")
    if repos:
        lines = []
        for n, g in list(repos.items())[:40]:
            g = g or {}
            lines.append(f"{n}: " + (f"`{g['commit_full']}` ({'uncommitted changes to tracked files' if g.get('dirty') else 'clean'})" if g.get("commit_full") else "not under git"))
        return "<br>".join(lines) + (f"<br>…and {len(repos) - 40} more" if len(repos) > 40 else "")
    return (f"`{git['commit_full']}`" + (" (working tree had uncommitted changes to tracked files)" if git.get("dirty") else " (clean)")) if git.get("commit_full") else "not under git"


def norm_ws(x):
    return re.sub(r"\s+", " ", x or "").strip()


def _evidence_fragments(evidence):
    parts = re.split(r"\.\.\.|…|\[MASKED\]|\*{4,}", evidence or "")
    frags = [norm_ws(p) for p in parts]
    return sorted([p for p in frags if len(p) >= 10], key=len, reverse=True)[:2]


def resolve_repo_file(repos, rel):
    """Absolute path of `rel` inside one of the repositories (also accepting `<repo-folder>/path` for multi-repository scans), or None."""
    repos = [repos] if isinstance(repos, str) else list(repos or [])
    for r in repos:
        root = os.path.realpath(r)
        cands = [rel or ""]
        head = os.path.basename(root.rstrip(os.sep)) + "/"
        if (rel or "").startswith(head):
            cands.append(rel[len(head):])
        for c in cands:
            p = os.path.realpath(os.path.join(root, c))
            if (p == root or p.startswith(root + os.sep)) and os.path.isfile(p):
                return p
    return None


def check_evidence(repo, rel, line, evidence):
    """Check a hand-written citation against the working tree. -> (line, message|None, corrected). Quoted evidence may be abbreviated with '...'."""
    p = resolve_repo_file(repo, rel)
    if p is None:
        return line, f"'{rel}' is not in the working tree (expected only for a git-history finding; otherwise fix the path)", False
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return line, f"'{rel}' could not be read", False
    if line < 1 or line > len(lines):
        return line, f"{rel}:{line} is outside the file ({len(lines)} lines)", False
    frags = _evidence_fragments(evidence)
    if not frags:
        return line, None, False
    nl = [norm_ws(x) for x in lines]
    if all(fr in " ".join(nl[max(0, line - 9):line + 8]) for fr in frags):
        return line, None, False
    single = [i + 1 for i in range(len(nl)) if frags[0] in nl[i]]
    joined = [i + 1 for i in range(len(nl)) if frags[0] in " ".join(nl[i:i + 3])]
    cands = single or joined
    if cands:
        best = min(cands, key=lambda c: abs(c - line))
        return best, f"{rel}: cited line {line} but the quoted evidence is at line {best}; corrected", True
    return line, f"{rel}:{line}: the quoted evidence was not found in the file", False


def assign_manual_ids(manual, reg_path):
    """Manual findings get IDs that survive re-renders: keyed by (file, CWE, domain) or an explicit `key`, remembered in finding-ids.json."""
    try:
        with open(reg_path, encoding="utf-8") as fh:
            reg = json.load(fh)
    except (OSError, ValueError):
        reg = {}
    m = reg.setdefault("manual", {})
    used = {int(v) for v in m.values()}
    nxt = max(used | {0}) + 1
    seen = {}
    taken = {}
    for f in manual:
        key = f["_mkey"]
        seen[key] = seen.get(key, 0) + 1
        k2 = key if seen[key] == 1 else f"{key}#{seen[key]}"
        num = None
        if f.get("_explicit_id"):
            num = int(f["_explicit_id"][5:])
            m[k2] = num
        elif k2 in m:
            num = int(m[k2])
        if num is None:
            while nxt in used or nxt in taken:
                nxt += 1
            num = nxt
            m[k2] = num
        used.add(num)
        taken[num] = k2
        f["id"] = f"FND-M{num:02d}"
    try:
        with open(reg_path, "w", encoding="utf-8") as fh:
            json.dump(reg, fh, indent=1, sort_keys=True)
    except OSError:
        pass


def masked_excerpt(repo, rel, line, context=22):
    """Masked source lines around `line`. The path must resolve inside a repository."""
    p = resolve_repo_file(repo, rel)
    if p is None:
        return "(file not available)"
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return "(file not readable)"
    lo, hi = max(1, line - context), min(len(lines), line + context)
    return "\n".join(f"{n:>5}  {redact_line(lines[n - 1]) if lines[n - 1].strip() else ''}" for n in range(lo, hi + 1))


def write_packets(out, repo, crit_high, scan):
    """One self-contained packet per Critical/High finding. A packet carries the claim and the code, deliberately NOT the
    assessor's description, exploit scenario or impact, so the second reader forms their own view."""
    os.makedirs(out, exist_ok=True)
    index = ["# Verification packets\n",
             "Give each packet to a reviewer (a fresh agent/session or a different person) who has **not** seen the original triage. "
             "They answer from the code, then fill `verification.json` (template at the end of each packet). Save it as `work/verification.json` next to `scan.json`.\n",
             "| ID | Severity | Claim | Packet | SHA-256 (start) |", "|---|---|---|---|---|"]
    template = {}
    manifest = {}
    for f in crit_high:
        locs = (f.get("locations") or [dict(line=f["line"])])[:3]
        body = [f"# Verify {f['id']}: {f['title']}\n",
                "You are the **second reader**. Decide from the code whether the claim below is true. You were not given the first reviewer's reasoning on purpose. "
                "Open the callers and the framework configuration when the excerpt is not enough; do not assume a guard exists or does not exist.\n",
                f"- **Claimed severity:** {f['severity']}", f"- **Weakness:** {f.get('cwe') or '-'}", f"- **Rule that raised it:** {f['rule']}",
                f"- **Claim:** {f['title']}" + (f". Scanner note: {f['detail']}" if f.get("detail") else ""), ""]
        for l in locs:
            fl = l.get("file", f["file"])
            body += [f"## `{fl}:{l['line']}`\n", "```text", masked_excerpt(repo, fl, int(l["line"])), "```\n"]
        body += ["## Answer these\n",
                 "1. Is the weakness really present in this code? Quote the lines.",
                 "2. Can attacker-controlled input reach it, or is there a guard (validation, authorization, framework default, config)? Where?",
                 "3. What is the realistic impact, and does the claimed severity fit?",
                 "4. Give a verdict: `agree`, `disagree` or `inconclusive`.\n",
                 "## Verdict template\n", "```json",
                 json.dumps({f["id"]: {"verdict": "agree | disagree | inconclusive", "verifier": "name or agent", "session": "model / session id",
                                       "independence": "independent | self", "packet_sha256": "output of: sha256sum " + f["id"] + ".md",
                                       "severity_suggestion": "", "notes": "one or two sentences with file:line evidence"}}, indent=2), "```\n",
                 "Secrets are masked in this packet. Do not write secret values anywhere."]
        fn = f"{f['id']}.md"
        text = "\n".join(body)
        with open(os.path.join(out, fn), "w", encoding="utf-8") as fh:
            fh.write(text)
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        manifest[f["id"]] = dict(file=fn, sha256=sha)
        index.append(f"| {f['id']} | {f['severity']} | {cell(f['title'])} | [{fn}]({fn}) | `{sha[:12]}` |")
        template[f["id"]] = {"verdict": "", "verifier": "", "session": "", "independence": "independent", "packet_sha256": sha, "severity_suggestion": "", "notes": ""}
    with open(os.path.join(out, "INDEX.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(index) + "\n")
    with open(os.path.join(out, "verification.template.json"), "w", encoding="utf-8") as fh:
        json.dump({"verifications": template}, fh, indent=2)
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"Wrote {len(crit_high)} verification packet(s) to {out}")


SARIF_SCORE = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0", "Info": "0.5"}
SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}


def build_sarif(scan, findings, rejected, accepted):
    """SARIF 2.1.0 of the triaged result. Rejected and accepted-risk candidates are included as suppressed so a code-scanning
    UI does not re-raise them. Snippets are already masked; fingerprints are stable across line moves."""
    rules_meta, results = {}, []

    def add(f, suppression=None):
        rid = f["rule"] if f["rule"] != "MANUAL" else "MANUAL-" + re.sub(r"[^A-Z0-9]+", "-", f["title"].upper())[:30]
        rules_meta.setdefault(rid, dict(id=rid, name=re.sub(r"[^A-Za-z0-9]+", "", f["title"].title())[:60] or rid, shortDescription=dict(text=f["title"][:200]),
                                        help=dict(text=(f.get("fix") or "")[:1000]),
                                        properties={"security-severity": SARIF_SCORE[f["severity"]], "tags": [t for t in ["security", f.get("cwe", ""), f.get("owasp", ""), f["domain"]] if t]}))
        loc = f.get("locations") or [dict(line=f.get("line", 1))]
        r = dict(ruleId=rid, level=SARIF_LEVEL[f["severity"]],
                 message=dict(text=f"{f['title']}" + (f" ({first_sentence(f.get('description') or f.get('detail') or '', 220)})" if (f.get("description") or f.get("detail")) else "")),
                 locations=[dict(physicalLocation=dict(artifactLocation=dict(uri=l.get("file", f["file"])), region=dict(startLine=max(1, int(l.get("line", 1) or 1)))))
                            for l in loc[:5]],
                 partialFingerprints={"appsecAudit/v1": f.get("fingerprint") or f["id"]},
                 properties=dict(findingId=f["id"], severity=f["severity"], confirmed=(f["decision"] == "confirmed"), confidence=f.get("confidence", "")))
        if suppression:
            r["suppressions"] = [dict(kind="external", status="accepted", justification=suppression[:500])]
        results.append(r)

    for f in findings:
        add(f)
    for f, reason, _d in rejected:
        add(f, reason or "rejected during triage")
    for f, reason in accepted:
        add(f, reason or "accepted risk")
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [dict(tool=dict(driver=dict(name="appsec-static-audit", version=scan["meta"]["version"], informationUri="https://github.com/lowtouch-ai/krithi-skills",
                                                 rules=list(rules_meta.values()))),
                          results=results,
                          properties=dict(repository=scan["meta"].get("repository", ""), commit=(scan["meta"].get("git") or {}).get("commit_full", ""),
                                          scannerSha256=(scan["meta"].get("run") or {}).get("scanner_sha256", "")))]}


def main():
    ap = argparse.ArgumentParser(description="Render the Markdown audit report")
    ap.add_argument("--scan", required=True, help="scan.json from audit.py")
    ap.add_argument("--triage", required=True, help="triage.json written by the auditor")
    ap.add_argument("--out", help="output directory (default: directory of scan.json)")
    ap.add_argument("--prefix", default="security-audit-report")
    ap.add_argument("--framework", action="append", default=[], help="extra framework mapping JSON (repeatable)")
    ap.add_argument("--allow-untriaged", action="store_true", help="render even if candidates lack a decision")
    ap.add_argument("--allow-unassessed", action="store_true", help="(default behaviour since 1.2; kept for compatibility)")
    ap.add_argument("--strict-checklist", action="store_true", help="refuse to render while any checklist item lacks a reviewer status")
    ap.add_argument("--verification", help="verification.json from the independent second pass (default: <out>/work/verification.json if present)")
    ap.add_argument("--packets", metavar="DIR", help="instead of rendering, write blind verification packets for confirmed Critical/High findings into DIR (needs --repo)")
    ap.add_argument("--repo", action="append", default=[], help="repository path (repeat for a multi-repository scan; paths prefixed with the folder name are understood): used by --packets to quote masked excerpts, and to check that hand-written file:line citations and quoted evidence match the source")
    ap.add_argument("--previous-triage", metavar="FILE", help="triage.json of an earlier review of the same code: the report lists every finding it confirmed that this review does not confirm, and why")
    ap.add_argument("--previous-scan", metavar="FILE", help="scan.json belonging to --previous-triage (default: scan.json next to it)")
    ap.add_argument("--strict-evidence", action="store_true", help="with --repo, treat a manual citation that does not match the source as an error instead of a warning")
    ap.add_argument("--emit-sarif", action="store_true", help="also write a SARIF 2.1.0 file next to the report (confirmed and unconfirmed findings; rejected ones as suppressed)")
    ap.add_argument("--fail-on", choices=["Critical", "High", "Medium", "Low"], help="exit with code 10 if a confirmed finding at or above this severity exists (for CI gates)")
    ap.add_argument("--fail-on-unconfirmed", action="store_true", help="with --fail-on, count unconfirmed candidates too")
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

    out_dir0 = a.out or os.path.dirname(os.path.abspath(a.scan))
    # ---------------- hand-written citations must match the source
    manual_items = [(n, n.get("file"), "line") for n in (tri.get("new_findings") or [])]
    ov_locs = [(loc, loc.get("file") or (tri.get("overrides") or {}).get(k, {}).get("file"), "line") for k, ov in (tri.get("overrides") or {}).items() for loc in (ov.get("locations") or [])]
    repos_ok = [r for r in (a.repo or []) if os.path.isdir(r)]
    if repos_ok:
        for n in tri.get("new_findings") or []:
            ln, msg, fixed = check_evidence(repos_ok, n.get("file"), int(n.get("line", 1) or 1), n.get("evidence"))
            if fixed:
                n["line"] = ln
            if msg:
                (warnings if (fixed or not a.strict_evidence) else errors).append(f"manual finding '{n.get('title', '')[:50]}': {msg}")
        for k, ov in (tri.get("overrides") or {}).items():
            for loc in ov.get("locations") or []:
                f_ = loc.get("file") or ov.get("file")
                if not f_:
                    continue
                ln, msg, fixed = check_evidence(repos_ok, f_, int(loc.get("line", 1) or 1), loc.get("snippet"))
                if fixed:
                    loc["line"] = ln
                if msg:
                    (warnings if (fixed or not a.strict_evidence) else errors).append(f"{k} location: {msg}")
    elif manual_items or ov_locs:
        warnings.append("hand-written file:line citations and quoted evidence were not checked against the source (pass --repo <path> to validate them)")

    # ---------------- findings: apply triage
    decisions = {}
    reasons = {}
    into = {}
    for k, v in (tri.get("decisions") or {}).items():
        if isinstance(v, dict):
            decisions[k], reasons[k] = v.get("decision", ""), v.get("reason", "")
            if v.get("into"):
                into[k] = v["into"]
        else:
            decisions[k] = v
    overrides = tri.get("overrides") or {}
    findings, rejected, accepted, cand_log = [], [], [], []
    by_fp = {f["fingerprint"]: f["id"] for f in scan["findings"]}
    decisions = {by_fp.get(k, k): v for k, v in decisions.items()}
    overrides = {by_fp.get(k, k): v for k, v in overrides.items()}
    for f in scan["findings"]:
        d = decisions.get(f["id"])
        via = "explicit" if d is not None else ""
        if d is None and f.get("suppression"):
            sp = f["suppression"]
            via = "suppression"
            d = "accepted_risk" if sp["type"] == "accepted_risk" else "false_positive"
            reasons[f["id"]] = (f"Suppressed by policy ({sp.get('owner') or 'owner not stated'}"
                                + (f", expires {sp['expires']}" if sp.get("expires") else "") + f"): {sp['reason']}")
        if d is None:
            for b in tri.get("bulk") or []:
                if b.get("rule") and not (f["rule"] == b["rule"] or (b["rule"].endswith("*") and f["rule"].startswith(b["rule"][:-1]))):
                    continue
                if b.get("file_regex") and not re.search(b["file_regex"], f["file"]):
                    continue
                if b.get("snippet_regex") and not re.search(b["snippet_regex"], " ".join(l.get("snippet", "") for l in f["locations"])):
                    continue
                if not (b.get("rule") or b.get("file_regex") or b.get("snippet_regex")):
                    continue
                d, reasons[f["id"]] = b["decision"], b.get("reason", "")
                via = "bulk"
                if b.get("into"):
                    into[f["id"]] = b["into"]
                break
        if d is None:
            if not a.allow_untriaged:
                errors.append(f"candidate {f['id']} ({f['rule']} {f['file']}:{f['line']}) has no decision in triage.json")
            d = "needs_review"
        d = d.lower().replace(" ", "_")
        if d not in ("confirmed", "false_positive", "needs_review", "consolidated", "accepted_risk"):
            errors.append(f"{f['id']}: unknown decision '{d}'")
        f = {**f, **{k: v for k, v in (overrides.get(f["id"]) or {}).items() if k != "controls_extra"}}
        f["controls_extra"] = (overrides.get(f["id"]) or {}).get("controls_extra", {})
        f["decision"] = d
        f["decided_by"] = via or "none"
        cand_log.append(f)
        if d == "accepted_risk":
            if not reasons.get(f["id"]):
                errors.append(f"{f['id']}: accepted_risk needs a reason (and should name an owner and expiry)")
            accepted.append((f, reasons.get(f["id"], "")))
        elif d in ("false_positive", "consolidated"):
            if not reasons.get(f["id"]):
                warnings.append(f"{f['id']} rejected without a reason")
            if d == "consolidated" and not into.get(f["id"]):
                warnings.append(f"{f['id']} consolidated without 'into'")
            rejected.append((f, ("Consolidated into " + into[f["id"]] + ". " if into.get(f["id"]) else "") + reasons.get(f["id"], ""), d))
        else:
            findings.append(f)
    reason_counts = {}
    for f_, r_, _d in rejected:
        if r_.strip() and f_.get("decided_by") in ("explicit", "bulk"):
            reason_counts.setdefault(norm_ws(r_).lower()[:220], []).append(f_)
    shared_reasons = []
    for k, fs_ in reason_counts.items():
        n_exp = sum(1 for x in fs_ if x["decided_by"] == "explicit")
        n_bulk = len(fs_) - n_exp
        if n_exp >= 5 or n_bulk >= 25:
            shared_reasons.append((fs_[0]["id"], len(fs_), k))
            warnings.append(f"{len(fs_)} candidates were rejected with the identical reason \"{k[:90]}…\" ({'by bulk rules' if n_bulk >= n_exp else 'individually'}): "
                            "confirm each was read, or record candidate-specific evidence")
    manual_list = []
    for n in tri.get("new_findings") or []:
        loc_line = int(n.get("line", 1) or 1)
        explicit = n.get("id") if re.fullmatch(r"FND-M\d{1,4}", str(n.get("id", ""))) else None
        manual_list.append(dict(id="", rule="MANUAL", domain=n["domain"], severity=n["severity"], cwe=n.get("cwe", ""), owasp=n.get("owasp") or owasp_for(n.get("cwe", "")),
                             title=n["title"], file=n.get("file", "(multiple)"), line=loc_line, description=n.get("description", ""), detail="",
                             fix=n.get("fix", ""), impact=n.get("impact", ""), exploit_scenario=n.get("exploit_scenario", ""),
                             locations=[dict(line=loc_line, snippet=redact_line(n.get("evidence", "")))] if n.get("evidence") else [],
                             confidence=n.get("confidence", "High"), decision="confirmed", source="manual", status="Open",
                             controls_extra=n.get("controls_extra", {}), patch=n.get("patch", ""),
                             _mkey=n.get("key") or f"{n.get('file', '')}|{n.get('cwe', '')}|{n['domain']}", _explicit_id=explicit))
    assign_manual_ids(manual_list, os.path.join(os.path.dirname(os.path.abspath(a.scan)), "finding-ids.json"))
    ids_seen = {}
    for mf in manual_list:
        if mf["id"] in ids_seen:
            errors.append(f"two manual findings share the ID {mf['id']} ('{ids_seen[mf['id']]}' and '{mf['title']}'); give each a distinct `id` or `key`")
        ids_seen[mf["id"]] = mf["title"]
    findings.extend(manual_list)
    findings.sort(key=lambda f: (SEV.index(f["severity"]), dom_order.index(f["domain"]) if f["domain"] in dom_order else 99, f["file"], f["line"]))
    n_manual = len(manual_list)
    for f in findings:
        f["owasp"] = f.get("owasp") or owasp_for(f.get("cwe", ""))
        if f["domain"] not in dom_title:
            errors.append(f"{f['id']}: unknown domain '{f['domain']}'")
    for f in findings:
        if f["decision"] == "confirmed" and f["severity"] in ("Critical", "High") and not (f.get("impact") or "").strip():
            warnings.append(f"{f['id']} ({f['severity']}) has no 'impact' in overrides; add impact (and exploit_scenario) for the client")
    confirmed = [f for f in findings if f["decision"] == "confirmed"]
    unconfirmed = [f for f in findings if f["decision"] == "needs_review"]
    fid = {f["id"] for f in findings}
    unconfirmed_ids = {f["id"] for f in unconfirmed}
    via_counts = {k: sum(1 for c in cand_log if c["decided_by"] == k) for k in ("explicit", "bulk", "suppression", "none")}
    ch_log = [c for c in cand_log if c["severity"] in ("Critical", "High")]
    ch_bulk = [c for c in ch_log if c["decided_by"] == "bulk"]
    ch_bulk_kinds = {k: sum(1 for c in ch_bulk if c["decision"] == k) for k in ("needs_review", "consolidated", "false_positive", "confirmed")}
    if len(ch_bulk) >= 20 and len(ch_bulk) * 2 >= len(ch_log):
        warnings.append(f"{len(ch_bulk)} of {len(ch_log)} Critical/High candidates were dispositioned by bulk rules rather than one by one")
    prev = None
    if a.previous_triage:
        try:
            ps = a.previous_scan or os.path.join(os.path.dirname(os.path.abspath(a.previous_triage)), "scan.json")
            with open(a.previous_triage, encoding="utf-8") as fh:
                ptri = json.load(fh)
            with open(ps, encoding="utf-8") as fh:
                pscan = json.load(fh)
            pc = previous_confirmed(ptri, pscan)
            cur_conf = [f for f in findings if f["decision"] == "confirmed"]
            state_by_fp = {c.get("fingerprint"): c for c in cand_log if c.get("fingerprint")}
            state_by_rf = {(c["rule"], c["file"]): c for c in cand_log}
            carried, dropped = [], []
            for p in pc:
                hit = None
                if p["kind"] == "scanner":
                    hit = next((f for f in cur_conf if f.get("fingerprint") and f["fingerprint"] == p["fp"]), None)
                else:
                    hit = next((f for f in cur_conf if f.get("_mkey") == p["key"] or norm_ws(f["title"]).lower() == norm_ws(p["title"]).lower()), None)
                if hit is None and p["file"]:                 # reworded or re-homed: same file and weakness class
                    hit = next((f for f in cur_conf if f["file"] == p["file"] and p["cwe"] and f.get("cwe") == p["cwe"]), None)
                if hit is not None:
                    carried.append((p, hit))
                    continue
                st = state_by_fp.get(p.get("fp")) or state_by_rf.get((p.get("rule"), p["file"])) if p["kind"] == "scanner" else None
                if st is not None:
                    why = {"needs_review": "now an unconfirmed candidate", "false_positive": "now rejected as a false positive", "consolidated": "now consolidated into " + str(into.get(st["id"], "another finding")),
                           "accepted_risk": "now an accepted risk"}.get(st["decision"], "now " + st["decision"])
                    why += f" ({st['id']}" + (f": {reasons.get(st['id'], '')[:110]}" if reasons.get(st["id"]) else "") + ")"
                elif p["kind"] == "scanner":
                    why = "no longer detected in this scan (fixed, moved, excluded, or the rule changed)"
                else:
                    why = "not re-raised: no finding in this review matches it"
                dropped.append((p, why))
            prev = dict(path=os.path.basename(os.path.dirname(os.path.abspath(a.previous_triage))) or a.previous_triage, at=(pscan.get("meta") or {}).get("scanned_at", ""),
                        total=len(pc), carried=carried, dropped=dropped)
            if dropped:
                warnings.append(f"{len(dropped)} of {len(pc)} findings confirmed in the previous review are not confirmed in this one (see Section 3.5)")
        except (OSError, ValueError, KeyError) as e:
            errors.append(f"--previous-triage could not be used: {e}")
    consolidated_into_unconfirmed = [f_ for f_, _r, d_ in rejected if d_ == "consolidated" and into.get(f_["id"]) in unconfirmed_ids]
    for f_, _r, d_ in rejected:
        if d_ == "consolidated" and into.get(f_["id"]) and into[f_["id"]] not in fid and not str(into[f_["id"]]).startswith("FND-M"):
            warnings.append(f"{f_['id']} is consolidated into {into[f_['id']]}, which is not a finding in this report")

    # ---------------- independent verification of Critical/High findings
    out_dir_guess = a.out or os.path.dirname(os.path.abspath(a.scan))
    vpath = a.verification or os.path.join(out_dir_guess, "work", "verification.json")
    ver_entries = {}
    if os.path.exists(vpath):
        try:
            vj = json.load(open(vpath, encoding="utf-8"))
            ver_entries = vj.get("verifications", vj) if isinstance(vj, dict) else {}
        except (OSError, ValueError) as e:
            errors.append(f"verification file {vpath} unreadable: {e}")
    elif a.verification:
        errors.append(f"verification file {a.verification} not found")
    resolution = tri.get("verification_resolution") or {}
    manifest = {}
    try:
        with open(os.path.join(out_dir_guess, "work", "verify", "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        manifest = {}
    vstat = dict(agree=0, disagree=0, disagree_resolved=0, inconclusive=0, missing=0, self_only=0, unbound=0, stale=0)
    crit_high = [f for f in confirmed if f["severity"] in ("Critical", "High")]
    for f in crit_high:
        v = ver_entries.get(f["id"]) or ver_entries.get(f.get("fingerprint", ""))
        if not v:
            vstat["missing"] += 1
            f["verification"] = dict(verdict="not verified")
            continue
        verdict = str(v.get("verdict", "")).strip().lower()
        if verdict not in ("agree", "disagree", "inconclusive"):
            errors.append(f"{f['id']}: verification verdict must be agree, disagree or inconclusive (got '{verdict}')")
            continue
        indep = "self" if "self" in str(v.get("independence", v.get("verifier", ""))).lower() else "independent"
        psha = str(v.get("packet_sha256", "")).strip().lower()
        want = ((manifest.get(f["id"]) or {}).get("sha256") or "").lower()
        binding = "bound" if (psha and want and psha == want) else "stale" if (psha and want) else "unbound"
        f["verification"] = dict(verdict=verdict, verifier=v.get("verifier", "unspecified"), independence=indep, notes=(v.get("notes") or "").strip(),
                                 severity_suggestion=v.get("severity_suggestion", ""), binding=binding, session=str(v.get("session", v.get("model", "")))[:60])
        if indep == "self":
            vstat["self_only"] += 1
        elif binding != "bound":
            vstat[binding] += 1
            if binding == "stale":
                warnings.append(f"{f['id']}: the verification refers to an older version of the packet (the code excerpt or claim changed since it was reviewed); re-verify")
        if verdict == "disagree":
            res_note = (resolution.get(f["id"]) or "").strip()
            if not res_note:
                errors.append(f"{f['id']}: the verifier disagrees ({f['verification']['notes'][:120] or 'no notes'}). Re-read the code, then either change the decision/severity or record why the finding stands in triage.json verification_resolution")
            else:
                f["verification"]["resolution"] = res_note
                vstat["disagree_resolved"] += 1
            vstat["disagree"] += 1
        else:
            vstat[verdict] += 1

    if a.packets:
        if not repos_ok:
            sys.exit("error: --packets needs --repo <path to the audited repository> (repeat it for a multi-repository scan)")
        if errors:
            print("Cannot build packets, fix triage.json:", file=sys.stderr)
            for e in errors:
                print("  - " + e, file=sys.stderr)
            sys.exit(2)
        write_packets(a.packets, repos_ok, crit_high, scan)
        return

    # ---------------- checklist: apply triage
    cl_in = tri.get("checklist") or {}
    checklist = []
    n_unassessed = 0
    for it in scan["checklist"]:
        t = cl_in.get(it["key"], {})
        raw = (t.get("status") or it["status"]).strip()
        is_open = raw in OPEN_STATES
        st = raw if is_open else STATUS_MAP.get(raw.lower(), "")
        if not st:
            errors.append(f"{it['key']}: invalid status '{raw}'")
            st = "NOT VERIFIED"
        linked = [x for x in (t.get("findings") if "findings" in t else it["finding_ids"]) if x in fid]
        conf_linked = [x for x in linked if any(f["id"] == x and f["decision"] == "confirmed" for f in findings)]
        derived = ""
        if is_open:
            if a.strict_checklist:
                errors.append(f"checklist {it['key']} ({it['issue'][:50]}) is still '{st}'; set Pass/Fail/Partial/N/A/Not Verified")
            elif conf_linked:
                st, derived = "FAIL", "Derived from the confirmed finding(s) linked to this control; the control was not otherwise reviewed."
            else:
                st, derived = "NOT ASSESSED", "No reviewer decision was recorded for this control."
                n_unassessed += 1
        if st == "PASS":
            if not (t.get("evidence") or "").strip():
                errors.append(f"checklist {it['key']} is PASS but has no evidence (state what you read, with file paths)")
            if conf_linked:
                errors.append(f"checklist {it['key']} is PASS but confirmed findings are linked: {', '.join(conf_linked)}")
        if st in ("FAIL", "PARTIAL") and not conf_linked:
            warnings.append(f"checklist {it['key']} is {st} with no confirmed finding linked")
        ev = (t.get("evidence") or "").strip() or derived
        if linked and st in ("FAIL", "PARTIAL"):
            ev = (ev + " " if ev else "") + "See " + ", ".join(linked) + "."
        checklist.append({**it, "status": st, "evidence": ev, "linked": linked})
    if n_unassessed:
        warnings.append(f"{n_unassessed} checklist item(s) were not assessed and are reported as NOT ASSESSED")
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

    def ver_label(v):
        if v["verdict"] == "not verified":
            return "Not re-checked by a second pass"
        who = v.get("verifier") or "unspecified"
        if v.get("independence") == "self":
            kind = "same assessor, second pass"
        else:
            kind = {"bound": "independence reported by the reviewer; response tied to the verification packet",
                    "stale": "independence reported by the reviewer; packet changed since the review",
                    "unbound": "independence reported by the reviewer; not tied to a verification packet"}[v.get("binding", "unbound")]
        if v.get("session"):
            who += f", {v['session']}"
        txt = {"agree": "Agreed", "disagree": "Disputed", "inconclusive": "Inconclusive"}[v["verdict"]] + f" ({kind}: {who})"
        if v.get("notes"):
            txt += ". " + v["notes"]
        if v.get("resolution"):
            txt += ". Assessor resolution: " + v["resolution"]
        return txt

    def sev_counts(fs):
        return {s: sum(1 for f in fs if f["severity"] == s) for s in SEV}

    comps = scan.get("components") or []
    rc_raw = (tri.get("meta") or {}).get("review_coverage") or tri.get("review_coverage") or {}
    def rc_status(name):
        v = rc_raw.get(name)
        st_ = (v.get("status") if isinstance(v, dict) else v) or "Not recorded"
        return st_, (v.get("notes", "") if isinstance(v, dict) else "")
    tot_lines = sum(c["lines"] for c in comps) or 1
    rev_c = [c for c in comps if rc_status(c["component"])[0].lower().startswith("reviewed")]
    part_c = [c for c in comps if rc_status(c["component"])[0].lower().startswith("partial")]
    if comps and rc_raw:
        review_line = (f"Manual code review coverage recorded by the assessor: {len(rev_c)} of {len(comps)} components reviewed in full "
                       f"({sum(c['lines'] for c in rev_c) * 100 // tot_lines}% of lines), {len(part_c)} partially, "
                       f"{len(comps) - len(rev_c) - len(part_c)} not reviewed or not recorded. Automated detection covered every scanned file; see Appendix A.2.")
        for c in comps:
            if (c["critical"] or c["high"]) and not rc_status(c["component"])[0].lower().startswith("reviewed"):
                warnings.append(f"component '{c['component']}' has {c['critical']} Critical / {c['high']} High candidate(s) but is not recorded as reviewed")
    elif comps:
        review_line = "Manual review coverage by component was not recorded; treat areas without a confirmed finding as scanned by pattern only, not as reviewed."
    else:
        review_line = ""
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
        ["Source revision", source_revision(meta, git)],
        ["Assessment type", "Static source-code security analysis (SAST, secrets, dependencies, IaC); no live testing"],
        ["Assessment date", now.strftime("%Y-%m-%d %H:%M %Z")],
        ["Prepared by", meta.get("assessor", "appsec-static-audit (automated scan with manual code review)")],
        ["Engagement", meta.get("engagement", "—")],
        ["Classification", "CONFIDENTIAL: security findings. Secret values are masked; do not distribute outside the engagement."],
    ]))
    w("\n## Table of Contents\n")
    for t in ["1. Executive Summary", "2. Scope and Methodology", "3. Findings Summary", "4. Security Control Checklist by Domain",
              "5. Detailed Findings", "6. Compliance Mapping", "7. Dependencies and Software Bill of Materials",
              "8. Remediation Roadmap", "Appendix A. Scan Coverage and Tooling", "Appendix B. Rejected and Consolidated Candidates"]:
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
    desc = meta.get("application_description") or ("a public-facing application that handles sensitive personal data" + (" (SSNs, financial records and potentially federal tax information)" if fti else ""))
    w(f"This report presents the results of a static security assessment of **{app}**, {desc}"
      + (". " if not desc.endswith(".") else " ") +
      f"{inv['files_scanned']:,} source and configuration files ({inv['lines']:,} lines) were analysed against 13 control domains covering the OWASP Top 10, access control, "
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

    if accepted:
        w(f"\n{len(accepted)} further candidate(s) are covered by accepted-risk or false-positive suppression entries and are not counted above (Section 3.3).")
    if crit_high:
        w(f"\nIndependent verification: {len(crit_high) - vstat['missing']} of {len(crit_high)} Critical/High findings were re-checked by a second pass "
          f"({vstat['agree']} agreed, {vstat['disagree']} disputed, {vstat['inconclusive']} inconclusive; {vstat['self_only']} by the same assessor rather than an independent reviewer; "
          f"{vstat['unbound'] + vstat['stale']} reported independent but not tied to a current verification packet, so independence rests on the reviewer's statement)."
          + (f" {vstat['missing']} were not re-checked." if vstat["missing"] else ""))
    w("\n### 1.4 Posture by Control Domain\n")
    rows = []
    for i, dk in enumerate(dom_order, 1):
        items = [c for c in checklist if c["domain"] == dk]
        cnt = lambda s: sum(1 for c in items if c["status"] == s)
        ds = [f for f in confirmed if f["domain"] == dk]
        worst = next((s for s in SEV if any(f["severity"] == s for f in ds)), "None")
        rows.append([f"4.{i}", dom_title[dk], len(items), cnt("PASS"), cnt("PARTIAL"), cnt("FAIL"), cnt("NOT VERIFIED") + cnt("N/A"), cnt("NOT ASSESSED"), len(ds), worst])
    w(table(["Section", "Domain", "Checks", "Pass", "Partial", "Fail", "N/A or Not verified", "Not assessed", "Findings", "Highest severity"], rows))

    w("\n### 1.5 Highest-Priority Issues\n")
    top = [f for f in confirmed if f["severity"] in ("Critical", "High")][:10]
    if top:
        w(table(["ID", "Severity", "Issue", "Location"], [[f["id"], f["severity"], f["title"], loc_str(f)] for f in top]))
    else:
        w("No Critical or High findings were confirmed.")

    w("\n### 1.6 Recommended Immediate Actions\n")
    acts = []
    if meta.get("immediate_actions"):
        acts = [f"{i}. {a_}" for i, a_ in enumerate(meta["immediate_actions"], 1)]
    else:
        for f in confirmed:
            if f["severity"] in ("Critical", "High") and len(acts) < 8:
                acts.append(f"{len(acts) + 1}. **{f['id']}** ({f['severity']}): {first_sentence(f['fix'])}")
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
    w("\n".join(f"- {x}" for x in scan["limitations"] + ([review_line] if review_line else [])) +
      "\n- Absence of a finding in a domain is not a guarantee of security. Source-only review cannot confirm controls enforced outside the repository.\n"
      "- Severity reflects code-level exploitability and data sensitivity; it should be re-rated with deployment context (network exposure, compensating controls).")

    if meta.get("architecture_md"):
        w("\n### 2.7 Architecture and Trust Boundaries Reviewed\n")
        w(meta["architecture_md"].strip() + "\n")
    if meta.get("positive_controls_md"):
        w("\n### 2.8 Positive Controls Observed\n")
        w(meta["positive_controls_md"].strip() + "\n")

    # ================= 3 SUMMARY
    w("\n---\n\n## 3. Findings Summary\n")
    w("### 3.1 Findings by Domain and Severity\n")
    if unconfirmed:
        w(f"This table counts the {len(confirmed)} confirmed finding(s) and {len(unconfirmed)} unconfirmed candidate(s). Section 1.3 separates them.\n")
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
    if accepted:
        w("\n### 3.3 Accepted Risks and Suppressions\n")
        w("These candidates match a suppression policy entry. They are **not** counted as findings, but the risk remains until it is fixed or the entry expires; review them at the stated expiry.\n")
        w(table(["ID", "Severity", "Issue", "Location", "Reason, owner and expiry"], [[f["id"], f["severity"], f["title"], loc_str(f), r_] for f, r_ in accepted]))
    ch = scan.get("changes")
    if ch:
        w("\n### 3.4 Changes Since the Previous Scan\n")
        gone = ch.get("no_longer_detected", [])
        w(f"Compared with the scan of {ch.get('previous_scanned_at', 'an earlier run')}" + (f" (commit {ch['previous_commit']})" if ch.get("previous_commit") else "") +
          f": **{sum(1 for f in findings if f.get('delta') == 'new')}** current finding(s) are new, **{sum(1 for f in findings if f.get('delta') == 'existing')}** were already present, and **{len(gone)}** earlier candidate(s) are no longer detected. "
          "*No longer detected* means the pattern no longer matches; the code may be fixed, moved, excluded or suppressed, so confirm before closing it.\n")
        newf = [f for f in findings if f.get("delta") == "new"]
        if newf:
            w("**New since the previous scan**\n")
            w(table(["ID", "Severity", "Issue", "Location"], [[f["id"], f["severity"], f["title"], loc_str(f)] for f in newf[:40]]) + (f"\n\n…and {len(newf) - 40} more." if len(newf) > 40 else ""))
        if gone:
            w("\n**No longer detected**\n")
            w(table(["Previous ID", "Severity", "Issue", "File"], [[g["id"], g["severity"], g["title"], f"`{g['file']}`"] for g in gone[:40]]) + (f"\n\n…and {len(gone) - 40} more." if len(gone) > 40 else ""))

    if prev:
        w("\n### 3.5 Comparison with the Previous Review\n")
        w(f"The previous review (scan of {prev['at'] or 'unknown date'}) confirmed **{prev['total']}** finding(s). In this review **{len(prev['carried'])}** are confirmed again"
          + (f" and **{len(prev['dropped'])}** are not. " if prev["dropped"] else ". ")
          + ("A finding that is not confirmed here may have been fixed, may have been judged a false positive on a second reading, or may simply not have been re-reviewed; "
             "the *Status now* column says which. Confirm each one before closing it.\n" if prev["dropped"] else "Nothing confirmed earlier has been dropped.\n"))
        if prev["dropped"]:
            w(table(["Previous ID", "Severity", "Previously confirmed finding", "Location", "Status now"],
                    [[p["id"] or "manual", p["severity"], p["title"], f"`{p['file']}:{p['line']}`", why] for p, why in sorted(prev["dropped"], key=lambda x: SEV.index(x[0]["severity"]) if x[0]["severity"] in SEV else 9)]))

    # ================= 4 CHECKLIST
    w("\n---\n\n## 4. Security Control Checklist by Domain\n")
    w("Status values are defined in Section 2.5. *Evidence* states what was examined or which finding applies.\n")
    for i, dk in enumerate(dom_order, 1):
        items = [c for c in checklist if c["domain"] == dk]
        w(f"### 4.{i} {dom_title[dk]}\n")
        w(dom_intro[dk] + "\n")
        w(table(["No.", "Control / Issue", "Status", "Evidence"], [[c["number"], c["issue"], f"**{c['status']}**", c["evidence"]] for c in items]))
        ds = [f for f in findings if f["domain"] == dk]
        own = {f["id"] for f in ds}
        refd = sorted({x for c in items for x in c["linked"]} - own)
        w("\n**Findings in this domain:** " + (", ".join(f"{f['id']} ({f['severity']})" for f in ds) if ds else "none") +
          ("; **also referenced by these checks:** " + ", ".join(refd) if refd else "") + "\n")
        if dk == "api" and scan.get("routes"):
            rts = scan["routes"]
            cnt = {}
            for r_ in rts:
                cnt[r_["auth"]] = cnt.get(r_["auth"], 0) + 1
            w(f"**Route inventory ({len(rts)} route registrations found statically).** " + ", ".join(f"{k}: {v}" for k, v in sorted(cnt.items())) +
              ". 'none seen' means no authentication marker near the route; it may be enforced by a gateway or base class. The full list is in `scan.json`.\n")
            show = [r_ for r_ in rts if r_["auth"] == "none seen"][:40]
            if show:
                w(table(["Method", "Path", "Framework", "Location", "Authentication"], [[r_["method"], f"`{r_['path']}`", r_["framework"], f"`{r_['file']}:{r_['line']}`", r_["auth"]] for r_ in show]))
                w("")

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
            ["Location", ", ".join(f"`{l.get('file', f['file'])}:{l['line']}`" for l in (f.get("locations") or [dict(line=f['line'])])[:12])],
            ["Weakness (CWE)", f.get("cwe") or "—"], ["OWASP Top 10 (2021)", f.get("owasp") or "—"],
            ["Confidence", f.get("confidence", "—")], ["Detected by", f.get("source", "scanner") + (f" rule {f['rule']}" if f["rule"] != "MANUAL" else " (manual review)")],
            ["Status", f.get("status", "Open")]]
            + ([["Since previous scan", "New" if f.get("delta") == "new" else "Already present"]] if f.get("delta") else [])
            + ([["Independent verification", ver_label(f["verification"])]] if f.get("verification") else [])))
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
            w("```text\n" + "\n".join(f"{l.get('file', f['file'])}:{l['line']}: {redact_line(l['snippet'])}" for l in snips[:12]) + "\n```\n")
        w(f"**Recommendation.** {f['fix']}\n")
        if (f.get("patch") or "").strip():
            w("**Suggested patch** (review and test before applying; not applied by this tool)\n")
            w("```diff\n" + f["patch"].strip("\n") + "\n```\n")
        w("**Compliance mapping.** NIST 800-53: " + ", ".join(c for c, _ in nist[:6]) + ". IRS Pub 1075: " + ", ".join(c for c, _ in irs[:4]) +
          ". EOTSS: " + "; ".join(eotss_label(e) for e in eot[:3]) + ".\n")

    # ================= 6 COMPLIANCE
    w("\n---\n\n## 6. Compliance Mapping\n")
    w("Each finding inherits the controls mapped to its domain (`references/compliance-map.json`) plus any control added during review. "
      "Confirm section numbers against the revisions the customer is audited against; framework revisions were not verified offline and this mapping is not an applicability determination or compliance attestation. IRS Pub 1075 Section 9.3 follows NIST 800-53 families."
      + (" FTI-specific requirements (FIPS 140-validated encryption in transit and at rest, audit of every FTI access, MFA for remote/privileged access, disposal) drive the severity of findings in the "
         "access, crypto, data, logging and iac domains.\n" if fti else " FTI handling was not established for this engagement and did not raise any severity rating.\n"))
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
        w(table(["Ecosystem", "Components", "Version-pinned", "From lockfile", "Direct", "Transitive", "Dev-only"],
                [[k, v["total"], v["pinned"], v.get("from_lockfile", 0), v.get("direct", 0), v.get("transitive", 0), v["dev"]] for k, v in sorted(deps["ecosystems"].items())]))
    else:
        w("No dependency manifests were found.")
    w(f"\nA CycloneDX 1.5 SBOM with {deps['total']} components was generated: `{deps['sbom']}` (deliver alongside this report).\n")
    w("### 7.2 Vulnerable, Unmaintained and Unpinned Dependencies\n")
    dd = [f for f in findings if f["domain"] == "deps"]
    w(table(["ID", "Severity", "Issue", "Detail", "Manifest"], [[f["id"], f["severity"], f["title"], f.get("detail", ""), f"`{f['file']}`"] for f in dd]) if dd else "None identified.")
    if meta.get("dependency_notes_md"):
        w("\n### 7.3 Additional Dependency and Image Notes\n")
        w(meta["dependency_notes_md"].strip() + "\n")
    dbi = deps.get("advisory_db") or {}
    if dbi.get("available"):
        age = dbi.get("age_days")
        stale = age is not None and age > 90
        w(f"\n*Coverage note:* vulnerability matching used the bundled OSV advisory snapshot dated **{dbi.get('generated', 'unknown')}**"
          + (f" ({age} days old{'; **older than 90 days, refresh before relying on this section**' if stale else ''})" if age is not None else "")
          + f", {dbi.get('advisories', 0):,} package advisories, exact-version matching only"
          + ("; results from a connected scan (`--osv-results`) were merged" if deps.get("imported_osv") else "; no connected scan was imported")
          + (f". {deps['unresolved']} declared dependenc{'y' if deps['unresolved'] == 1 else 'ies'} had no exact version and were not matched." if deps.get("unresolved") else ".")
          + " Run a connected OSV/NVD scan before release to cover advisories published after the snapshot.")
    else:
        w("\n*Coverage note:* **the advisory snapshot was unavailable, so CVE matching fell back to a small curated list and coverage is PARTIAL.** Run a connected OSV/NVD scan and import it with `--osv-results`.")

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
    run = scan["meta"].get("run") or {}
    opts = run.get("options") or {}
    dbi_ = (scan.get("dependencies") or {}).get("advisory_db") or {}
    rows_a = [
        ["Scanner", f"{scan['meta']['tool']} {scan['meta']['version']} (offline; no network calls)"],
        ["Scanner build fingerprint", f"`{run['scanner_sha256'][:16]}` (SHA-256 of scripts and reference data; identical value = identical rules)" if run.get("scanner_sha256") else "not recorded"],
        ["Repository revision" if not meta.get("repositories") else "Repository revisions", repository_revisions(meta, git)],
        ["Scan time", f"{scan['meta']['scanned_at']} ({scan['meta'].get('duration_s', '?')}s" + (f", {run['jobs']} worker processes" if run.get("jobs", 1) > 1 else "") + ")"],
        ["Files analysed", f"{inv['files_scanned']:,} ({inv['lines']:,} lines) in {len(comps)} component(s)"],
        ["Excluded paths", ", ".join(f"`{x}`" for x in opts.get("excludes", [])) or "none"],
        ["Git history", f"{h['commits_scanned']} commits scanned, {h['hits']} secret hit(s)" if h.get("ran") else h.get("note", "not scanned")],
        ["Detection rules", f"{len(R.RULES)} line rules, {len(R.PRESENCE)} control-presence checks; intra-file data-flow tracking ({inv.get('flow_candidates', 0)} flow candidate(s))"],
        ["Advisory snapshot", (f"{dbi_.get('generated', '?')} ({dbi_.get('advisories', 0):,} advisories; SHA-256 `{run.get('advisory_db_sha256', '')[:16]}`)" if dbi_.get("available") else "unavailable")],
        ["Imported results", f"{scan.get('sarif_imported', 0)} SARIF result(s)" + ("; OSV scan merged" if (scan.get("dependencies") or {}).get("imported_osv") else "")],
        ["Suppression policy", f"{scan.get('suppression', {}).get('applied', 0)} applied, {scan.get('suppression', {}).get('expired', 0)} expired" if scan.get("suppression", {}).get("files") else "none"],
        ["Candidates raised / confirmed / rejected / accepted risk / unconfirmed", f"{len(scan['findings'])} / {len(confirmed) - n_manual} / {len(rejected)} / {len(accepted)} / {len(unconfirmed)}"],
        ["Candidates dispositioned individually / by bulk rule / by suppression policy", f"{via_counts['explicit']} / {via_counts['bulk']} / {via_counts['suppression']}"],
        ["Manually added findings", str(n_manual)]]
    if prev:
        rows_a.append(["Compared with previous review", f"{prev['total']} previously confirmed: {len(prev['carried'])} confirmed again, {len(prev['dropped'])} not (Section 3.5)"])
    w(table(["Item", "Detail"], rows_a))
    if comps:
        w("\n### A.2 Coverage by Component\n")
        w("Components are the top-level folders (or `packages/*`, `services/*`, `apps/*` style folders in a monorepo), ordered by review priority: Critical and High candidates first. "
          "*Review status* is what the assessor recorded after reading the code; automated detection covered every scanned file regardless.\n")
        shown = [c for c in comps if c["critical"] or c["high"] or c["medium"]][:40] or comps[:40]
        w(table(["Component", "Files", "Lines", "Candidates", "Critical", "High", "Medium", "Low/Info", "Manual review"],
                [[f"`{c['component']}`", f"{c['files']:,}", f"{c['lines']:,}", c["candidates"], c["critical"], c["high"], c["medium"], c["low"],
                  rc_status(c["component"])[0] + (f": {rc_status(c['component'])[1]}" if rc_status(c["component"])[1] else "")] for c in shown]))
        rest = len(comps) - len(shown)
        if rest > 0:
            w(f"\n…and {rest} more component(s) with no Critical, High or Medium candidates (full list in `scan.json`).")
    w("\n## Appendix B. Rejected and Consolidated Candidates\n")
    if rejected:
        n_c = sum(1 for _f, _r, d_ in rejected if d_ == "consolidated")
        w(f"{len(rejected)} candidate(s) were not carried into Section 5: {len(rejected) - n_c} incorrect or inapplicable pattern match(es) and {n_c} valid observation(s) consolidated into another finding. "
          "A consolidation is not a claim that the weakness is absent.\n")
    notes_b = []
    if ch_bulk:
        notes_b.append(f"{len(ch_bulk)} of {len(ch_log)} Critical/High candidates were dispositioned by bulk rules, not individually "
                       f"({ch_bulk_kinds['needs_review']} left unconfirmed, {ch_bulk_kinds['consolidated']} consolidated, {ch_bulk_kinds['false_positive']} rejected as false positives); "
                       "each bulk rule carries one shared reason, so spot-check them before relying on these rejections")
    if consolidated_into_unconfirmed:
        notes_b.append(f"{len(consolidated_into_unconfirmed)} candidates were consolidated into findings that are themselves unconfirmed; a consolidation groups leads, it does not confirm them")
    if notes_b:
        w("\n**Review note.** " + ". ".join(notes_b) + ".\n")
    if shared_reasons:
        w("\n**Review note.** " + "; ".join(f"{n_} candidates share the identical recorded reason \"{k[:80]}…\"" for _f, n_, k in shared_reasons) +
          ". Identical wording is acceptable for a deliberate bulk rule, but confirm each candidate was read individually before relying on these rejections.\n")
    w(table(["ID", "Rule", "Location", "Reason"], [[f["id"], f["rule"], f"`{f['file']}:{f['line']}`", r_] for f, r_, _d in rejected]) if rejected else "None.")

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
    print(f"Overall risk: {rating}; confirmed {len(confirmed)}, unconfirmed {len(unconfirmed)}, rejected {len(rejected)}, accepted risk {len(accepted)}")
    if a.emit_sarif:
        sp = os.path.join(out_dir, f"security-audit_{stamp}.sarif")
        with open(sp, "w", encoding="utf-8") as fh:
            json.dump(build_sarif(scan, findings, rejected, accepted), fh, indent=1)
        print(f"SARIF written: {sp}")
    if a.fail_on:
        limit = SEV.index(a.fail_on)
        bad = [f for f in (confirmed + (unconfirmed if a.fail_on_unconfirmed else [])) if SEV.index(f["severity"]) <= limit]
        if bad:
            print(f"CI gate FAILED: {len(bad)} finding(s) at or above {a.fail_on}: " + ", ".join(f["id"] for f in bad[:12]) + ("..." if len(bad) > 12 else ""), file=sys.stderr)
            sys.exit(10)
        print(f"CI gate passed: no confirmed finding at or above {a.fail_on}.")


if __name__ == "__main__":
    main()
