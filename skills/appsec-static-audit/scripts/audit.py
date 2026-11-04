#!/usr/bin/env python3
"""appsec-static-audit scanner.

Static, offline analysis of a source tree. Reads files and local git history only; makes NO network
calls and never contacts the application under review. Writes:
  <out>/scan.json         candidate findings, checklist pre-fill, inventory, limitations
  <out>/sbom.cdx.json     CycloneDX 1.5 SBOM built from dependency manifests / lockfiles

Every candidate must be confirmed or rejected by reading the code (see SKILL.md), then
render_report.py builds the Markdown report.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deps as depmod  # noqa: E402
import rules as R  # noqa: E402

VERSION = "1.0.0"
SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "env", "dist", "build", "target", "out", "__pycache__", ".tox",
             ".mypy_cache", ".idea", ".vscode", "bower_components", "site-packages", ".gradle", ".terraform", "coverage",
             ".next", ".nuxt", ".pytest_cache", ".cache", "bin", "obj", "packages"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".7z", ".rar",
              ".jar", ".war", ".ear", ".class", ".dll", ".exe", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3",
              ".mp4", ".mov", ".avi", ".wav", ".pyc", ".pyo", ".o", ".a", ".bin", ".onnx", ".pt", ".pth", ".parquet", ".map"}
LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock",
              "go.sum", "npm-shrinkwrap.json", "uv.lock", "pdm.lock"}
TEST_RX = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|testdata|e2e|cypress)(/|$)|\.(test|spec)\.[a-z]+$|(^|/)test_[^/]+$|_test\.(go|py)$", re.I)
EXAMPLE_RX = re.compile(r"\.(example|sample|template|dist)$|(^|/)(example|sample)s?[-_.]", re.I)
SENSITIVE_FILES = [
    (re.compile(r"(^|/)\.env(\.[\w-]+)?$", re.I), "Environment file"),
    (re.compile(r"\.(pem|key|p12|pfx|jks|keystore|ppk)$", re.I), "Key / certificate store"),
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$"), "SSH private key"),
    (re.compile(r"(^|/)(\.htpasswd|\.netrc|\.pypirc|credentials(\.json)?|secrets?\.(ya?ml|json)|\.git-credentials)$", re.I), "Credential file"),
    (re.compile(r"(^|/)terraform\.tfstate(\.backup)?$|\.tfstate$"), "Terraform state (contains secrets in plaintext)"),
]
DATA_FILES = re.compile(r"\.(dump|bak|sqlite3?|db|mdb|bacpac|backup)$", re.I)
EXTRA_SECRET = [("npm auth token", re.compile(r"_authToken\s*=\s*(?!\$\{)[A-Za-z0-9\-_.]{10,}"), "High")]
UNQUOTED_SECRET = re.compile(r"(?i)^\s*[\w.-]*(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)[\w.-]*\s*[=:]\s*([^\s\"'#$<{\[][^\s#]{5,})\s*$")
FRAMEWORKS = {
    "Flask": r"\bfrom flask import|\bimport flask\b|Flask\(", "Django": r"\bdjango\b", "FastAPI": r"\bfastapi\b",
    "Express": r"\bexpress\(\)|require\(['\"]express['\"]\)|from ['\"]express['\"]", "Spring": r"org\.springframework|@SpringBootApplication",
    "ASP.NET": r"Microsoft\.AspNetCore|System\.Web\.Mvc", "Rails": r"Rails\.application|ActionController", "Laravel": r"Illuminate\\|laravel/framework",
    "React": r"from ['\"]react['\"]|require\(['\"]react['\"]\)", "Angular": r"@angular/core", "Vue": r"from ['\"]vue['\"]",
    "Terraform": r"^\s*(resource|provider)\s+\"", "Kubernetes": r"^\s*apiVersion:.*\n\s*kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|Service|Ingress)",
    "SAML": r"SAMLResponse|passport-saml|python3-saml|pysaml2|Saml2", "OIDC/OAuth": r"openid|oidc|oauth2?|authlib|passport-oauth",
}


def tags_for(rel):
    name = os.path.basename(rel)
    low = name.lower()
    ext = os.path.splitext(low)[1]
    t = set()
    if ext == ".py":
        t.add("py")
    if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"):
        t.add("js")
    if ext in (".java", ".kt", ".scala", ".groovy"):
        t.add("java")
    if ext in (".cs", ".cshtml", ".razor", ".vb"):
        t.add("cs")
    if ext in (".php", ".phtml"):
        t.add("php")
    if ext == ".go":
        t.add("go")
    if ext in (".rb", ".erb", ".rake"):
        t.add("rb")
    if ext in (".tf", ".tfvars", ".hcl"):
        t.add("tf")
    if ext in (".yml", ".yaml", ".json", ".template"):
        t.add("yaml")
    if low.startswith("dockerfile") or low.endswith(".dockerfile"):
        t.add("docker")
    if low.startswith("docker-compose") or low.startswith("compose."):
        t.update({"docker", "yaml"})
    if ext in (".xml", ".config", ".properties", ".ini", ".cfg", ".toml", ".conf", ".gradle", ".htaccess") or low in (".htaccess", "nginx.conf"):
        t.add("conf")
    if ext in (".html", ".htm", ".ejs", ".hbs", ".jinja", ".j2", ".twig", ".vue", ".cshtml", ".erb", ".razor", ".jsp", ".phtml"):
        t.add("html")
    if ext in (".sh", ".bash", ".ps1", ".bat"):
        t.add("sh")
    if ext == ".sql":
        t.add("sql")
    if low == ".env" or low.startswith(".env.") or ext == ".env":
        t.update({"env", "conf"})
    if ext in (".md", ".markdown", ".rst", ".txt"):
        t.add("md")
    return t


def sev_down(s):
    i = R.SEV.index(s)
    return R.SEV[min(i + 1, len(R.SEV) - 1)]


def mask(v):
    return v[:2] + "****" if len(v) >= 8 else "****"


def redact_line(line, force=False):
    s = line.strip()
    for _, rx, _ in R.SECRET_PATTERNS:
        s = rx.sub(lambda m: mask(m.group(0)), s)
    s = re.sub(r"(://[^/\s:@\"']+:)[^/\s:@\"']+(@)", r"\1****\2", s)
    s = R.GENERIC_SECRET.sub(lambda m: m.group(0).replace(m.group(3), mask(m.group(3))), s)
    s = R.SSN_RX.sub(lambda m: "***-**-" + m.group(0)[-4:], s)
    m = UNQUOTED_SECRET.match(s)
    if m and not R.PLACEHOLDER.search(m.group(2)):
        s = s.replace(m.group(2), mask(m.group(2)))
    if force:
        s = re.sub(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\w*\s*[=:]\s*)([^\s\"'#$<{\[]{6,})",
                   lambda m: m.group(1) + mask(m.group(2)), s)
        s = re.sub(r"([\"'])[^\"'\s]{6,}\1", lambda m: m.group(1) + mask(m.group(0)[1:-1]) + m.group(1), s)
    return s[:220] + ("…" if len(s) > 220 else "")


def is_comment(line):
    s = line.lstrip()
    return s.startswith(("#", "//", "/*", "*", "--", "<!--", ";"))


def walk(root, max_kb):
    skipped_large = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for f in fn:
            ap = os.path.join(dp, f)
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            if os.path.splitext(f.lower())[1] in BINARY_EXT:
                continue
            try:
                size = os.path.getsize(ap)
            except OSError:
                continue
            if size > max_kb * 1024:
                skipped_large.append(rel)
                continue
            yield ap, rel, size
    walk.skipped_large = skipped_large


def read_text(ap):
    try:
        with open(ap, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def lineno(text, pos):
    return text.count("\n", 0, pos) + 1


class Collector:
    def __init__(self):
        self.groups = {}      # (rule, file) -> candidate
        self.rule_files = {}  # rule -> set(files)

    def add(self, meta, file, line, snippet, ctx, extra_title=None, detail=None, source="scanner"):
        key = (meta["id"], file)
        c = self.groups.get(key)
        if c is None:
            sev = meta["severity"]
            note = ""
            if ctx == "test" and meta["id"] != "MISC-PROMPT-1":
                sev = sev_down(sev)
                note = " (located in test/fixture code; severity reduced one level, confirm no production reuse)"
            c = dict(rule=meta["id"], domain=meta["domain"], severity=sev, cwe=meta.get("cwe", ""), owasp=meta.get("owasp", ""),
                     title=extra_title or meta["title"], file=file, line=line, locations=[], detail=(detail or "") + note,
                     fix=meta["fix"], confidence=meta.get("confidence", "Medium"), context=ctx, source=source)
            self.groups[key] = c
            self.rule_files.setdefault(meta["id"], set()).add(file)
        if len(c["locations"]) < 8 and not any(loc["line"] == line for loc in c["locations"]):
            c["locations"].append(dict(line=line, snippet=snippet))
        c["line"] = min(c["line"], line)

    def add_raw(self, d):
        key = (d["rule"], d["file"], d["title"])
        d.setdefault("locations", [dict(line=d.get("line", 1), snippet=(d.get("detail") or d["title"])[:200])])
        d.setdefault("context", "source")
        d.setdefault("source", "scanner")
        d.setdefault("owasp", "")
        self.groups[key] = d


def scan_tree(root, max_kb, col):
    meta_by_id = {r["id"]: r for r in R.RULES}
    pres_state = {p["id"]: dict(when=None, found=False) for p in R.PRESENCE}
    inv = dict(files=0, by_lang={}, manifests=[], iac=[], frameworks=set(), skipped_binary=0, loc=0)
    manifest_files, secret_hashes = [], set()
    fw_rx = {k: re.compile(v, re.M | re.I) for k, v in FRAMEWORKS.items()}
    texts_for_deps = []
    for ap, rel, size in walk(root, max_kb):
        base = os.path.basename(rel)
        ctx = "test" if TEST_RX.search(rel) else "source"
        if base in LOCK_NAMES or base.endswith((".min.js", ".min.css")):
            manifest_files.append((ap, rel))
            continue
        text = read_text(ap)
        if text is None:
            inv["skipped_binary"] += 1
            continue
        tags = tags_for(rel)
        inv["files"] += 1
        inv["loc"] += text.count("\n") + 1
        for t in tags:
            inv["by_lang"][t] = inv["by_lang"].get(t, 0) + 1
        if re.fullmatch(r"(package\.json|requirements[\w.\-]*\.txt|pom\.xml|go\.mod|.*\.csproj|packages\.config|.*\.gradle(\.kts)?|Pipfile|composer\.json)", base):
            inv["manifests"].append(rel)
            manifest_files.append((ap, rel))
        if tags & {"tf"} or "docker" in tags or (("yaml" in tags) and re.search(r"AWSTemplateFormatVersion|apiVersion:\s*\S+\s*\n\s*kind:", text)):
            inv["iac"].append(rel)
        for name, rx in fw_rx.items():
            if name not in inv["frameworks"] and "md" not in tags and rx.search(text):
                inv["frameworks"].add(name)

        # ---- file-level rules
        for rx, label in SENSITIVE_FILES:
            if rx.search(rel) and not EXAMPLE_RX.search(rel):
                col.add(meta_by_id["SEC-FILE-1"], rel, 1, f"{label}: {base}", ctx, extra_title=f"Sensitive file committed: {base} ({label})")
        if DATA_FILES.search(rel):
            col.add(meta_by_id["SEC-FILE-2"], rel, 1, f"Data file: {base}", ctx, extra_title=f"Database dump / data file committed: {base}")

        if "md" in tags and len(tags) == 1:
            scan_prompt_only(rel, text, ctx, meta_by_id, col)
            continue

        # ---- presence bookkeeping (repo + file scope)
        if ctx == "source":
            for p in R.PRESENCE:
                st = pres_state[p["id"]]
                if p["scope"] == "repo":
                    if not st["found"] and p["expect"].search(text):
                        st["found"] = True
                    if st["when"] is None and (tags & p["langs"]):
                        m = p["when"].search(text)
                        if m:
                            st["when"] = (rel, lineno(text, m.start()), redact_line(text.splitlines()[lineno(text, m.start()) - 1]))
                elif tags & p["langs"]:
                    m = p["when"].search(text)
                    if m and not p["expect"].search(text):
                        ln = lineno(text, m.start())
                        col.add_raw(dict(rule=p["id"], domain=p["domain"], severity=p["severity"], cwe=p["cwe"], owasp=p["owasp"],
                                         title=p["title"], file=rel, line=ln, fix=p["fix"], confidence=p["confidence"],
                                         detail="Control not evidenced in this file; it may be enforced elsewhere (gateway, base class, middleware). Confirm by reading the code.",
                                         locations=[dict(line=ln, snippet=redact_line(text.splitlines()[ln - 1]))]))

        # ---- line rules
        applicable = [r for r in R.RULES if r["id"] not in ("SEC-FILE-1", "SEC-FILE-2", "DATA-4") and (r["langs"] & tags or "any" in r["langs"])]
        generic_ok = "md" not in tags
        for i, line in enumerate(text.split("\n"), 1):
            if len(line) > 2000 or not line.strip():
                continue
            commented = is_comment(line)
            if generic_ok:
                hit_secret = secret_scan(line)
                if hit_secret:
                    name, val, sev = hit_secret
                    m = dict(id="SEC-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-")[:28], domain="secrets", severity=sev,
                             cwe="CWE-798", owasp="A02", title=f"Hardcoded secret: {name}",
                             fix="Remove from source, rotate the credential now (it is exposed to everyone with repo access), load from a secrets manager or environment, and add pre-commit secret scanning.",
                             confidence="High" if "key" in name.lower() or "token" in name.lower() else "Medium")
                    if EXAMPLE_RX.search(rel):
                        m["severity"] = "Low"
                    col.add(m, rel, i, redact_line(line), ctx)
                    secret_hashes.add(hashlib.sha1(val.encode()).hexdigest())
                if R.SSN_RX.search(line) and "sql" not in tags and not re.search(r"(?i)(isbn|phone|fax|tel|version|uuid|guid)", line):
                    sev = "High" if ctx == "source" else "Medium"
                    col.add(dict(id="DATA-4", domain="data", severity=sev, cwe="CWE-359", owasp="",
                                 title="Literal SSN-shaped value in source or fixtures",
                                 fix=meta_by_id["DATA-4"]["fix"], confidence="Medium"), rel, i, redact_line(line), ctx)
            for r in applicable:
                if commented and r["id"] != "MISC-PROMPT-1":
                    continue
                if r["only_files"] and not r["only_files"].search(rel):
                    continue
                if r["rx"].search(line):
                    if r["id"] == "SSO-OIDC-2" and not re.search(r"(?i)(admin|role|permission|isAdmin|=)", line):
                        continue
                    col.add(r, rel, i, redact_line(line, force=r["redact"]), ctx)
    # repo-scope presence findings
    for p in R.PRESENCE:
        st = pres_state[p["id"]]
        if p["scope"] == "repo" and st["when"] and not st["found"]:
            f, ln, snip = st["when"]
            col.add_raw(dict(rule=p["id"], domain=p["domain"], severity=p["severity"], cwe=p["cwe"], owasp=p["owasp"], title=p["title"],
                             file=f, line=ln, fix=p["fix"], confidence=p["confidence"],
                             detail="Relevant code exists but no matching control was found anywhere in the repository (absence of evidence, not proof). It may be delegated to the IdP, gateway or platform; confirm and document where.",
                             locations=[dict(line=ln, snippet=snip)]))
    inv["frameworks"] = sorted(inv["frameworks"])
    return inv, manifest_files, secret_hashes


def scan_prompt_only(rel, text, ctx, meta_by_id, col):
    m = meta_by_id["MISC-PROMPT-1"]
    for i, line in enumerate(text.split("\n"), 1):
        if m["rx"].search(line):
            col.add(m, rel, i, redact_line(line), ctx)


def secret_scan(line):
    for name, rx, sev in R.SECRET_PATTERNS + EXTRA_SECRET:
        m = rx.search(line)
        if m:
            val = m.group(0)
            if name.startswith("Credentials in connection") and R.PLACEHOLDER.search(val):
                continue
            return name, val, sev
    m = R.GENERIC_SECRET.search(line)
    if m:
        val = m.group(3)
        if not R.PLACEHOLDER.search(val) and not re.search(r"(?i)(process\.env|os\.environ|getenv|System\.getenv|config\.get|settings\.)", line):
            return "Hardcoded credential literal", val, "High"
    m = UNQUOTED_SECRET.match(line)
    if m and not R.PLACEHOLDER.search(m.group(2)):
        return "Hardcoded credential literal (config)", m.group(2), "High"
    return None


# --------------------------------------------------------------------------- git history
def git_root(root):
    try:
        out = subprocess.run(["git", "-C", root, "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=20)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def git_meta(root):
    def g(*a):
        try:
            r = subprocess.run(["git", "-C", root] + list(a), capture_output=True, text=True, timeout=20)
            return r.stdout.strip() if r.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""
    return dict(commit=g("rev-parse", "--short", "HEAD"), branch=g("rev-parse", "--abbrev-ref", "HEAD"),
                remote=re.sub(r"//[^/@]*@", "//", g("config", "--get", "remote.origin.url")), commits=g("rev-list", "--count", "--all"))


def scan_history(root, max_commits, working_hashes, col, timeout=600):
    """Scan ADDED lines in all local history for secrets. Uses only the local object database."""
    res = dict(ran=False, commits_scanned=0, hits=0, note="")
    if not git_root(root):
        res["note"] = "Not a git repository (or git not installed): history was not scanned."
        return res
    cmd = ["git", "-C", root, "log", "--all", f"--max-count={max_commits}", "-p", "-U0", "--no-color", "--diff-filter=AMR",
           "--pretty=format:@@COMMIT %h %aI"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    except OSError:
        res["note"] = "git could not be executed."
        return res
    res["ran"] = True
    start = time.time()
    commit = date = fil = None
    seen = {}
    for line in proc.stdout:
        if time.time() - start > timeout:
            proc.kill()
            res["note"] = f"History scan stopped after {timeout}s; results are partial."
            break
        if line.startswith("@@COMMIT "):
            _, commit, date = line.strip().split(" ", 2)
            res["commits_scanned"] += 1
            continue
        if line.startswith("+++ b/"):
            fil = line[6:].strip()
            continue
        if not line.startswith("+") or line.startswith("+++") or not fil:
            continue
        base = os.path.basename(fil)
        if base in LOCK_NAMES or base.endswith(".min.js") or os.path.splitext(base.lower())[1] in BINARY_EXT or len(line) > 2000:
            continue
        hit = secret_scan(line[1:])
        if not hit:
            continue
        name, val, sev = hit
        h = hashlib.sha1(val.encode()).hexdigest()
        key = (fil, h)
        if key in seen:
            seen[key]["occurrences"] += 1
            seen[key]["first_commit"], seen[key]["first_date"] = commit, date
            continue
        seen[key] = dict(file=fil, name=name, severity=sev, last_commit=commit, last_date=date, first_commit=commit, first_date=date,
                         snippet=redact_line(line[1:]), occurrences=1, in_tree=h in working_hashes)
    proc.wait()
    res["hits"] = len(seen)
    for (fil, _), s in list(seen.items())[:60]:
        where = "still present in the working tree" if s["in_tree"] else "no longer in the working tree but remains in git history"
        meta = dict(id="SEC-HIST-1", domain="secrets", severity=s["severity"], cwe="CWE-798", owasp="A02",
                    title=f"Secret in git history: {s['name']}", fix="Treat as compromised: rotate/revoke now, then purge history (git filter-repo / BFG) and force-push, and invalidate clones. Add pre-commit and CI secret scanning.",
                    confidence="High")
        col.add(meta, fil, 1, s["snippet"], "source",
                detail=f"Introduced in commit {s['first_commit']} ({s['first_date'][:10]}); {where}; {s['occurrences']} occurrence(s) across history.")
    return res


# --------------------------------------------------------------------------- SARIF import
def import_sarif(path, col):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    n = 0
    for run in data.get("runs", []):
        tool = (run.get("tool", {}).get("driver", {}) or {}).get("name", "sarif")
        rules = {r.get("id"): r for r in (run.get("tool", {}).get("driver", {}) or {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "sarif")
            rule = rules.get(rid, {})
            props = rule.get("properties", {}) or {}
            sec = props.get("security-severity")
            lvl = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level", "warning")
            try:
                s = float(sec)
                sev = "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"
            except (TypeError, ValueError):
                sev = {"error": "High", "warning": "Medium", "note": "Low"}.get(lvl, "Medium")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            f = (loc.get("artifactLocation") or {}).get("uri", "unknown").replace("file://", "")
            ln = (loc.get("region") or {}).get("startLine", 1)
            text = (res.get("message") or {}).get("text", rid)
            hay = (rid + " " + " ".join(props.get("tags", []) if isinstance(props.get("tags"), list) else [])).lower()
            dom = ("secrets" if re.search(r"secret|credential|password|api.?key|token", hay) else
                   "sso" if re.search(r"jwt|saml|oidc|oauth", hay) else
                   "session" if re.search(r"cookie|session", hay) else
                   "crypto" if re.search(r"crypto|hash|cipher|tls|ssl|random", hay) else
                   "iac" if re.search(r"docker|kube|terraform|s3|iam|security.?group|cors|header|cloudformation", hay) else
                   "logging" if "log" in hay else "access" if re.search(r"authz|access.?control|idor", hay) else "owasp")
            cwe = next((t.split(":")[0].upper() for t in props.get("tags", []) if isinstance(t, str) and t.lower().startswith("cwe-")), "")
            col.add_raw(dict(rule=f"SARIF:{rid}", domain=dom, severity=sev, cwe=cwe, title=text[:140], file=f, line=ln,
                             fix=(rule.get("help") or {}).get("text", "See the originating tool's guidance for this rule.")[:400],
                             confidence="Medium", source=f"sarif:{tool}", detail=f"Imported from {tool} rule {rid}.",
                             locations=[dict(line=ln, snippet=text[:200])]))
            n += 1
    return n


# --------------------------------------------------------------------------- assemble
def finalize(col, cap_per_rule=40):
    cands = list(col.groups.values())
    by_rule = {}
    for c in cands:
        by_rule.setdefault(c["rule"], []).append(c)
    kept, suppressed = [], {}
    for rule, lst in by_rule.items():
        lst.sort(key=lambda c: (R.SEV.index(c["severity"]), c["file"]))
        kept.extend(lst[:cap_per_rule])
        if len(lst) > cap_per_rule:
            suppressed[rule] = len(lst) - cap_per_rule
    kept.sort(key=lambda c: (R.SEV.index(c["severity"]), c["domain"], c["file"], c["line"]))
    for n, c in enumerate(kept, 1):
        c["id"] = f"FND-{n:03d}"
        c["fingerprint"] = hashlib.sha1(f"{c['rule']}|{c['file']}|{c['locations'][0]['snippet']}".encode()).hexdigest()[:10]
        c["triage"] = "candidate"
        c["status"] = "Open"
    return kept, suppressed


def prefill_checklist(cands, ref_dir):
    spec = json.load(open(os.path.join(ref_dir, "checklist.json"), encoding="utf-8"))
    out = []
    for d_i, d in enumerate(spec["domains"], 1):
        for i_i, it in enumerate(d["items"], 1):
            hits = [c["id"] for c in cands if any((c["rule"].startswith(s[:-1]) if s.endswith("*") else c["rule"] == s) for s in it["signals"])]
            out.append(dict(key=it["key"], number=f"4.{d_i}.{i_i}", domain=d["key"], issue=it["issue"], signals=it["signals"], review=it["review"],
                            scanner_hits=hits, status="Needs Review" if hits else "Not Assessed", evidence="", finding_ids=hits))
    return out


def main():
    ap = argparse.ArgumentParser(description="Offline static security scan; writes scan.json + sbom.cdx.json")
    ap.add_argument("repo", help="path to the source repository")
    ap.add_argument("--out", default="./security-audit", help="output directory")
    ap.add_argument("--name", help="application name for the report/SBOM (default: folder name)")
    ap.add_argument("--max-file-kb", type=int, default=1024)
    ap.add_argument("--no-git-history", action="store_true", help="skip the git history secret scan")
    ap.add_argument("--max-commits", type=int, default=5000)
    ap.add_argument("--osv-results", help="osv-scanner JSON produced elsewhere (imported, not executed)")
    ap.add_argument("--sarif", action="append", default=[], help="SARIF file from another tool (Semgrep, CodeQL, ...) to merge; repeatable")
    a = ap.parse_args()

    root = os.path.abspath(a.repo)
    if not os.path.isdir(root):
        sys.exit(f"error: {root} is not a directory")
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    col = Collector()
    inv, manifest_files, working_hashes = scan_tree(root, a.max_file_kb, col)

    comps = depmod.collect(manifest_files)
    for d in depmod.analyze(comps, manifest_files, a.osv_results):
        d.setdefault("fix", "")
        col.add_raw(d)
    app = a.name or os.path.basename(root.rstrip("/")) or "application"
    gm = git_meta(root)
    with open(os.path.join(a.out, "sbom.cdx.json"), "w", encoding="utf-8") as fh:
        json.dump(depmod.sbom(comps, app, gm.get("commit") or "unknown"), fh, indent=2)

    hist = dict(ran=False, note="Skipped by --no-git-history.", commits_scanned=0, hits=0)
    if not a.no_git_history:
        hist = scan_history(root, a.max_commits, working_hashes, col)
    sarif_n = sum(import_sarif(p, col) for p in a.sarif)

    cands, suppressed = finalize(col)
    eco = {}
    for c in comps:
        e = eco.setdefault(c["ecosystem"], dict(total=0, pinned=0, dev=0))
        e["total"] += 1
        e["pinned"] += 1 if c["version"] else 0
        e["dev"] += 1 if c["dev"] else 0
    limitations = [
        "Static analysis only. No network calls were made and the live application was not touched; runtime behaviour, deployed configuration, WAF/gateway controls and IdP-side policy were not observed.",
        "Pattern-based detection finds candidates; absence of a hit is not proof a control exists. Each domain still requires manual code reading.",
        f"Dependency CVE matching uses a curated offline advisory list ({sum(len(v) for v in depmod.ADVISORIES.values())} advisories). It is not exhaustive. Import connected OSV/NVD results with --osv-results for full coverage.",
    ]
    if not hist["ran"]:
        limitations.append("Git history was not scanned: " + hist.get("note", ""))
    if getattr(walk, "skipped_large", None):
        limitations.append(f"{len(walk.skipped_large)} file(s) over {a.max_file_kb} KB were not scanned.")
    if suppressed:
        limitations.append("Per-rule display cap reached (additional matching files not listed): " + ", ".join(f"{k} (+{v})" for k, v in suppressed.items()))

    scan = dict(
        meta=dict(tool="appsec-static-audit", version=VERSION, application=app, repository=os.path.basename(root), scanned_at=datetime.now().astimezone().isoformat(timespec="seconds"),
                  git=gm, duration_s=round(time.time() - t0, 1), frameworks=inv["frameworks"]),
        inventory=dict(files_scanned=inv["files"], lines=inv["loc"], by_tag=dict(sorted(inv["by_lang"].items())), manifests=inv["manifests"],
                       iac_files=inv["iac"][:200], frameworks=inv["frameworks"], skipped_binary=inv["skipped_binary"],
                       skipped_large=getattr(walk, "skipped_large", [])),
        dependencies=dict(total=len(comps), ecosystems=eco, sbom="sbom.cdx.json"),
        history=hist, sarif_imported=sarif_n, limitations=limitations, suppressed=suppressed,
        findings=cands, checklist=prefill_checklist(cands, os.path.join(HERE, "..", "references")),
    )
    with open(os.path.join(a.out, "scan.json"), "w", encoding="utf-8") as fh:
        json.dump(scan, fh, indent=2)

    sev_count = {s: sum(1 for c in cands if c["severity"] == s) for s in R.SEV}
    print(f"Scanned {inv['files']} files ({inv['loc']} lines) in {scan['meta']['duration_s']}s; {len(comps)} dependencies; "
          f"history: {'%d commits' % hist['commits_scanned'] if hist['ran'] else 'not scanned'}")
    print("Candidate findings: " + ", ".join(f"{k} {v}" for k, v in sev_count.items()) + f"  (total {len(cands)})")
    print(f"Wrote {os.path.join(a.out, 'scan.json')} and {os.path.join(a.out, 'sbom.cdx.json')}")
    print("NEXT: read the code per domain, triage every candidate, then write triage.json and run render_report.py")


if __name__ == "__main__":
    main()
