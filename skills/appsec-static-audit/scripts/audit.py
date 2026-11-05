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
import flow  # noqa: E402
import rules as R  # noqa: E402

VERSION = "1.1.0"
SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "env", "dist", "build", "target", "out", "__pycache__", ".tox",
             ".mypy_cache", ".idea", ".vscode", "bower_components", "site-packages", ".gradle", ".terraform", "coverage",
             ".next", ".nuxt", ".pytest_cache", ".cache", "bin", "obj", "packages"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".7z", ".rar",
              ".jar", ".war", ".ear", ".class", ".dll", ".exe", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3",
              ".mp4", ".mov", ".avi", ".wav", ".pyc", ".pyo", ".o", ".a", ".bin", ".onnx", ".pt", ".pth", ".parquet", ".map"}
LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock",
              "go.sum", "npm-shrinkwrap.json", "uv.lock", "pdm.lock", "Cargo.lock", "packages.lock.json"}
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


BACKUP_RX = re.compile(r"(\.(bak|orig|old|backup|save|swp|tmp|rej)([-_.\w]*)?|~)$", re.I)


def tags_for(rel):
    name = BACKUP_RX.sub("", os.path.basename(rel)) or os.path.basename(rel)
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


def _excluded(rel, patterns):
    import fnmatch
    base = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        p = pat.strip().strip("/")
        if not p:
            continue
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(base, p) or fnmatch.fnmatch(rel, p + "/*") or rel == p or rel.startswith(p + "/"):
            return True
    return False


def walk(root, max_kb, excludes=(), inv=None):
    skipped_large = []
    for dp, dn, fn in os.walk(root):
        reldir = os.path.relpath(dp, root).replace(os.sep, "/")
        reldir = "" if reldir == "." else reldir
        keep = []
        for d in dn:
            if d in SKIP_DIRS or d.endswith(".egg-info"):
                continue
            if excludes and _excluded((reldir + "/" + d).lstrip("/"), excludes):
                if inv is not None:
                    inv["excluded"] += 1
                continue
            keep.append(d)
        dn[:] = sorted(keep)
        for f in sorted(fn):
            ap = os.path.join(dp, f)
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            if os.path.splitext(f.lower())[1] in BINARY_EXT:
                continue
            if excludes and _excluded(rel, excludes):
                if inv is not None:
                    inv["excluded"] += 1
                continue
            try:
                size = os.path.getsize(ap)
            except OSError:
                continue
            if size > max_kb * 1024 and not (f in LOCK_NAMES and size <= 200 * 1024 * 1024):   # lockfiles are routinely > 1 MB
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
            if ctx in ("test", "backup") and meta["id"] != "MISC-PROMPT-1":
                sev = sev_down(sev)
                note = (" (located in test/fixture code; severity reduced one level, confirm no production reuse)" if ctx == "test"
                        else " (located in a backup/old copy of a file; severity reduced one level, confirm it is not deployed)")
            c = dict(rule=meta["id"], domain=meta["domain"], severity=sev, cwe=meta.get("cwe", ""), owasp=meta.get("owasp", ""),
                     title=extra_title or meta["title"], file=file, line=line, locations=[], detail=(detail or "") + note,
                     fix=meta["fix"], confidence=meta.get("confidence", "Medium"), context=ctx, source=source)
            self.groups[key] = c
            self.rule_files.setdefault(meta["id"], set()).add(file)
        if detail and c is not None and detail not in c["detail"] and len(c["detail"]) < 700:
            c["detail"] = (c["detail"] + " " + detail).strip()
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


META_BY_ID = {r["id"]: r for r in R.RULES}
FW_RX = {k: re.compile(v, re.M | re.I) for k, v in FRAMEWORKS.items()}
MANIFEST_RX = re.compile(r"(package\.json|requirements[\w.\-]*\.txt|pom\.xml|go\.mod|.*\.csproj|packages\.config|.*\.gradle(\.kts)?|Pipfile|composer\.json|pyproject\.toml|Cargo\.toml|Gemfile|\.npmrc|\.yarnrc(\.yml)?|pip\.(conf|ini))")
MONOREPO_DIRS = {"packages", "services", "apps", "libs", "modules", "projects", "src", "components", "cmd", "internal", "plugins"}


class Recorder:
    """Stands in for Collector inside a worker process: records add() calls so the parent can replay them in file order."""

    def __init__(self):
        self.calls = []

    def add(self, meta, file, line, snippet, ctx, extra_title=None, detail=None, source="scanner"):
        ref = meta["id"] if "rx" in meta else meta        # registered rules travel by id, ad-hoc metas by value
        self.calls.append((ref, file, line, snippet, ctx, extra_title, detail, source))


def component_of(rel):
    parts = rel.split("/")
    if len(parts) == 1:
        return "(repository root)"
    if parts[0] in MONOREPO_DIRS and len(parts) > 2:
        return parts[0] + "/" + parts[1]
    return parts[0]


def scan_file(task):
    """Scan one file. Pure function of the file: safe to run in a worker process. Returns a plain-data result."""
    ap, rel = task
    base = os.path.basename(rel)
    ctx = "test" if TEST_RX.search(rel) else "backup" if BACKUP_RX.search(base) else "source"
    res = dict(rel=rel, ap=ap, kind="file", ctx=ctx, tags=[], loc=0, manifest=False, iac=False, frameworks=[], routes=[], calls=[],
               secret_hashes=[], long_line=False, flow_unparsed=False, flow_hits=0, commented_hits=0, pres_repo={}, pres_file=[])
    if base in LOCK_NAMES or base.endswith((".min.js", ".min.css")):
        res["kind"] = "lock"
        res["minified"] = base.endswith((".min.js", ".min.css"))
        return res
    text = read_text(ap)
    if text is None:
        res["kind"] = "binary"
        return res
    col = Recorder()
    meta_by_id = META_BY_ID
    tags = tags_for(rel)
    res["tags"] = sorted(tags)
    res["loc"] = text.count("\n") + 1
    if MANIFEST_RX.fullmatch(base):
        res["manifest"] = True
    if tags & {"tf"} or "docker" in tags or (("yaml" in tags) and re.search(r"AWSTemplateFormatVersion|apiVersion:\s*\S+\s*\n\s*kind:", text)):
        res["iac"] = True
    if "md" not in tags:
        res["frameworks"] = [n for n, rx in FW_RX.items() if rx.search(text)]

    for rx, label in SENSITIVE_FILES:
        if rx.search(rel) and not EXAMPLE_RX.search(rel):
            col.add(meta_by_id["SEC-FILE-1"], rel, 1, f"{label}: {base}", ctx, extra_title=f"Sensitive file committed: {base} ({label})")
    if DATA_FILES.search(rel):
        col.add(meta_by_id["SEC-FILE-2"], rel, 1, f"Data file: {base}", ctx, extra_title=f"Database dump / data file committed: {base}")

    if "md" in tags and len(tags) == 1:
        scan_prompt_only(rel, text, ctx, meta_by_id, col)
        res["calls"] = col.calls
        return res

    if ctx == "source" and tags & {"py", "js", "java", "cs", "go", "php"}:
        find_routes(rel, text, tags, res["routes"])

    # ---- presence bookkeeping (repo + file scope)
    if ctx == "source":
        for p in R.PRESENCE:
            if p["scope"] == "repo":
                found = bool(p["expect"].search(text))
                when = None
                if tags & p["langs"]:
                    m = p["when"].search(text)
                    if m:
                        ln = lineno(text, m.start())
                        when = (rel, ln, redact_line(text.splitlines()[ln - 1]))
                if found or when:
                    res["pres_repo"][p["id"]] = (found, when)
            elif tags & p["langs"]:
                m = p["when"].search(text)
                if m and not p["expect"].search(text):
                    ln = lineno(text, m.start())
                    res["pres_file"].append((p["id"], p["aggregate"], dict(file=rel, line=ln, snippet=redact_line(text.splitlines()[ln - 1]))))

    applicable = [r for r in R.RULES if r["id"] not in ("SEC-FILE-1", "SEC-FILE-2", "DATA-4") and (r["langs"] & tags or "any" in r["langs"])]
    generic_ok = "md" not in tags
    logical = list(flow.logical_lines(text, tags)) if tags & flow.CODE_TAGS else None
    if ctx in ("source", "test"):
        flow_hits = []
        if "py" in tags:
            flow_hits, ok = flow.python_flows(text)
            res["flow_unparsed"] = not ok
        elif "js" in tags and logical is not None:
            flow_hits = flow.javascript_flows(logical)
        for fh in flow_hits:
            meta = meta_by_id.get(fh["rule"])
            if meta:
                res["flow_hits"] += 1
                col.add(meta, rel, fh["line"], redact_line(fh["snippet"]), ctx, detail=fh["detail"])
    line_iter = logical if logical is not None else enumerate(text.split("\n"), 1)
    long_nos = {n for n, l in enumerate(text.split("\n"), 1) if len(l) > 2000}
    for i, line in line_iter:
        if not line.strip():
            continue
        if i in long_nos or len(line) > 6000:
            res["long_line"] = True
            continue
        commented = is_comment(line)
        if generic_ok:
            hit_secret = secret_scan(line, tags, commented)
            if hit_secret:
                name, val, sev = hit_secret
                m = dict(id="SEC-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-")[:28], domain="secrets", severity=sev,
                         cwe="CWE-798", owasp="A02", title=f"Hardcoded secret: {name}",
                         fix="Remove from source, rotate the credential now (it is exposed to everyone with repo access), load from a secrets manager or environment, and add pre-commit secret scanning.",
                         confidence="High" if "key" in name.lower() or "token" in name.lower() else "Medium")
                if EXAMPLE_RX.search(rel):
                    m["severity"] = "Low"
                col.add(m, rel, i, redact_line(line), ctx)
                res["secret_hashes"].append(hashlib.sha1(val.encode()).hexdigest())
            if R.SSN_RX.search(line) and "sql" not in tags and not re.search(r"(?i)(isbn|phone|fax|tel|version|uuid|guid)", line):
                sev = "High" if ctx == "source" else "Medium"
                col.add(dict(id="DATA-4", domain="data", severity=sev, cwe="CWE-359", owasp="",
                             title="Literal SSN-shaped value in source or fixtures",
                             fix=meta_by_id["DATA-4"]["fix"], confidence="Medium"), rel, i, redact_line(line), ctx)
        prose = PROSE_LINE.match(line) is not None
        for r in applicable:
            if commented and r["id"] != "MISC-PROMPT-1":
                if r["rx"].search(line):
                    res["commented_hits"] += 1
                continue
            if prose and r["id"] != "MISC-PROMPT-1":
                continue
            if r["only_files"] and not r["only_files"].search(rel):
                continue
            if r["rx"].search(line):
                if r["skip"] and r["skip"].search(line):
                    continue
                if r["id"] == "SSO-OIDC-2" and not re.search(r"(?i)(admin|role|permission|isAdmin|=)", line):
                    continue
                col.add(r, rel, i, redact_line(line, force=r["redact"]), ctx)
    res["calls"] = col.calls
    return res


def _default_jobs():
    return max(1, min(os.cpu_count() or 1, 8))


def scan_tree(root, max_kb, col, jobs=1, excludes=(), progress=None):
    """Walk and scan the repository (optionally with a process pool) and merge results in walk order, so output is deterministic."""
    meta_by_id = META_BY_ID
    inv = dict(files=0, by_lang={}, manifests=[], iac=[], frameworks=set(), skipped_binary=0, loc=0,
               long_line_files=[], minified=[], commented_hits=0, commented_files=set(), flow_unparsed=[], flow_hits=0,
               excluded=0, components={}, jobs=1)
    manifest_files, secret_hashes, agg = [], set(), {}
    pres_state = {p["id"]: dict(when=None, found=False) for p in R.PRESENCE}
    routes = []
    tasks = [(ap, rel) for ap, rel, _size in walk(root, max_kb, excludes, inv)]
    use_pool = jobs > 1 and len(tasks) >= 300
    results = None
    pool = None
    if use_pool:
        try:
            import multiprocessing
            pool = multiprocessing.Pool(jobs)
            results = pool.imap(scan_file, tasks, chunksize=16)
            inv["jobs"] = jobs
        except (OSError, ImportError, ValueError):
            pool = None
    if results is None:
        results = map(scan_file, tasks)
    try:
        for n, res in enumerate(results, 1):
            if progress and n % 5000 == 0:
                progress(n, len(tasks))
            rel, ap = res["rel"], res["ap"]
            if res["kind"] == "lock":
                manifest_files.append((ap, rel))
                if res.get("minified"):
                    inv["minified"].append(rel)
                continue
            if res["kind"] == "binary":
                inv["skipped_binary"] += 1
                continue
            inv["files"] += 1
            inv["loc"] += res["loc"]
            for t in res["tags"]:
                inv["by_lang"][t] = inv["by_lang"].get(t, 0) + 1
            comp = inv["components"].setdefault(component_of(rel), dict(files=0, lines=0, routes=0, manifests=0, iac=0))
            comp["files"] += 1
            comp["lines"] += res["loc"]
            if res["manifest"]:
                inv["manifests"].append(rel)
                manifest_files.append((ap, rel))
                comp["manifests"] += 1
            if res["iac"]:
                inv["iac"].append(rel)
                comp["iac"] += 1
            inv["frameworks"].update(res["frameworks"])
            if res["long_line"]:
                inv["long_line_files"].append(rel)
            if res["flow_unparsed"]:
                inv["flow_unparsed"].append(rel)
            inv["flow_hits"] += res["flow_hits"]
            if res["commented_hits"]:
                inv["commented_hits"] += res["commented_hits"]
                inv["commented_files"].add(rel)
            routes.extend(res["routes"][:max(0, 3000 - len(routes))])
            comp["routes"] += len(res["routes"])
            secret_hashes.update(res["secret_hashes"])
            for pid, (found, when) in res["pres_repo"].items():
                st = pres_state[pid]
                st["found"] = st["found"] or found
                if st["when"] is None and when:
                    st["when"] = when
            for pid, aggregate, loc in res["pres_file"]:
                p = next(x for x in R.PRESENCE if x["id"] == pid)
                key = pid if aggregate else (pid, loc["file"])
                ag = agg.get(key)
                if ag is None:
                    ag = agg[key] = dict(rule=pid, domain=p["domain"], severity=p["severity"], cwe=p["cwe"], owasp=p["owasp"],
                                         title=p["title"], file=loc["file"], line=loc["line"], fix=p["fix"], confidence=p["confidence"], locations=[], count=0,
                                         detail="Control not evidenced in the cited file(s); it may be enforced elsewhere (gateway, base class, middleware, IdP). Confirm by reading the code.")
                ag["count"] += 1
                if len(ag["locations"]) < 25:
                    ag["locations"].append(loc)
            for ref, f, line, snippet, ctx, extra_title, detail, source in res["calls"]:
                col.add(meta_by_id[ref] if isinstance(ref, str) else ref, f, line, snippet, ctx, extra_title=extra_title, detail=detail, source=source)
    finally:
        if pool is not None:
            pool.close()
            pool.join()
    for ag in agg.values():
        if ag["count"] > len(ag["locations"]):
            ag["detail"] += f" {ag['count']} file(s) matched; the first {len(ag['locations'])} are listed."
        elif ag["count"] > 1:
            ag["detail"] += f" {ag['count']} file(s) matched."
        col.add_raw(ag)
    for p in R.PRESENCE:
        st = pres_state[p["id"]]
        if p["scope"] == "repo" and st["when"] and not st["found"]:
            f, ln, snip = st["when"]
            col.add_raw(dict(rule=p["id"], domain=p["domain"], severity=p["severity"], cwe=p["cwe"], owasp=p["owasp"], title=p["title"],
                             file=f, line=ln, fix=p["fix"], confidence=p["confidence"],
                             detail="Relevant code exists but no matching control was found anywhere in the repository (absence of evidence, not proof). It may be delegated to the IdP, gateway or platform; confirm and document where.",
                             locations=[dict(line=ln, snippet=snip)]))
    inv["frameworks"] = sorted(inv["frameworks"])
    inv["commented_files"] = sorted(inv["commented_files"])
    inv["routes"] = routes
    return inv, manifest_files, secret_hashes


def scan_prompt_only(rel, text, ctx, meta_by_id, col):
    m = meta_by_id["MISC-PROMPT-1"]
    for i, line in enumerate(text.split("\n"), 1):
        if m["rx"].search(line):
            col.add(m, rel, i, redact_line(line), ctx)


PROSE_LINE = re.compile(r"^\s*\"(Description|Title|Message|Summary|PrimaryURL|References|FixedVersion|Text)\"\s*:", re.I)
CONFIG_TAGS = {"env", "conf", "yaml", "sh", "tf", "docker"}


SECRETISH = re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key|access[_-]?key|auth[_-]?key|signing[_-]?key|encryption[_-]?key|credential|salt|jwt)")
ENV_FALLBACKS = [
    re.compile(r"""process\.env\.(\w+)\s*(?:\|\||\?\?)\s*["'`]([^"'`$\s]{6,})["'`]"""),
    re.compile(r"""process\.env\[\s*["'](\w+)["']\s*\]\s*(?:\|\||\?\?)\s*["'`]([^"'`$\s]{6,})["'`]"""),
    re.compile(r"""os\.environ\.get\(\s*["'](\w+)["']\s*,\s*["']([^"'\s]{6,})["']\s*\)"""),
    re.compile(r"""os\.getenv\(\s*["'](\w+)["']\s*,\s*["']([^"'\s]{6,})["']\s*\)"""),
    re.compile(r"""os\.environ(?:\.get\(\s*["'](\w+)["']\s*\)|\[\s*["'](\w+)["']\s*\])\s+or\s+["']([^"'\s]{6,})["']"""),
    re.compile(r"""ENV\.fetch\(\s*["'](\w+)["']\s*,\s*["']([^"'\s]{6,})["']\s*\)|ENV\[\s*["'](\w+)["']\s*\]\s*\|\|\s*["']([^"'\s]{6,})["']"""),
    re.compile(r"""getenv\(\s*["'](\w+)["']\s*\)\s*(?:\?:|\?\?|\|\|)\s*["']([^"'\s]{6,})["']"""),
    re.compile(r"""(?:System\.getenv|Environment\.GetEnvironmentVariable)\(\s*["'](\w+)["']\s*\)\s*(?:\?\?|\|\||\?:)\s*["']([^"'\s]{6,})["']"""),
    re.compile(r"""os\.Getenv\(\s*["'](\w+)["']\s*\)[^\n]*(?:\|\||==\s*"")[^\n]*["']([^"'\s]{6,})["']"""),
]
ASSIGNED_NAME = re.compile(r"^\s*(?:export\s+)?(?:const|let|var|final|static|private|public|val)?\s*(?:[\w<>\[\]]+\s+)?([A-Za-z_$][\w$.]*)\s*[:=]")


def env_fallback_secret(line):
    """`process.env.X || "literal"`, `os.environ.get("X", "literal")`: a hardcoded default for a secret is a hardcoded secret."""
    for rx in ENV_FALLBACKS:
        m = rx.search(line)
        if not m:
            continue
        groups = [g for g in m.groups() if g]
        if len(groups) < 2:
            continue
        env_name, val = groups[0], groups[-1]
        am = ASSIGNED_NAME.match(line)
        key = env_name if SECRETISH.search(env_name) else (am.group(1) if am and SECRETISH.search(am.group(1)) else None)
        if key and not R.PLACEHOLDER.search(val) and R.looks_secret(val, key):
            return "Default secret in env lookup", val, "High"
    return None


def secret_scan(line, tags=None, commented=False):
    """Return (name, value, severity) for a likely hardcoded secret on this line, else None."""
    if commented and re.search(r"(?i)\b(example|e\.g\.|sample|for instance)\b", line):
        return None
    fb = env_fallback_secret(line)
    if fb:
        return fb
    for name, rx, sev in R.SECRET_PATTERNS + EXTRA_SECRET:
        m = rx.search(line)
        if m:
            val = m.group(0)
            if name.startswith("Credentials in connection") and R.PLACEHOLDER.search(val):
                continue
            return name, val, sev
    m = R.GENERIC_SECRET.search(line)
    if m:
        val, key = m.group(3), m.group(1)
        if (not R.PLACEHOLDER.search(val) and R.looks_secret(val, key)
                and not re.search(r"(?i)(process\.env|os\.environ|getenv|System\.getenv|config\.get|settings\.|\.get\()", line)):
            return "Hardcoded credential literal", val, "High"
    if tags is None or tags & CONFIG_TAGS:
        m = UNQUOTED_SECRET.match(line)
        if m and not R.PLACEHOLDER.search(m.group(2)) and R.looks_secret(m.group(2), m.group(1)):
            return "Hardcoded credential literal (config)", m.group(2), "High"
    return None


# --------------------------------------------------------------------------- route inventory
ROUTE_PATTERNS = [
    ("Flask/FastAPI", re.compile(r"@\s*\w+\.(get|post|put|delete|patch|head|options|route|api_route)\(\s*f?[\"']([^\"']*)[\"']"), {"py"}),
    ("Express", re.compile(r"(?<![\w.])(app|router|\w+Router|\w+_router)\.(get|post|put|delete|patch|all)\(\s*[\"'`]([^\"'`]*)[\"'`]"), {"js"}),
    ("Spring", re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*[\"']([^\"']*)[\"'])?"), {"java"}),
    ("ASP.NET", re.compile(r"\[Http(Get|Post|Put|Delete|Patch)(?:\(\s*[\"']([^\"']*)[\"']\s*\))?\]"), {"cs"}),
    ("Django", re.compile(r"(?<![\w.])(re_)?path\(\s*r?[\"']([^\"']*)[\"']"), {"py"}),
    ("Go", re.compile(r"(?-i:(?<![\w])\w+\.(GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\(\s*\"([^\"]*)\")"), {"go"}),
    ("Laravel", re.compile(r"Route::(get|post|put|delete|patch)\(\s*[\"']([^\"']*)[\"']"), {"php"}),
]
AUTH_EVIDENCE = re.compile(r"(?i)login_required|permission_required|jwt_required|Depends\(|Security\(|authenticate|authorize|@PreAuthorize|@Secured|@RolesAllowed|requires_auth|auth_required|isAuthenticated|ensureAuth|ensureLoggedIn|verifyToken|passport\.|requireAuth|\bprotect\b|\bguard\b|bearer|IsAuthenticated|permission_classes|\[Authorize|current_user|require_login|before_action\s*:authenticate")
ROUTER_LEVEL_AUTH = re.compile(r"(?i)dependencies\s*=\s*\[|(app|router)\.use\(\s*[\w.]*(auth|jwt|passport|protect|verify)|@(PreAuthorize|Secured|Authorize)[^\n]*\n\s*(public\s+)?(class|@)|\[Authorize\]\s*\n\s*(\[[^\n]*\]\s*\n\s*)*public\s+class|SecurityFilterChain|authorizeHttpRequests")
PUBLIC_PATH = re.compile(r"(?i)^/?(health\w*|ping|ready\w*|live\w*|metrics|static|favicon\.ico|version|status|docs|openapi\.json|login|logout|callback)\b")


def find_routes(rel, text, tags, out, cap=3000):
    if len(out) >= cap:
        return
    lines = text.split("\n")
    router_level = bool(ROUTER_LEVEL_AUTH.search(text))
    for fw, rx, need in ROUTE_PATTERNS:
        if not (tags & need):
            continue
        for m in rx.finditer(text):
            ln = lineno(text, m.start())
            window = "\n".join(lines[max(0, ln - 7):min(len(lines), ln + 3)])
            g = [x for x in m.groups() if x is not None]
            method = (g[0] if g and g[0].lower() in ("get", "post", "put", "delete", "patch", "head", "options", "route", "all", "request", "api_route", "handle", "handlefunc") else "ANY").upper()
            path = next((x for x in reversed(g) if x and x.lower() != method.lower()), "")
            if AUTH_EVIDENCE.search(window):
                auth = "evidenced"
            elif router_level:
                auth = "router/class-level (verify)"
            elif PUBLIC_PATH.match(path or ""):
                auth = "public by convention"
            else:
                auth = "none seen"
            out.append(dict(file=rel, line=ln, framework=fw, method=method, path=path or "(unspecified)", auth=auth))
            if len(out) >= cap:
                return


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
    dirty = g("status", "--porcelain", "--untracked-files=no")
    return dict(commit=g("rev-parse", "--short", "HEAD"), commit_full=g("rev-parse", "HEAD"), dirty=bool(dirty) if g("rev-parse", "HEAD") else None,
                branch=g("rev-parse", "--abbrev-ref", "HEAD"),
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
        hit = secret_scan(line[1:], tags_for(fil), is_comment(line[1:]))
        if not hit:
            continue
        name, val, sev = hit
        if TEST_RX.search(fil) and name.startswith("Hardcoded credential literal"):
            continue  # generic literals in test code are not reported; specific key formats still are
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
    seen = {}
    for c in kept:
        # fingerprint ignores line numbers so it survives edits elsewhere in the file; title distinguishes aggregate findings
        base = f"{c['rule']}|{c['file']}|{c['title'] if c['rule'].startswith(('DEP-', 'SARIF')) else ''}|{re.sub(chr(92) + 's+', ' ', c['locations'][0]['snippet']).strip()[:160]}"
        fp = hashlib.sha1(base.encode()).hexdigest()[:10]
        n = seen.get(fp, 0) + 1
        seen[fp] = n
        c["fingerprint"] = fp if n == 1 else f"{fp}-{n}"
        c["triage"] = "candidate"
        c["status"] = "Open"
    return kept, suppressed


def assign_stable_ids(cands, registry_path, repo_name):
    """FND numbers are remembered per fingerprint in a registry file, so a finding keeps its ID across re-scans
    (and an existing triage.json stays valid). New findings get the next free number; fixed ones leave a gap."""
    reg = dict(repository=repo_name, next=1, ids={})
    note = ""
    try:
        with open(registry_path, encoding="utf-8") as fh:
            old = json.load(fh)
        if old.get("repository") == repo_name and isinstance(old.get("ids"), dict):
            reg = old
        else:
            note = f"finding-ids.json belongs to repository '{old.get('repository')}', ignored"
    except (OSError, ValueError):
        pass
    used = set(reg["ids"].values())
    reg["next"] = max(int(reg.get("next", 1)), (max(used) + 1) if used else 1)
    for c in cands:
        n = reg["ids"].get(c["fingerprint"])
        if n is None:
            n = reg["next"]
            reg["next"] += 1
            reg["ids"][c["fingerprint"]] = n
        c["id"] = f"FND-{n:03d}"
    try:
        with open(registry_path, "w", encoding="utf-8") as fh:
            json.dump(reg, fh, indent=1, sort_keys=True)
    except OSError as e:
        note = (note + "; " if note else "") + f"could not write {registry_path}: {e}"
    return note


def load_suppressions(paths):
    """Suppression policy: accepted risks and known false positives that should not need re-triage on every scan."""
    entries, problems = [], []
    today = datetime.now().date()
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            problems.append(f"suppression file {os.path.basename(p)} unreadable: {e}")
            continue
        for i, e in enumerate(data.get("suppressions", []), 1):
            if not (e.get("fingerprint") or e.get("rule") or e.get("file_regex")):
                problems.append(f"{os.path.basename(p)} entry {i} ignored: needs fingerprint, rule or file_regex")
                continue
            if not (e.get("reason") or "").strip():
                problems.append(f"{os.path.basename(p)} entry {i} ignored: a reason is required")
                continue
            kind = e.get("type", "accepted_risk")
            if kind not in ("accepted_risk", "false_positive"):
                problems.append(f"{os.path.basename(p)} entry {i} ignored: type must be accepted_risk or false_positive")
                continue
            exp = None
            if e.get("expires"):
                try:
                    exp = datetime.strptime(str(e["expires"]), "%Y-%m-%d").date()
                except ValueError:
                    problems.append(f"{os.path.basename(p)} entry {i} ignored: expires must be YYYY-MM-DD")
                    continue
            if kind == "accepted_risk" and exp is None:
                problems.append(f"{os.path.basename(p)} entry {i} ignored: an accepted risk needs an 'expires' date")
                continue
            entries.append(dict(e, type=kind, _exp=exp, _expired=bool(exp and exp < today)))
    return entries, problems


def apply_suppressions(cands, entries):
    applied = expired = 0
    for c in cands:
        for e in entries:
            if e.get("fingerprint") and e["fingerprint"] != c["fingerprint"]:
                continue
            if e.get("rule") and not (c["rule"] == e["rule"] or (e["rule"].endswith("*") and c["rule"].startswith(e["rule"][:-1]))):
                continue
            if e.get("file_regex") and not re.search(e["file_regex"], c["file"]):
                continue
            if e.get("snippet_regex") and not re.search(e["snippet_regex"], " ".join(l.get("snippet", "") for l in c["locations"])):
                continue
            if e["_expired"]:
                expired += 1
                c["detail"] = (c.get("detail", "") + f" A suppression for this finding expired on {e['expires']} (owner: {e.get('owner', 'unknown')}) and no longer applies: re-assess.").strip()
                break
            c["suppression"] = dict(type=e["type"], reason=e["reason"], owner=e.get("owner", ""), expires=e.get("expires", ""))
            applied += 1
            break
    return applied, expired


def load_previous(path):
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d.get("findings"), list) else None
    except (OSError, ValueError):
        return None


def compare_previous(cands, prev):
    cur = {c["fingerprint"] for c in cands}
    pfp = {f["fingerprint"]: f for f in prev["findings"] if f.get("fingerprint")}
    for c in cands:
        c["delta"] = "existing" if c["fingerprint"] in pfp else "new"
    gone = [dict(id=f["id"], rule=f["rule"], severity=f["severity"], title=f["title"], file=f["file"]) for fp, f in pfp.items() if fp not in cur]
    gone.sort(key=lambda f: (R.SEV.index(f["severity"]), f["file"]))
    return dict(previous_scanned_at=(prev.get("meta") or {}).get("scanned_at", ""), previous_commit=((prev.get("meta") or {}).get("git") or {}).get("commit", ""),
                new=sum(1 for c in cands if c["delta"] == "new"), existing=sum(1 for c in cands if c["delta"] == "existing"), no_longer_detected=gone)


def tool_fingerprint():
    """Hash of the scanner code and reference data, so a result can be tied to exactly the rules that produced it."""
    h = hashlib.sha256()
    for sub in ("scripts", "references"):
        d = os.path.join(HERE, "..", sub)
        for fn in sorted(os.listdir(d)):
            if fn.endswith((".py", ".json")):
                with open(os.path.join(d, fn), "rb") as fh:
                    h.update(fn.encode() + b"\0" + fh.read())
    return h.hexdigest()


def file_sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


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
    ap.add_argument("--jobs", type=int, default=_default_jobs(), help="worker processes for large repositories (default: up to 8; 1 disables)")
    ap.add_argument("--exclude", action="append", default=[], help="glob or path to skip (repeatable), e.g. --exclude 'vendor/*' --exclude third_party")
    ap.add_argument("--exclude-from", help="file with one exclude pattern per line")
    ap.add_argument("--suppressions", action="append", default=[], help="suppression policy JSON (accepted risks / known false positives); repeatable")
    ap.add_argument("--previous", help="scan.json of an earlier run to compare against (default: the scan.json already in --out; 'none' disables)")
    ap.add_argument("--cap-per-rule", type=int, default=40, help="max candidates listed per rule (extra files are counted, not listed)")
    ap.add_argument("--advisory-db", help="advisory snapshot to use instead of references/advisory-db.json.gz (see tools/build_advisory_db.py)")
    ap.add_argument("--sarif", action="append", default=[], help="SARIF file from another tool (Semgrep, CodeQL, ...) to merge; repeatable")
    a = ap.parse_args()

    root = os.path.abspath(a.repo)
    if not os.path.isdir(root):
        sys.exit(f"error: {root} is not a directory")
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    col = Collector()
    excludes = list(a.exclude)
    if a.exclude_from:
        try:
            with open(a.exclude_from, encoding="utf-8") as fh:
                excludes += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"error: cannot read --exclude-from: {e}")
    prev_path = a.previous or os.path.join(a.out, "scan.json")
    prev = None if (a.previous or "").lower() == "none" else load_previous(prev_path)
    if prev and (prev.get("meta") or {}).get("repository") != os.path.basename(root):
        prev = None
    inv, manifest_files, working_hashes = scan_tree(
        root, a.max_file_kb, col, jobs=max(1, a.jobs), excludes=excludes,
        progress=lambda n, t: print(f"  ... {n:,}/{t:,} files scanned", file=sys.stderr, flush=True))

    comps = depmod.collect(manifest_files)
    db = depmod.load_db(a.advisory_db)
    dbi = depmod.db_info(db)
    unresolved = 0
    for d in depmod.analyze(comps, manifest_files, a.osv_results, db):
        if d["rule"] == "_DEPSTAT":
            unresolved = d["unresolved"]
            continue
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

    cands, suppressed = finalize(col, a.cap_per_rule)
    repo_name = os.path.basename(root)
    id_note = assign_stable_ids(cands, os.path.join(a.out, "finding-ids.json"), repo_name)
    supp_paths = list(a.suppressions)
    for cand in (os.path.join(root, ".appsec-audit", "suppressions.json"), os.path.join(a.out, "suppressions.json")):
        if os.path.exists(cand) and cand not in supp_paths:
            supp_paths.append(cand)
    supp_entries, supp_problems = load_suppressions(supp_paths)
    supp_applied, supp_expired = apply_suppressions(cands, supp_entries)
    changes = compare_previous(cands, prev) if prev else None
    eco = {}
    lock_dirs = {os.path.basename(r) for _, r in manifest_files}
    for c in comps:
        e = eco.setdefault(c["ecosystem"], dict(total=0, pinned=0, dev=0, direct=0, transitive=0, from_lockfile=0))
        e["total"] += 1
        e["pinned"] += 1 if c["version"] else 0
        e["dev"] += 1 if c["dev"] else 0
        e["direct"] += 1 if c.get("direct") else 0
        e["transitive"] += 1 if c.get("direct") is False else 0
        e["from_lockfile"] += 1 if c.get("kind") == "lock" else 0
    comp_rows = []
    for name, cv in inv["components"].items():
        fs = [c for c in cands if component_of(c["file"]) == name]
        sc = {sv: sum(1 for c in fs if c["severity"] == sv) for sv in R.SEV}
        comp_rows.append(dict(component=name, files=cv["files"], lines=cv["lines"], routes=cv["routes"], manifests=cv["manifests"], iac_files=cv["iac"],
                              candidates=len(fs), critical=sc["Critical"], high=sc["High"], medium=sc["Medium"], low=sc["Low"] + sc["Info"]))
    comp_rows.sort(key=lambda r: (-r["critical"], -r["high"], -r["candidates"], -r["lines"], r["component"]))
    limitations = [
        "Static analysis only. No network calls were made and the live application was not touched; runtime behaviour, deployed configuration, WAF/gateway controls and IdP-side policy were not observed.",
        "Pattern-based detection finds candidates; absence of a hit is not proof a control exists. Each domain still requires manual code reading.",
    ]
    if dbi["available"]:
        age = dbi.get("age_days")
        limitations.append(f"Dependency matching used the bundled OSV advisory snapshot dated {dbi['generated']}"
                           + (f" ({age} days old)" if age is not None else "") + f" with {dbi['advisories']} package advisories across {', '.join(sorted(dbi['ecosystems']))}. "
                           "It matches exact resolved versions only and cannot know about advisories published after that date"
                           + ("; THE SNAPSHOT IS OLDER THAN 90 DAYS: refresh it (tools/build_advisory_db.py) or import a connected scan with --osv-results. " if age is not None and age > 90 else
                              "; refresh it regularly or import a connected scan with --osv-results for the latest data. ")
                           + "Unreviewed or vendor-specific advisories, malware reports and licence issues are not covered.")
    else:
        limitations.append(f"The advisory snapshot (references/advisory-db.json.gz) was not found or unreadable, so dependency matching fell back to a small curated list "
                           f"({sum(len(v) for v in depmod.ADVISORIES.values())} advisories). Dependency CVE coverage is therefore PARTIAL: import a connected scan with --osv-results.")
    if unresolved:
        limitations.append(f"{unresolved} declared dependenc{'y' if unresolved == 1 else 'ies'} have no exact resolved version (version ranges with no lockfile), so they could not be matched against advisories. Commit lockfiles.")
    no_lock = [e for e, v in eco.items() if v["total"] and not v["from_lockfile"] and e != "maven" and e != "nuget"]
    if no_lock:
        limitations.append("No lockfile was found for: " + ", ".join(sorted(no_lock)) + ". Transitive dependencies were not resolved for these ecosystems.")
    limitations.append("Detection depth: line/statement regex rules (multi-line statements are joined) plus intra-file data-flow tracking. "
                       "Python uses AST analysis; JavaScript/TypeScript uses statement-level tracking; Go, Ruby, PHP, Java and C# rely on regex rules only. "
                       "Flows that cross files, frameworks' dependency injection or dynamic dispatch are not followed.")
    if inv["flow_unparsed"]:
        limitations.append(f"{len(inv['flow_unparsed'])} Python file(s) could not be parsed (syntax error or Python 2) so data-flow analysis was skipped for them: "
                           + ", ".join(inv["flow_unparsed"][:8]) + ("..." if len(inv["flow_unparsed"]) > 8 else ""))
    if inv["minified"]:
        limitations.append(f"{len(inv['minified'])} minified file(s) were not scanned (review their unminified sources): " + ", ".join(inv["minified"][:6]) + ("..." if len(inv["minified"]) > 6 else ""))
    if inv["long_line_files"]:
        limitations.append(f"Over-long lines (bundled or generated code) were skipped in {len(inv['long_line_files'])} file(s): " + ", ".join(inv["long_line_files"][:6]) + ("..." if len(inv["long_line_files"]) > 6 else ""))
    if inv["commented_hits"]:
        limitations.append(f"{inv['commented_hits']} rule match(es) inside commented-out code were not reported ({len(inv['commented_files'])} file(s), e.g. "
                           + ", ".join(inv["commented_files"][:4]) + "). Check that the code was not re-enabled or deployed under another name.")
    if inv["excluded"] or excludes:
        limitations.append(f"Excluded from the scan by request ({inv['excluded']} path(s) matched): " + ", ".join(excludes[:10]) + ("..." if len(excludes) > 10 else "") + ". Nothing under these paths was assessed.")
    limitations.append("Secrets are matched by format and context only: whether a credential is still live was not checked (that would need network access), so treat every hit as exposed until proven revoked.")
    if id_note:
        limitations.append("Finding-ID registry: " + id_note + ".")
    for pr in supp_problems:
        limitations.append("Suppression policy: " + pr + ".")
    if supp_applied:
        limitations.append(f"{supp_applied} candidate(s) match a suppression policy entry (accepted risk or known false positive) and are listed separately in the report with their owner and expiry.")
    if supp_expired:
        limitations.append(f"{supp_expired} candidate(s) match a suppression entry that has expired and are treated as open again.")
    if not hist["ran"]:
        limitations.append("Git history was not scanned: " + hist.get("note", ""))
    if getattr(walk, "skipped_large", None):
        limitations.append(f"{len(walk.skipped_large)} file(s) over {a.max_file_kb} KB were not scanned.")
    if suppressed:
        limitations.append("Per-rule display cap reached (additional matching files not listed): " + ", ".join(f"{k} (+{v})" for k, v in suppressed.items()))

    scan = dict(
        meta=dict(tool="appsec-static-audit", version=VERSION, application=app, repository=os.path.basename(root), scanned_at=datetime.now().astimezone().isoformat(timespec="seconds"),
                  git=gm, duration_s=round(time.time() - t0, 1), frameworks=inv["frameworks"],
                  run=dict(scanner_sha256=tool_fingerprint(), advisory_db_sha256=file_sha256(os.path.abspath(a.advisory_db or depmod.DB_PATH)) if dbi.get("available") else "",
                           python=sys.version.split()[0], jobs=inv["jobs"], rules=len(R.RULES), presence_checks=len(R.PRESENCE),
                           options=dict(max_file_kb=a.max_file_kb, max_commits=a.max_commits, git_history=not a.no_git_history, excludes=excludes,
                                        cap_per_rule=a.cap_per_rule, osv_results=bool(a.osv_results), sarif_files=len(a.sarif),
                                        suppression_files=[os.path.basename(p) for p in supp_paths]))),
        inventory=dict(files_scanned=inv["files"], lines=inv["loc"], by_tag=dict(sorted(inv["by_lang"].items())), manifests=inv["manifests"],
                       iac_files=inv["iac"][:200], frameworks=inv["frameworks"], skipped_binary=inv["skipped_binary"],
                       skipped_large=getattr(walk, "skipped_large", []),
                       not_scanned=dict(minified=inv["minified"], long_lines=inv["long_line_files"], flow_unparsed=inv["flow_unparsed"],
                                        commented_rule_matches=inv["commented_hits"]),
                       flow_candidates=inv["flow_hits"]),
        routes=inv["routes"], components=comp_rows, changes=changes,
        suppression=dict(files=[os.path.basename(p) for p in supp_paths], applied=supp_applied, expired=supp_expired, problems=supp_problems),
        dependencies=dict(total=len(comps), ecosystems=eco, sbom="sbom.cdx.json", advisory_db=dbi, unresolved=unresolved,
                          imported_osv=bool(a.osv_results)),
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
