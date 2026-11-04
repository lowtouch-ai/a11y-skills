"""Dependency inventory, offline advisory matching and CycloneDX SBOM generation.

No network access. Vulnerability coverage here is a CURATED, NON-EXHAUSTIVE list of well-known
advisories. For complete CVE coverage, run OSV-Scanner / npm audit / pip-audit in a connected
environment and feed the JSON back with --osv-results.
"""
import json
import os
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# (ecosystem, name) -> list of (fixed_version_exclusive, severity, [ids], note)
ADVISORIES = {
    ("npm", "lodash"): [("4.17.21", "High", ["CVE-2021-23337", "CVE-2020-8203"], "Command injection / prototype pollution")],
    ("npm", "minimist"): [("1.2.6", "Critical", ["CVE-2021-44906"], "Prototype pollution")],
    ("npm", "jsonwebtoken"): [("9.0.0", "High", ["CVE-2022-23529", "CVE-2022-23539", "CVE-2022-23540", "CVE-2022-23541"], "Insecure key/algorithm handling")],
    ("npm", "node-forge"): [("1.3.0", "High", ["CVE-2022-24771", "CVE-2022-24772"], "Signature verification bypass")],
    ("npm", "axios"): [("0.21.2", "High", ["CVE-2021-3749"], "ReDoS")],
    ("npm", "express"): [("4.17.3", "Medium", ["CVE-2022-24999"], "qs prototype pollution (DoS)")],
    ("npm", "ejs"): [("3.1.7", "Critical", ["CVE-2022-29078"], "Template injection -> RCE")],
    ("npm", "handlebars"): [("4.7.7", "Critical", ["CVE-2021-23369"], "RCE via templates")],
    ("npm", "underscore"): [("1.12.1", "High", ["CVE-2021-23358"], "Arbitrary code execution")],
    ("npm", "moment"): [("2.29.4", "High", ["CVE-2022-31129"], "ReDoS / path traversal in locale")],
    ("npm", "serialize-javascript"): [("3.1.0", "High", ["CVE-2020-7660"], "RCE via serialization")],
    ("npm", "xml2js"): [("0.5.0", "Medium", ["CVE-2023-0842"], "Prototype pollution")],
    ("npm", "shelljs"): [("0.8.5", "High", ["CVE-2022-0144"], "Improper privilege management")],
    ("pypi", "pyyaml"): [("5.4", "Critical", ["CVE-2020-14343"], "Arbitrary code execution via full_load")],
    ("pypi", "jinja2"): [("2.11.3", "High", ["CVE-2020-28493"], "ReDoS")],
    ("pypi", "pillow"): [("10.0.1", "High", ["CVE-2023-4863", "CVE-2023-44271"], "libwebp heap overflow / DoS")],
    ("pypi", "requests"): [("2.31.0", "Medium", ["CVE-2023-32681"], "Proxy-Authorization header leak")],
    ("pypi", "urllib3"): [("1.26.5", "High", ["CVE-2021-33503"], "ReDoS")],
    ("pypi", "cryptography"): [("3.3.2", "High", ["CVE-2020-36242"], "Integer overflow in symmetric encryption")],
    ("pypi", "flask"): [("2.2.5", "High", ["CVE-2023-30861"], "Session cookie disclosure via caching proxies")],
    ("pypi", "werkzeug"): [("2.2.3", "High", ["CVE-2023-25577"], "Multipart DoS")],
    ("pypi", "pyjwt"): [("2.4.0", "High", ["CVE-2022-29217"], "Algorithm confusion")],
    ("maven", "org.apache.logging.log4j:log4j-core"): [("2.17.1", "Critical", ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"], "Log4Shell RCE and follow-ons")],
    ("maven", "org.springframework:spring-beans"): [("5.3.18", "Critical", ["CVE-2022-22965"], "Spring4Shell RCE")],
    ("maven", "org.springframework:spring-webmvc"): [("5.3.18", "Critical", ["CVE-2022-22965"], "Spring4Shell RCE")],
    ("maven", "org.apache.commons:commons-text"): [("1.10.0", "Critical", ["CVE-2022-42889"], "Text4Shell RCE")],
    ("maven", "org.yaml:snakeyaml"): [("2.0", "Critical", ["CVE-2022-1471"], "Unsafe deserialization")],
    ("maven", "org.apache.struts:struts2-core"): [("2.5.33", "Critical", ["CVE-2023-50164"], "File upload path traversal -> RCE")],
    ("maven", "commons-collections:commons-collections"): [("3.2.2", "Critical", ["CVE-2015-7501"], "Deserialization gadget")],
    ("maven", "com.alibaba:fastjson"): [("1.2.83", "Critical", ["CVE-2022-25845"], "Deserialization RCE")],
    ("golang", "golang.org/x/crypto"): [("0.17.0", "Medium", ["CVE-2023-48795"], "SSH Terrapin attack")],
    ("golang", "golang.org/x/net"): [("0.17.0", "High", ["CVE-2023-39325", "CVE-2023-44487"], "HTTP/2 rapid reset DoS")],
    ("nuget", "newtonsoft.json"): [("13.0.1", "High", ["CVE-2024-21907"], "DoS via deeply nested JSON")],
}

ABANDONED = {
    ("npm", "request"): "Deprecated and unmaintained since 2020",
    ("npm", "request-promise"): "Deprecated (depends on request)",
    ("npm", "node-uuid"): "Deprecated; use uuid",
    ("npm", "node-sass"): "Deprecated; use sass (Dart Sass)",
    ("npm", "tslint"): "Deprecated; use ESLint",
    ("npm", "babel-eslint"): "Deprecated; use @babel/eslint-parser",
    ("npm", "crypto"): "Deprecated stub; use Node's built-in crypto module",
    ("pypi", "pycrypto"): "Unmaintained since 2013 with known CVEs; use pycryptodome / cryptography",
    ("pypi", "nose"): "Unmaintained; use pytest",
    ("pypi", "python-ldap2"): "Unmaintained",
    ("maven", "log4j:log4j"): "Log4j 1.x is end-of-life (CVE-2019-17571, CVE-2021-4104)",
    ("maven", "commons-httpclient:commons-httpclient"): "End-of-life; use Apache HttpClient 5",
}

LOCKFILES = {"npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"),
             "pypi": ("Pipfile.lock", "poetry.lock", "requirements.txt", "pdm.lock", "uv.lock"),
             "rubygems": ("Gemfile.lock",), "packagist": ("composer.lock",), "golang": ("go.sum",)}


def _vtuple(v):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts[:5]) or (0,)


def version_lt(a, b):
    ta, tb = _vtuple(a), _vtuple(b)
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) < tb + (0,) * (n - len(tb))


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _comp(eco, name, version, spec, file, dev=False, line=0):
    return dict(ecosystem=eco, name=name, version=version, spec=spec, file=file, dev=dev, line=line)


def parse_package_json(path, rel, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for key, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for n, spec in (data.get(key) or {}).items():
            out.append(_comp("npm", n, None, str(spec), rel, dev))
    return out


def parse_package_lock(path, rel, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for key, meta in (data.get("packages") or {}).items():
        if not key:
            continue
        name = key.split("node_modules/")[-1]
        if meta.get("version"):
            out.append(_comp("npm", name, meta["version"], meta["version"], rel, bool(meta.get("dev"))))

    def walk(deps):
        for n, meta in (deps or {}).items():
            if meta.get("version"):
                out.append(_comp("npm", n, meta["version"], meta["version"], rel, bool(meta.get("dev"))))
            walk(meta.get("dependencies"))
    if not data.get("packages"):
        walk(data.get("dependencies"))
    return out


def parse_yarn_lock(path, rel, text):
    out = []
    for m in re.finditer(r'^"?(@?[^@\s"]+)@[^\n]*:\n\s+version\s+"?([^"\n]+)"?', text, re.M):
        out.append(_comp("npm", m.group(1), m.group(2), m.group(2), rel))
    return out


def parse_requirements(path, rel, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.split("#")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            if line.startswith(("git+", "http")):
                out.append(_comp("pypi", line[:80], None, line, rel, line=i))
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|<=|~=|>|<|!=)?\s*([^;\s,]*)", line)
        if m:
            ver = m.group(4) if m.group(3) == "==" else None
            out.append(_comp("pypi", m.group(1).lower().replace("_", "-"), ver, (m.group(3) or "") + (m.group(4) or "") or "*", rel, line=i))
    return out


def parse_pipfile_lock(path, rel, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for sect, dev in (("default", False), ("develop", True)):
        for n, meta in (data.get(sect) or {}).items():
            out.append(_comp("pypi", n.lower(), (meta.get("version") or "").lstrip("="), meta.get("version", "*"), rel, dev))
    return out


def parse_poetry_lock(path, rel, text):
    return [_comp("pypi", m.group(1).lower(), m.group(2), m.group(2), rel)
            for m in re.finditer(r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"', text)]


def parse_pom(path, rel, text):
    out = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    props = {}
    for p in root.findall(f"{ns}properties/*"):
        props[p.tag.replace(ns, "")] = (p.text or "").strip()
    for d in root.iter(f"{ns}dependency"):
        g = (d.findtext(f"{ns}groupId") or "").strip()
        a = (d.findtext(f"{ns}artifactId") or "").strip()
        v = (d.findtext(f"{ns}version") or "").strip()
        m = re.fullmatch(r"\$\{([^}]+)\}", v)
        if m:
            v = props.get(m.group(1), "")
        if a:
            out.append(_comp("maven", f"{g}:{a}", v or None, v or "managed", rel))
    return out


def parse_gradle(path, rel, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(r"(implementation|api|compile|runtimeOnly|compileOnly|testImplementation|annotationProcessor)\s*\(?\s*[\"']([^:\"']+):([^:\"']+):([^\"')]+)[\"']", line)
        if m:
            out.append(_comp("maven", f"{m.group(2)}:{m.group(3)}", m.group(4), m.group(4), rel, m.group(1).startswith("test"), i))
    return out


def parse_go_mod(path, rel, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}/[^\s]+)\s+v([^\s]+)", line)
        if m:
            out.append(_comp("golang", m.group(1), m.group(2), m.group(2), rel, line=i))
    return out


def parse_gemfile_lock(path, rel, text):
    return [_comp("rubygems", m.group(1), m.group(2), m.group(2), rel)
            for m in re.finditer(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][^)]*)\)$", text, re.M)]


def parse_composer_lock(path, rel, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for sect, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(sect) or []:
            out.append(_comp("packagist", p.get("name", ""), (p.get("version") or "").lstrip("v"), p.get("version", ""), rel, dev))
    return out


def parse_csproj(path, rel, text):
    out = []
    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"[^>]*?Version="([^"]+)"', text):
        out.append(_comp("nuget", m.group(1).lower(), m.group(2), m.group(2), rel))
    for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text):
        out.append(_comp("nuget", m.group(1).lower(), m.group(2), m.group(2), rel))
    return out


PARSERS = [
    (lambda n: n == "package.json", parse_package_json),
    (lambda n: n in ("package-lock.json", "npm-shrinkwrap.json"), parse_package_lock),
    (lambda n: n == "yarn.lock", parse_yarn_lock),
    (lambda n: re.fullmatch(r"requirements[\w.\-]*\.txt", n) is not None, parse_requirements),
    (lambda n: n == "Pipfile.lock", parse_pipfile_lock),
    (lambda n: n == "poetry.lock", parse_poetry_lock),
    (lambda n: n == "pom.xml", parse_pom),
    (lambda n: n.endswith((".gradle", ".gradle.kts")), parse_gradle),
    (lambda n: n == "go.mod", parse_go_mod),
    (lambda n: n == "Gemfile.lock", parse_gemfile_lock),
    (lambda n: n == "composer.lock", parse_composer_lock),
    (lambda n: n.endswith(".csproj") or n == "packages.config", parse_csproj),
]


def collect(files):
    """files: iterable of (abs_path, rel_path). Returns component list (deduped)."""
    comps = []
    for ap, rp in files:
        base = os.path.basename(ap)
        for match, parser in PARSERS:
            if match(base):
                comps.extend(parser(ap, rp, _read(ap)))
                break
    seen, out = set(), []
    for c in comps:
        key = (c["ecosystem"], c["name"], c["version"] or c["spec"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def purl(c):
    eco = {"npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "golang", "rubygems": "gem", "packagist": "composer", "nuget": "nuget"}[c["ecosystem"]]
    name = c["name"].replace(":", "/") if eco == "maven" else c["name"]
    return f"pkg:{eco}/{name}" + (f"@{c['version']}" if c["version"] else "")


def sbom(components, app_name, app_version="unknown"):
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "tools": [{"vendor": "appsec-static-audit", "name": "deps.py", "version": "1.0"}],
                     "component": {"type": "application", "name": app_name, "version": app_version}},
        "components": [{"type": "library", "bom-ref": purl(c), "name": c["name"], "version": c["version"] or c["spec"],
                        "purl": purl(c), "scope": "optional" if c["dev"] else "required",
                        "properties": [{"name": "source", "value": c["file"]}]} for c in components],
    }


def analyze(components, root_files, osv_results=None):
    """Return dependency candidate findings (list of dicts, no IDs yet)."""
    findings = []
    names_by_dir = {}
    for c in components:
        names_by_dir.setdefault(os.path.dirname(c["file"]), set()).add(os.path.basename(c["file"]))
    for c in components:
        key = (c["ecosystem"], c["name"].lower())
        if c["version"]:
            for fixed, sev, ids, note in ADVISORIES.get(key, []):
                if version_lt(c["version"], fixed):
                    findings.append(dict(rule="DEP-1", domain="deps", severity=sev, cwe="CWE-1395",
                                         title=f"Known vulnerable dependency: {c['name']} {c['version']}",
                                         file=c["file"], line=c["line"] or 1,
                                         detail=f"{note}. Advisories: {', '.join(ids)}. Fixed in {fixed}.",
                                         fix=f"Upgrade {c['name']} to >= {fixed} (latest supported), regenerate the lockfile and retest.",
                                         confidence="High", owasp="A06", ids=ids))
        if key in ABANDONED:
            findings.append(dict(rule="DEP-2", domain="deps", severity="Medium", cwe="CWE-1104",
                                 title=f"Unmaintained / end-of-life dependency: {c['name']}",
                                 file=c["file"], line=c["line"] or 1, detail=ABANDONED[key],
                                 fix="Replace with a maintained alternative and remove the dependency.",
                                 confidence="High", owasp="A06"))
        spec = c["spec"] or ""
        if c["ecosystem"] == "npm" and not c["version"] and re.search(r"^(\*|latest|x|)$|^(git|https?|github:|file:)", spec):
            findings.append(dict(rule="DEP-3", domain="deps", severity="Medium", cwe="CWE-829",
                                 title=f"Unpinned or non-registry dependency source: {c['name']}@{spec or '*'}",
                                 file=c["file"], line=1, detail="Wildcard, 'latest', git or URL dependency defeats reproducible, reviewable builds.",
                                 fix="Pin to a reviewed version from the registry and commit the lockfile.", confidence="Medium", owasp="A08"))
        if c["ecosystem"] == "pypi" and c["file"].startswith("requirements") or (c["ecosystem"] == "pypi" and os.path.basename(c["file"]).startswith("requirements")):
            if not c["version"]:
                findings.append(dict(rule="DEP-3", domain="deps", severity="Low", cwe="CWE-829",
                                     title=f"Unpinned Python dependency: {c['name']} ({spec})", file=c["file"], line=c["line"] or 1,
                                     detail="No exact version pin; builds are not reproducible and may pull a vulnerable release.",
                                     fix="Pin with == (preferably with --hash) or use a lockfile.", confidence="Medium", owasp="A08"))
    # manifests without lockfiles
    for d, names in names_by_dir.items():
        if "package.json" in names and not names & set(LOCKFILES["npm"]):
            findings.append(dict(rule="DEP-4", domain="deps", severity="Medium", cwe="CWE-1104",
                                 title="npm manifest without a lockfile", file=os.path.join(d, "package.json"), line=1,
                                 detail="Without package-lock.json/yarn.lock the installed tree is not reproducible and cannot be audited.",
                                 fix="Commit the lockfile and install with `npm ci`.", confidence="High", owasp="A08"))
    if osv_results:
        findings.extend(import_osv(osv_results))
    return findings


def import_osv(path):
    """Import an osv-scanner JSON file produced elsewhere (results[].packages[].vulnerabilities[])."""
    out = []
    try:
        data = json.loads(_read(path))
    except ValueError:
        return out
    sevmap = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
    for res in data.get("results", []):
        src = (res.get("source") or {}).get("path", "lockfile")
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            for v in pkg.get("vulnerabilities", []):
                sev = sevmap.get(str((v.get("database_specific") or {}).get("severity", "")).upper(), "High")
                ids = [v.get("id")] + (v.get("aliases") or [])
                out.append(dict(rule="DEP-1", domain="deps", severity=sev, cwe="CWE-1395",
                                title=f"Known vulnerable dependency: {p.get('name')} {p.get('version')}",
                                file=src, line=1, detail=f"{v.get('summary', '')} ({', '.join(i for i in ids if i)}). Source: imported OSV results.",
                                fix="Upgrade to a fixed version listed in the advisory.", confidence="High", owasp="A06", ids=[i for i in ids if i]))
    return out
