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

MANIFEST_LOCKS = {   # manifest name -> lockfiles that make the installed tree reproducible / auditable
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"),
    "Pipfile": ("Pipfile.lock",),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"),
    "Cargo.toml": ("Cargo.lock",),
    "composer.json": ("composer.lock",),
    "Gemfile": ("Gemfile.lock",),
    "go.mod": ("go.sum",),
}
LOCKFILES = {"npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"),
             "pypi": ("Pipfile.lock", "poetry.lock", "requirements.txt", "pdm.lock", "uv.lock"),
             "rubygems": ("Gemfile.lock",), "packagist": ("composer.lock",), "golang": ("go.sum",), "cargo": ("Cargo.lock",)}
LOCK_BASENAMES = {n for v in MANIFEST_LOCKS.values() for n in v} | {"packages.lock.json"}

# ---------------------------------------------------------------------------- version comparison
_PRE = {"dev": -6, "snapshot": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3, "pre": -3, "preview": -3, "rc": -2, "cr": -2, "c": -2}
_POST = {"post": 1, "p": 1, "sp": 1, "patch": 1, "rev": 1, "r": 1}


def _vkey(v):
    """Comparable key for semver / PEP 440 / Maven / RubyGems style versions (pre-releases sort below the release)."""
    v = (v or "").strip().lower().lstrip("v=").split("+")[0]
    v = re.sub(r"^\d+!", "", v)                       # PEP 440 epoch
    parts = re.findall(r"\d+|[a-z]+", v)
    nums, i = [], 0
    while i < len(parts) and parts[i].isdigit():
        nums.append(int(parts[i]))
        i += 1
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    qual, rank = [], None
    for p in parts[i:]:
        if p.isdigit():
            qual.append((rank if rank is not None else 0, int(p)))
            rank = None
        else:
            rank = _PRE.get(p, _POST.get(p, 0))
            qual.append((rank, 0))
    return (tuple(nums), tuple(qual) if qual else ((0, 0),))


def vcmp(a, b):
    ka, kb = _vkey(a), _vkey(b)
    na, nb = ka[0], kb[0]
    n = max(len(na), len(nb))
    na, nb = na + (0,) * (n - len(na)), nb + (0,) * (n - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    qa, qb = ka[1], kb[1]
    m = max(len(qa), len(qb))
    qa, qb = qa + ((0, 0),) * (m - len(qa)), qb + ((0, 0),) * (m - len(qb))
    return 0 if qa == qb else (-1 if qa < qb else 1)


def version_lt(a, b):
    return vcmp(a, b) < 0


# ---------------------------------------------------------------------------- advisory database
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "references", "advisory-db.json.gz")
_DB = {}


def load_db(path=None):
    """Load the bundled OSV snapshot (built by tools/build_advisory_db.py). Returns dict or None."""
    path = os.path.abspath(path or DB_PATH)
    if path in _DB:
        return _DB[path]
    db = None
    try:
        import gzip
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            db = json.load(fh)
    except (OSError, ValueError, EOFError):
        db = None
    _DB[path] = db
    return db


def db_info(db):
    if not db:
        return dict(available=False)
    gen = db.get("generated", "")
    age = None
    try:
        age = (datetime.now(timezone.utc) - datetime.strptime(gen, "%Y-%m-%d").replace(tzinfo=timezone.utc)).days
    except ValueError:
        pass
    return dict(available=True, generated=gen, age_days=age, source=db.get("source", ""),
                ecosystems={e: len(p) for e, p in (db.get("ecosystems") or {}).items()},
                advisories=sum(len(v) for p in (db.get("ecosystems") or {}).values() for v in p.values()))


def _norm_name(eco, name):
    n = name.strip()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", n.lower())
    if eco in ("npm", "nuget", "packagist", "rubygems", "cargo"):
        return n.lower()
    return n


def _in_ranges(version, entry):
    """Is `version` affected by this db entry? Returns (affected, fixed_versions_list)."""
    ids, sev, summary, ranges = entry[0], entry[1], entry[2], entry[3]
    if len(entry) > 4 and not ranges:
        return (version in entry[4] or version.lstrip("v") in entry[4]), []
    for intro, fixed, last in ranges:
        lo = intro in ("0", "", None) or vcmp(version, intro) >= 0
        if not lo:
            continue
        if fixed is not None and vcmp(version, fixed) >= 0:
            continue
        if last is not None and vcmp(version, last) > 0:
            continue
        return True, [fixed] if fixed else []
    return False, []


def db_matches(db, eco, name, version):
    """All snapshot advisories affecting name@version -> list of dict(ids, severity, summary, fixed)."""
    out = []
    for entry in ((db.get("ecosystems") or {}).get(eco) or {}).get(_norm_name(eco, name), []):
        hit, fixed = _in_ranges(version, entry)
        if hit:
            out.append(dict(ids=entry[0], severity=entry[1], summary=entry[2], fixed=fixed))
    return out


REQ_NAME_RX = re.compile(r"[\w.\-]*(requirements|constraints)[\w.\-]*\.(txt|in)", re.I)
REQ_DIR_RX = re.compile(r"(^|/)requirements?(\.d)?/[^/]+\.(txt|in)$", re.I)


def is_requirements_file(path):
    """pip requirement / constraint files under any naming convention: requirements.txt, dev-requirements.in, prod_requirements.txt,
    constraints.txt, requirements/base.txt ..."""
    p = (path or "").replace("\\", "/")
    return bool(REQ_NAME_RX.fullmatch(os.path.basename(p)) or REQ_DIR_RX.search(p))


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _comp(eco, name, version, spec, file, dev=False, line=0, direct=None, raw=""):
    return dict(ecosystem=eco, name=name, version=version, spec=spec, file=file, dev=dev, line=line, direct=direct, raw=raw)


def parse_package_json(path, rel, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for key, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for n, spec in (data.get(key) or {}).items():
            spec = str(spec)
            exact = re.fullmatch(r"=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?)", spec.strip())   # "4.17.15" is a pin, "^4.17.15" is a range
            m_line = re.search(r'^[ \t]*"' + re.escape(n) + r'"\s*:\s*"[^"\n]*"', text, re.M)
            out.append(_comp("npm", n, exact.group(1) if exact else None, spec, rel, dev,
                             line=(text.count("\n", 0, m_line.start()) + 1) if m_line else 0, raw=m_line.group(0).strip() if m_line else f'"{n}": "{spec}"'))
    return out


def parse_package_lock(path, rel, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    root_pkg = (data.get("packages") or {}).get("") or {}
    declared = set((root_pkg.get("dependencies") or {})) | set((root_pkg.get("devDependencies") or {})) | set((root_pkg.get("optionalDependencies") or {}))
    for key, meta in (data.get("packages") or {}).items():
        if not key:
            continue
        name = key.split("node_modules/")[-1]
        if meta.get("version"):
            top = key.count("node_modules/") == 1
            out.append(_comp("npm", name, meta["version"], meta["version"], rel, bool(meta.get("dev")),
                             direct=(top and name in declared) if declared else None))

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
    for m in re.finditer(r'^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:?\s+"?([^"\n]+)"?', text, re.M):
        out.append(_comp("npm", m.group(1), m.group(2), m.group(2), rel))
    return out


def parse_requirements(path, rel, text):
    out = []
    for i, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.split(" #")[0].split("\t#")[0].strip()
        if line.startswith("#"):
            continue
        if not line or line.startswith("-") or re.match(r"(git\+|hg\+|svn\+|bzr\+|https?://|file:|ftp://)", line):
            if re.match(r"(git\+|hg\+|svn\+|bzr\+|https?://|file:|ftp://)", line):
                out.append(_comp("pypi", line[:80], None, line, rel, line=i, raw=raw_line.strip()[:200]))
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|<=|~=|>|<|!=)?\s*([^;\s,]*)", line)
        if m:
            ver = m.group(4) if m.group(3) == "==" else None
            out.append(_comp("pypi", m.group(1).lower().replace("_", "-"), ver, (m.group(3) or "") + (m.group(4) or "") or "*", rel, line=i, raw=raw_line.strip()[:200]))
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
    """poetry.lock / uv.lock / pdm.lock: [[package]] blocks with name and version."""
    return [_comp("pypi", re.sub(r"[-_.]+", "-", m.group(1).lower()), m.group(2), m.group(2), rel)
            for m in re.finditer(r'\[\[package\]\]\s*\n(?:[^\n\[]*\n)*?name\s*=\s*"([^"]+)"\s*\n(?:[^\n\[]*\n)*?version\s*=\s*"([^"]+)"', text)]


def parse_cargo_lock(path, rel, text):
    out = []
    for blk in re.split(r"\n\s*\n", text):
        n = re.search(r'^name\s*=\s*"([^"]+)"', blk, re.M)
        v = re.search(r'^version\s*=\s*"([^"]+)"', blk, re.M)
        if n and v and re.search(r'^source\s*=', blk, re.M):      # path/workspace crates have no source
            out.append(_comp("cargo", n.group(1), v.group(1), v.group(1), rel))
    return out


def parse_go_sum(path, rel, text):
    out, seen = [], set()
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"(\S+)\s+v(\S+?)(/go\.mod)?\s+h1:", line)
        if m and not m.group(3) and (m.group(1), m.group(2)) not in seen:
            seen.add((m.group(1), m.group(2)))
            out.append(_comp("golang", m.group(1), m.group(2), m.group(2), rel, line=i))
    return out


def parse_pnpm_lock(path, rel, text):
    out, seen = [], set()
    in_pk = False
    for line in text.splitlines():
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_pk = True
            continue
        if in_pk and re.match(r"^\S", line):
            in_pk = False
        if not in_pk:
            continue
        m = re.match(r"^\s{2}['\"]?/?((?:@[^/@\s'\"]+/)?[^@/\s'\"]+)[@/](\d[^:(\s'\"_]*)[^:]*['\"]?:\s*$", line)
        if m and (m.group(1), m.group(2)) not in seen:
            seen.add((m.group(1), m.group(2)))
            out.append(_comp("npm", m.group(1), m.group(2), m.group(2), rel))
    return out


def parse_nuget_lock(path, rel, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for _, pkgs in (data.get("dependencies") or {}).items():
        for n, meta in (pkgs or {}).items():
            if meta.get("resolved"):
                out.append(_comp("nuget", n.lower(), meta["resolved"], meta["resolved"], rel, direct=(meta.get("type") == "Direct")))
    return out


_LOCK_INDEX = {
    "package-lock.json": r'^\s*"(?:[^"]*/)?node_modules/(?P<n>@[^"/]+/[^"/]+|[^"/@][^"/]*)"\s*:',
    "npm-shrinkwrap.json": r'^\s*"(?:[^"]*/)?node_modules/(?P<n>@[^"/]+/[^"/]+|[^"/@][^"/]*)"\s*:',
    "yarn.lock": r'^"?(?P<n>@?[^@\s"]+)@',
    "pnpm-lock.yaml": r"^\s+['\"]?/?(?P<n>(?:@[^/@\s'\"]+/)?[^@/\s'\"]+)[@/]\d",
    "poetry.lock": r'^name\s*=\s*"(?P<n>[^"]+)"', "uv.lock": r'^name\s*=\s*"(?P<n>[^"]+)"', "pdm.lock": r'^name\s*=\s*"(?P<n>[^"]+)"',
    "Cargo.lock": r'^name\s*=\s*"(?P<n>[^"]+)"',
    "composer.lock": r'^\s*"name"\s*:\s*"(?P<n>[^"]+)"',
    "Gemfile.lock": r"^\s{4}(?P<n>[A-Za-z0-9_.\-]+) \(",
    "packages.lock.json": r'^\s*"(?P<n>[^"]+)"\s*:\s*\{',
    "Pipfile.lock": r'^\s*"(?P<n>[^"]+)"\s*:\s*\{',
}


def _norm_pkg(n):
    return re.sub(r"[-_.]+", "-", n.lower())


def _locate_in_lock(base, text, comps):
    """One pass over a lockfile: remember the first line that declares each package, so findings can cite the real line."""
    pat = _LOCK_INDEX.get(base)
    if not pat or not comps or not any(not c.get("line") for c in comps):
        return
    rx = re.compile(pat, re.I)
    idx = {}
    for i, line in enumerate(text.split("\n"), 1):
        m = rx.match(line)
        if m:
            idx.setdefault(_norm_pkg(m.group("n")), (i, line.strip()[:160]))
    for c in comps:
        if not c.get("line"):
            hit = idx.get(_norm_pkg(c["name"].split("/")[-1] if c["ecosystem"] == "golang" else c["name"]))
            if hit:
                c["line"], c["raw"] = hit[0], c.get("raw") or hit[1]


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
    tlines = text.split("\n")
    cursor = {}
    for d in root.iter(f"{ns}dependency"):
        g = (d.findtext(f"{ns}groupId") or "").strip()
        a = (d.findtext(f"{ns}artifactId") or "").strip()
        v = (d.findtext(f"{ns}version") or "").strip()
        m = re.fullmatch(r"\$\{([^}]+)\}", v)
        if m:
            v = props.get(m.group(1), "")
        if a:
            ln, raw = 0, ""
            start = cursor.get(a, 0)
            for i in range(start, len(tlines)):
                if re.search(r"<artifactId>\s*" + re.escape(a) + r"\s*</artifactId>", tlines[i]):
                    ln, raw, cursor[a] = i + 1, tlines[i].strip()[:160], i + 1
                    break
            out.append(_comp("maven", f"{g}:{a}", v or None, v or "managed", rel, line=ln, raw=raw))
    return out


def parse_gradle(path, rel, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(r"(implementation|api|compile|runtimeOnly|compileOnly|testImplementation|annotationProcessor)\s*\(?\s*[\"']([^:\"']+):([^:\"']+):([^\"')]+)[\"']", line)
        if m:
            out.append(_comp("maven", f"{m.group(2)}:{m.group(3)}", m.group(4), m.group(4), rel, m.group(1).startswith("test"), i, raw=line.strip()[:160]))
    return out


def parse_go_mod(path, rel, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}/[^\s]+)\s+v([^\s]+)", line)
        if m:
            out.append(_comp("golang", m.group(1), m.group(2), m.group(2), rel, line=i, raw=line.strip()[:160]))
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
        out.append(_comp("nuget", m.group(1).lower(), m.group(2), m.group(2), rel, line=text.count("\n", 0, m.start()) + 1, raw=" ".join(m.group(0).split())[:160]))
    for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text):
        out.append(_comp("nuget", m.group(1).lower(), m.group(2), m.group(2), rel, line=text.count("\n", 0, m.start()) + 1, raw=" ".join(m.group(0).split())[:160]))
    return out


PARSERS = [
    (lambda n: n == "package.json", parse_package_json),
    (lambda n: n in ("package-lock.json", "npm-shrinkwrap.json"), parse_package_lock),
    (lambda n: n == "yarn.lock", parse_yarn_lock),
    (lambda n: REQ_NAME_RX.fullmatch(n) is not None, parse_requirements),
    (lambda n: n == "Pipfile.lock", parse_pipfile_lock),
    (lambda n: n in ("poetry.lock", "uv.lock", "pdm.lock"), parse_poetry_lock),
    (lambda n: n == "Cargo.lock", parse_cargo_lock),
    (lambda n: n == "go.sum", parse_go_sum),
    (lambda n: n == "pnpm-lock.yaml", parse_pnpm_lock),
    (lambda n: n == "packages.lock.json", parse_nuget_lock),
    (lambda n: n == "pom.xml", parse_pom),
    (lambda n: n.endswith((".gradle", ".gradle.kts")), parse_gradle),
    (lambda n: n == "go.mod", parse_go_mod),
    (lambda n: n == "Gemfile.lock", parse_gemfile_lock),
    (lambda n: n == "composer.lock", parse_composer_lock),
    (lambda n: n.endswith(".csproj") or n == "packages.config", parse_csproj),
]


def collect(files):
    """files: iterable of (abs_path, rel_path). Returns component list (deduped, lock data preferred over manifest ranges)."""
    comps = []
    for ap, rp in files:
        base = os.path.basename(ap)
        parser = next((p for m, p in PARSERS if m(base)), None)
        if parser is None and REQ_DIR_RX.search(rp.replace("\\", "/")):
            parser = parse_requirements
        if parser is None:
            continue
        kind = "lock" if base in LOCK_BASENAMES and base != "requirements.txt" else "manifest"
        text = _read(ap)
        found = parser(ap, rp, text)
        if kind == "lock":
            _locate_in_lock(base, text, found)
        for c in found:
            c["kind"] = kind
            comps.append(c)
    locked = {(c["ecosystem"], c["name"].lower()) for c in comps if c["kind"] == "lock" and c["version"]}
    declared = {(c["ecosystem"], c["name"].lower()) for c in comps if c["kind"] == "manifest"}
    eco_has_lock = {e for e, _ in locked}
    seen, out = set(), []
    for c in comps:
        key = (c["ecosystem"], c["name"].lower())
        if c["kind"] == "manifest" and not c["version"] and key in locked:
            continue                      # the lockfile resolves this range to an exact version
        if c["kind"] == "lock" and c["direct"] is None and c["ecosystem"] in eco_has_lock and declared:
            c["direct"] = key in declared
        if c["kind"] == "manifest" and c["direct"] is None:
            c["direct"] = True
        k2 = (c["ecosystem"], c["name"], c["version"] or c["spec"])
        if k2 not in seen:
            seen.add(k2)
            out.append(c)
    return out


def purl(c):
    eco = {"npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "golang", "rubygems": "gem", "packagist": "composer", "nuget": "nuget", "cargo": "cargo"}[c["ecosystem"]]
    name = c["name"].replace(":", "/") if eco == "maven" else c["name"]
    return f"pkg:{eco}/{name}" + (f"@{c['version']}" if c["version"] else "")


def sbom(components, app_name, app_version="unknown"):
    """CycloneDX 1.5. A package declared in several files or repositories is one component with one `source` property per declaration."""
    merged = {}
    for c in components:
        ref = purl(c)
        comp = merged.get(ref)
        if comp is None:
            comp = merged[ref] = {"type": "library", "bom-ref": ref, "name": c["name"], "version": c["version"] or c["spec"], "purl": ref,
                                  "scope": "optional" if c["dev"] else "required", "properties": []}
            if c.get("direct") is not None:
                comp["properties"].append({"name": "dependency-type", "value": "direct" if c.get("direct") else "transitive"})
        elif not c["dev"]:
            comp["scope"] = "required"
        src = {"name": "source", "value": c["file"]}
        if src not in comp["properties"]:
            comp["properties"].insert(0, src)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "tools": [{"vendor": "appsec-static-audit", "name": "deps.py", "version": "1.0"}],
                     "component": {"type": "application", "name": app_name, "version": app_version}},
        "components": list(merged.values()),
    }


SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _sev_down(sv):
    return SEV_ORDER[min(SEV_ORDER.index(sv) + 1, len(SEV_ORDER) - 1)]


def _merge_vulns(into, vulns):
    """Merge advisory dicts, de-duplicating by any shared id/alias (a GHSA and its CVE are the same advisory)."""
    for v in vulns:
        ids = set(v["ids"])
        for have in into:
            if ids & set(have["ids"]):
                have["ids"] = list(dict.fromkeys(have["ids"] + v["ids"]))
                have["fixed"] = list(dict.fromkeys(have["fixed"] + v["fixed"]))
                if SEV_ORDER.index(v["severity"]) < SEV_ORDER.index(have["severity"]):
                    have["severity"] = v["severity"]
                break
        else:
            into.append(dict(v))


def _upgrade_target(version, vulns):
    """Lowest version that clears every advisory that has a fix, and the ids that have no fix."""
    targets, unfixed = [], []
    for v in vulns:
        fx = [f for f in v["fixed"] if vcmp(f, version) > 0]
        if fx:
            targets.append(min(fx, key=lambda x: _vkey(x)))
        else:
            unfixed.append(v["ids"][0])
    return (max(targets, key=lambda x: _vkey(x)) if targets else None), unfixed


def analyze(components, root_files, osv_results=None, db=None):
    """Return dependency candidate findings (list of dicts, no IDs yet)."""
    findings = []
    unpinned = {}
    by_comp = {}   # (eco, normalized name, version) -> dict(comp, vulns, sources)
    unresolved = 0
    for c in components:
        key = (c["ecosystem"], c["name"].lower())
        if c["version"]:
            vulns = []
            if db and (db.get("ecosystems") or {}).get(c["ecosystem"]):
                vulns = db_matches(db, c["ecosystem"], c["name"], c["version"])
            else:   # no snapshot: curated fallback
                for fixed, sev, ids, note in ADVISORIES.get(key, []):
                    if version_lt(c["version"], fixed):
                        vulns.append(dict(ids=ids, severity=sev, summary=note, fixed=[fixed]))
            if vulns:
                ent = by_comp.setdefault((c["ecosystem"], _norm_name(c["ecosystem"], c["name"]), c["version"], c.get("repo", "")), dict(comp=c, vulns=[]))
                _merge_vulns(ent["vulns"], vulns)
        elif c["ecosystem"] in ("npm", "pypi", "maven", "golang", "rubygems", "packagist", "nuget", "cargo") and c.get("kind") != "lock" and not (c["spec"] or "").startswith(("git", "http", "file", "github:")):
            unresolved += 1
        if key in ABANDONED:
            findings.append(dict(rule="DEP-2", domain="deps", severity="Medium", cwe="CWE-1104",
                                 title=f"Unmaintained / end-of-life dependency: {c['name']}",
                                 file=c["file"], line=c["line"] or 1, detail=ABANDONED[key],
                                 locations=[dict(line=c["line"] or 1, snippet=c.get("raw") or f"{c['name']} {c['spec']}")],
                                 fix="Replace with a maintained alternative and remove the dependency.",
                                 confidence="High", owasp="A06"))
        spec = c["spec"] or ""
        if (c["ecosystem"] == "npm" and not c["version"] and re.search(r"^(\*|latest|x|)$|^(git|https?|github:|file:)", spec)) or \
                (c["ecosystem"] == "pypi" and is_requirements_file(c["file"]) and not c["file"].lower().endswith(".in") and not c["version"]):
            unpinned.setdefault((c["file"], c["ecosystem"]), []).append((c["name"], spec or "*", c["line"] or 1, c.get("raw") or f"{c['name']} {spec or '*'}"))

    # imported connected-scan results (osv-scanner JSON) merge into the same per-component findings
    if osv_results:
        for (eco, name, ver, src, vulns) in import_osv(osv_results):
            ent = by_comp.setdefault((eco, _norm_name(eco, name), ver, ""), dict(comp=dict(ecosystem=eco, name=name, version=ver, file=src, line=1, dev=False, direct=None), vulns=[]))
            ent["imported"] = True
            _merge_vulns(ent["vulns"], vulns)

    for (eco, _, ver, _repo), ent in by_comp.items():
        c, vulns = ent["comp"], ent["vulns"]
        vulns.sort(key=lambda v: SEV_ORDER.index(v["severity"]))
        sev = vulns[0]["severity"]
        notes = []
        if c.get("dev"):
            sev = _sev_down(sev)
            notes.append("dev-only dependency: severity lowered one level; it does not ship to production unless the build is deployed with dev packages")
        if c.get("direct") is False:
            notes.append("transitive dependency: upgrade the direct dependency that pulls it in (or add an override/resolution)")
        target, unfixed = _upgrade_target(ver, vulns)
        top = "; ".join(f"{v['ids'][0]} ({v['severity']}): {v['summary']}" for v in vulns[:5]) + (f"; +{len(vulns) - 5} more" if len(vulns) > 5 else "")
        all_ids = list(dict.fromkeys(i for v in vulns for i in v["ids"]))[:24]
        fix = (f"Upgrade {c['name']} to >= {target}" + (f" (no fixed release listed yet for {', '.join(unfixed[:4])}: assess exposure or replace the package)" if unfixed else "")
               if target else f"No fixed release is listed for {c['name']} {ver}: assess exposure, apply vendor mitigations or replace the package")
        fix += ", regenerate the lockfile and retest."
        findings.append(dict(rule="DEP-1", domain="deps", severity=sev, cwe="CWE-1395",
                             title=f"Known vulnerable dependency: {c['name']} {ver} ({len(vulns)} advisor{'y' if len(vulns) == 1 else 'ies'})",
                             file=c["file"], line=c.get("line") or 1,
                             locations=[dict(line=c.get("line") or 1, snippet=c.get("raw") or f"{c['name']} {ver} (resolved version from {os.path.basename(c['file'])})")],
                             detail=f"{top}. Matched by exact version against the {'imported OSV results and ' if ent.get('imported') else ''}advisory snapshot. "
                                    + (" ".join(n + "." for n in notes)),
                             fix=fix, confidence="High", owasp="A06", ids=all_ids))
    for (f, eco), items in unpinned.items():
        names = ", ".join(f"{n} ({sp})" for n, sp, _, _ in items[:15]) + ("..." if len(items) > 15 else "")
        findings.append(dict(rule="DEP-3", domain="deps", severity="Medium" if eco == "npm" else "Low", cwe="CWE-829",
                             title=f"{len(items)} unpinned or non-registry {eco} dependenc{'y' if len(items) == 1 else 'ies'} in {os.path.basename(f)}",
                             file=f, line=items[0][2],
                             detail=f"No exact version pin (or git/URL source): {names}. Builds are not reproducible and may pull a vulnerable release.",
                             fix="Pin exact versions (preferably with hashes) or commit a lockfile, and install with `npm ci` / `pip install --require-hashes`.",
                             confidence="Medium", owasp="A08",
                             locations=[dict(line=ln, snippet=raw) for _n, _sp, ln, raw in items[:25]]))

    # manifests without a lockfile in the same directory (the installed tree, incl. transitive packages, cannot be audited)
    names_by_dir, abs_of = {}, {}
    for ap, rel in root_files:
        names_by_dir.setdefault(os.path.dirname(rel), set()).add(os.path.basename(rel))
        abs_of[rel] = ap
    has_deps = {
        "package.json": lambda t: bool(re.search(r'"(dependencies|devDependencies)"\s*:\s*\{\s*"', t)),
        "pyproject.toml": lambda t: bool(re.search(r"(?m)^\s*(dependencies\s*=\s*\[\s*[\"']|\[tool\.poetry\.dependencies\])", t)),
        "Cargo.toml": lambda t: bool(re.search(r"(?m)^\[(dependencies|dev-dependencies|build-dependencies)\]\s*\n\s*\w", t)),
        "composer.json": lambda t: bool(re.search(r'"require(-dev)?"\s*:\s*\{\s*"', t)),
        "go.mod": lambda t: bool(re.search(r"(?m)^\s*(require\s+\S+\s+v|\S+\.\S+/\S+\s+v\d)", t)),
        "Pipfile": lambda t: bool(re.search(r"(?m)^\[packages\]\s*\n\s*\w", t)),
        "Gemfile": lambda t: bool(re.search(r"(?m)^\s*gem\s+[\"']", t)),
    }
    for d, names in sorted(names_by_dir.items()):
        for manifest, locks in MANIFEST_LOCKS.items():
            if manifest in names and not names & set(locks):
                rel = os.path.join(d, manifest)
                if not has_deps.get(manifest, lambda t: True)(_read(abs_of.get(rel, ""))):
                    continue
                findings.append(dict(rule="DEP-4", domain="deps", severity="Medium", cwe="CWE-1104",
                                     title=f"{manifest} without a lockfile ({', '.join(locks[:3])})", file=rel, line=1,
                                     locations=[dict(line=1, snippet=f"{manifest} found in {d or '.'}; none of {', '.join(locks[:4])} alongside it")],
                                     detail="Without a lockfile the installed tree (including transitive packages) is not reproducible, so it cannot be matched against advisories exactly.",
                                     fix="Generate and commit the lockfile and install from it (`npm ci`, `poetry install`, `uv sync --frozen`, `cargo build --locked`, `composer install`).",
                                     confidence="High", owasp="A08"))
    findings.extend(scan_manifests(root_files, components))
    findings.append(dict(rule="_DEPSTAT", unresolved=unresolved))
    return findings


def import_osv(path):
    """Import an osv-scanner JSON file produced elsewhere. -> list of (ecosystem, name, version, source_file, [vuln dicts])."""
    out = []
    try:
        data = json.loads(_read(path))
    except ValueError:
        return out
    ecomap = {"npm": "npm", "pypi": "pypi", "maven": "maven", "go": "golang", "rubygems": "rubygems", "packagist": "packagist", "nuget": "nuget", "crates.io": "cargo"}
    sevmap = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
    for res in data.get("results", []):
        src = (res.get("source") or {}).get("path", "lockfile")
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            eco = ecomap.get(str(p.get("ecosystem", "")).split(":")[0].lower())
            if not eco or not p.get("name") or not p.get("version"):
                continue
            vulns = []
            for v in pkg.get("vulnerabilities", []):
                sev = sevmap.get(str((v.get("database_specific") or {}).get("severity", "")).upper(), "High")
                ids = [i for i in [v.get("id")] + (v.get("aliases") or []) if i]
                fixed = []
                for aff in v.get("affected", []):
                    for r in aff.get("ranges", []):
                        fixed += [ev["fixed"] for ev in r.get("events", []) if "fixed" in ev]
                vulns.append(dict(ids=ids, severity=sev, summary=(v.get("summary") or "")[:140], fixed=list(dict.fromkeys(fixed))))
            if vulns:
                out.append((eco, p["name"], p["version"], src, vulns))
    return out


# ---------------------------------------------------------------------------- supply-chain checks
POPULAR = {
    "npm": """react react-dom lodash express axios moment chalk commander debug request async underscore bluebird jquery vue angular webpack
        babel typescript eslint prettier jest mocha chai uuid dotenv cors body-parser mongoose mongodb mysql mysql2 redis passport jsonwebtoken
        bcrypt bcryptjs socket.io ws yargs minimist glob rimraf mkdirp fs-extra node-fetch cross-env nodemon rxjs tslib core-js classnames
        prop-types redux react-redux next nuxt vite rollup sass less postcss autoprefixer cheerio puppeteer colors semver inquirer ora
        winston morgan helmet multer nodemailer sequelize knex pg sqlite3 handlebars ejs pug marked highlight.js date-fns dayjs ramda immer zod joi""".split(),
    "pypi": """requests numpy pandas flask django scipy matplotlib pillow pytest boto3 botocore urllib3 setuptools six pyyaml cryptography
        jinja2 sqlalchemy psycopg2 pymysql redis celery click certifi idna charset-normalizer pydantic fastapi uvicorn gunicorn httpx aiohttp
        beautifulsoup4 lxml scikit-learn tensorflow torch keras opencv-python selenium paramiko pycryptodome pyjwt bcrypt tqdm rich colorama
        attrs packaging pip wheel virtualenv tox black flake8 mypy pylint isort docutils sphinx markdown jsonschema simplejson ujson python-dateutil
        pytz tzdata toml tomli typing-extensions werkzeug itsdangerous markupsafe openpyxl xlrd xlsxwriter pymongo mongoengine docker kubernetes""".split(),
}
POPULAR_SET = {e: set(v) for e, v in POPULAR.items()}


def _edit1(a, b):
    """True if a and b differ by exactly one insertion, deletion, substitution or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        d = [i for i in range(len(a)) if a[i] != b[i]]
        return len(d) == 1 or (len(d) == 2 and d[1] == d[0] + 1 and a[d[0]] == b[d[1]] and a[d[1]] == b[d[0]])
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


# established packages whose names legitimately sit one edit away from a more popular one
KNOWN_LOOKALIKES = {"markdown2", "psycopg", "psycopg2", "psycopg3", "python-jose", "pyjwt", "mysqlclient", "pymysql", "pytest-cov", "pytest-mock",
                    "pytest-asyncio", "flask-cors", "flask-login", "flask-sqlalchemy", "django-cors-headers", "lodash-es", "react-is", "vue-router",
                    "vue-loader", "core-js-pure", "dotenv-expand", "dotenv-flow", "cross-fetch", "node-fetch-native", "ts-node", "socket.io-client"}


def _squat_of(eco, name):
    n = name.lower()
    pop = POPULAR_SET.get(eco)
    if not pop or n in pop or n in KNOWN_LOOKALIKES or n.startswith("@") or len(n) < 5:
        return None
    if any(re.fullmatch(re.escape(p) + r"\d{1,2}", n) for p in pop):       # markdown2, pillow3: a major-version style suffix is not a typo
        return None
    flat = re.sub(r"[-_.]", "", n)
    for p in pop:
        if len(p) < 5:
            continue
        if _edit1(n, p) or (flat == re.sub(r"[-_.]", "", p) and n != p):
            return p
    return None


LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
SUSPICIOUS_SCRIPT = re.compile(r"(?i)\b(curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin)\b|https?://|\bnode\s+-e\b|\beval\b|base64|powershell|\bnc\s+-|/dev/tcp|\|\s*(ba)?sh\b|\brm\s+-rf\s+[~/]")


def scan_manifests(root_files, components):
    """Typosquat, install-script, insecure-registry and lockfile-integrity checks (static, offline)."""
    out = []
    for ap, rel in root_files:
        base = os.path.basename(ap)
        text = None
        if base == "package.json":
            text = _read(ap)
            try:
                data = json.loads(text)
            except ValueError:
                continue
            for k, cmd in (data.get("scripts") or {}).items():
                if k in LIFECYCLE and isinstance(cmd, str) and SUSPICIOUS_SCRIPT.search(cmd):
                    out.append(dict(rule="DEP-6", domain="deps", severity="High", cwe="CWE-506",
                                    title=f"npm lifecycle script '{k}' downloads or executes remote/obfuscated code", file=rel, line=1,
                                    detail=f"`{k}`: {cmd[:160]}. Install scripts run automatically on every `npm install`, including in CI, and are the usual vector for malicious or hijacked packages.",
                                    fix="Remove the script or replace it with a pinned, checksum-verified local step; install with `--ignore-scripts` in CI and review what runs.",
                                    confidence="Medium", owasp="A08"))
        elif base in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
            text = _read(ap)
            bad = [m.start() for m in re.finditer(r'(?:"resolved":\s*"|resolved\s+"?|tarball:\s*)http://', text)]
            if bad:
                out.append(dict(rule="DEP-7", domain="deps", severity="High", cwe="CWE-494",
                                title=f"Lockfile resolves packages over plain HTTP ({len(bad)} entr{'y' if len(bad) == 1 else 'ies'})", file=rel, line=text.count("\n", 0, bad[0]) + 1,
                                detail="Packages fetched over http:// can be replaced in transit; integrity hashes are the only remaining protection.",
                                fix="Regenerate the lockfile against an https registry URL and verify integrity hashes.", confidence="High", owasp="A08"))
            if base in ("package-lock.json", "npm-shrinkwrap.json"):
                try:
                    pk = (json.loads(text).get("packages") or {})
                except ValueError:
                    pk = {}
                hosts = {}
                for k, meta in pk.items():
                    r = meta.get("resolved") or ""
                    m = re.match(r"https?://([^/]+)/", r)
                    if m and not r.startswith("https://registry.npmjs.org/") and not r.startswith("https://registry.yarnpkg.com/"):
                        hosts[m.group(1)] = hosts.get(m.group(1), 0) + 1
                    if r and "integrity" not in meta and not meta.get("link"):
                        hosts["(no integrity hash)"] = hosts.get("(no integrity hash)", 0) + 1
                if hosts:
                    out.append(dict(rule="DEP-7", domain="deps", severity="Medium", cwe="CWE-494",
                                    title="Lockfile contains packages from non-default hosts or without integrity hashes", file=rel, line=1,
                                    detail="Hosts / gaps: " + ", ".join(f"{h} ({n})" for h, n in sorted(hosts.items(), key=lambda x: -x[1])[:6]) + ". Confirm these are your private registry and that integrity is enforced.",
                                    fix="Resolve everything through one trusted registry, keep integrity fields, and block unexpected hosts with a registry allowlist.", confidence="Low", owasp="A08"))
        elif base in (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini") or is_requirements_file(rel):
            text = _read(ap)
            for i, line in enumerate(text.splitlines(), 1):
                ln = line.strip()
                if not ln or ln.startswith(("#", ";")):
                    continue
                if re.search(r"(?i)strict-ssl\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED|trusted-host|--trusted-host|enableStrictSsl:\s*false", ln):
                    out.append(dict(rule="DEP-8", domain="deps", severity="High", cwe="CWE-295", title=f"Package-manager TLS verification weakened in {base}", file=rel, line=i,
                                    detail=ln[:160], fix="Remove the setting; trust a private CA through the manager's CA-bundle option instead of disabling checks.", confidence="High", owasp="A02"))
                elif re.search(r"(?i)(registry|index-url|extra-index-url|npmRegistryServer)\s*[=: ]\s*\"?http://", ln):
                    out.append(dict(rule="DEP-8", domain="deps", severity="High", cwe="CWE-319", title=f"Package registry configured over plain HTTP in {base}", file=rel, line=i,
                                    detail=ln[:160], fix="Use an https registry URL.", confidence="High", owasp="A02"))
                elif re.search(r"(?i)^--extra-index-url|^extra-index-url", ln):
                    out.append(dict(rule="DEP-8", domain="deps", severity="Medium", cwe="CWE-427", title=f"Extra package index in {base} (dependency-confusion risk)", file=rel, line=i,
                                    detail="pip merges all indexes and installs the highest version found anywhere, so a public package with the same name as an internal one wins.",
                                    fix="Use a single index (--index-url) that proxies both, or pin with --require-hashes.", confidence="Medium", owasp="A08"))
    seen = set()
    for c in components:
        sq = _squat_of(c["ecosystem"], c["name"])
        if sq and (c["ecosystem"], c["name"]) not in seen:
            seen.add((c["ecosystem"], c["name"]))
            out.append(dict(rule="DEP-5", domain="deps", severity="Medium", cwe="CWE-1357",
                            title=f"Possible typosquat: {c['name']} (resembles {sq})", file=c["file"], line=c["line"] or 1,
                            detail=f"The name is one edit away from the popular package '{sq}'. Typosquatted packages are a common malware vector. This is a name heuristic, not proof.",
                            fix=f"Confirm the package is the intended one (publisher, download counts, repository). If it was meant to be '{sq}', correct the name and rotate any secrets that were present where it was installed.",
                            confidence="Low", owasp="A08"))
    return out
