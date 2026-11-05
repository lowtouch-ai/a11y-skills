"""Every detection rule must have at least one test that proves it can fire.

Line rules are exercised together in one repository (one sample file per rule). Control-presence checks ("control not
evidenced") must each run alone, because any other file mentioning the control would satisfy them.

Run:  python3 -m pytest tests/appsec-static-audit/test_rule_coverage.py     (or run this file directly)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "skills", "appsec-static-audit", "scripts"))
import rules as R  # noqa: E402
import test_detection as td  # noqa: E402

# rule id -> (sample file name, content). The file name carries the extension that selects the language tag.
LINE_SAMPLES = {
    "INJ-SQL-3": ("a.php", "<?php\nmysqli_query($c, \"SELECT * FROM t WHERE id=\" . $_GET['id']);\n"),
    "INJ-CMD-3": ("A.java", "class A { void f(String c) throws Exception { Runtime.getRuntime().exec(c); } }\n"),
    "INJ-CMD-4": ("b.php", "<?php\nshell_exec($cmd);\n"),
    "INJ-EVAL-1": ("e.js", "function f(code) { return eval(code); }\n"),
    "XSS-2": ("x.py", "from markupsafe import Markup\nhtml = Markup(user_text)\n"),
    "XSS-3": ("x.php", "<?php\necho $_GET['q'];\n"),
    "PATH-2": ("p.go", "package main\nfunc f(r *http.Request) { os.Open(r.FormValue(\"f\")) }\n"),
    "XXE-1": ("x2.py", "parser = etree.XMLParser(resolve_entities=True)\n"),
    "UPLOAD-1": ("u.js", "const upload = multer({ dest: 'uploads/' });\n"),
    "CSRF-1": ("c.py", "@csrf_exempt\ndef view(request):\n    pass\n"),
    "ACC-3": ("a3.java", "class S { void c(Object http) { http.authorizeRequests().anyRequest().permitAll(); } }\n"),
    "ACC-4": ("h.py", "uid = request.headers[\"X-User-Id\"]\n"),
    "ACC-5": ("v.html", "<button v-if=\"isAdmin\">Delete</button>\n"),
    "SSO-JWT-1": ("j1.py", "claims = jwt.decode(tok, key, algorithms=[\"none\"])\n"),
    "SSO-JWT-3": ("j3.js", "const claims = jwtDecode(token);\n"),
    "SSO-JWT-4": ("j4.py", "JWT_SECRET = \"secret123\"\n"),
    "SSO-OIDC-1": ("o1.py", "redirect_uri = request.args[\"ru\"]\n"),
    "SSO-OIDC-2": ("o2.py", "role = claims[\"roles\"]\n"),
    "SSO-BYP-2": ("b2.py", "def login(password):\n    if password == \"letmein123\":\n        return True\n"),
    "SES-1C": ("s1c.py", "SESSION_COOKIE_SAMESITE = \"None\"\n"),
    "SES-2": ("s2.py", "PERMANENT_SESSION_LIFETIME = timedelta(days=30)\n"),
    "SES-4": ("php.ini", "session.use_only_cookies = 0\n"),
    "MFA-1": ("m1.py", "MFA_REQUIRED = False\n"),
    "CRY-7": ("nginx.conf", "ssl_protocols TLSv1 TLSv1.1;\n"),
    "CRY-8": ("c8.py", "def my_encrypt(data):\n    return data\n"),
    "DATA-5": ("d5.py", "class Meta:\n    fields = \"__all__\"\n"),
    "DATA-6": ("d6.py", "headers = {\"Cache-Control\": \"public, max-age=600\"}\n"),
    "API-2": ("g.js", "const server = new ApolloServer({ introspection: true });\n"),
    "IAC-6": ("l.tf", "resource \"aws_cloudtrail\" \"t\" {\n  enable_logging = false\n}\n"),
    "IAC-7": ("h.tf", "resource \"aws_lb_listener\" \"l\" {\n  protocol = \"HTTP\"\n}\n"),
    "DKR-4": ("docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    privileged: true\n"),
    "CFG-3": ("n.conf", "server_tokens on;\n"),
    "LOG-3": ("l3.py", "try: risky()\nexcept Exception: pass\n"),
    "LOG-4": ("l4.py", "logger.info(f\"login {request.args['u']}\")\n"),
    "CI-1": (".github/workflows/ci.yml", "on: pull_request\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n"),
    "CI-2": (".github/workflows/prt.yml", "on:\n  pull_request_target:\njobs:\n  b:\n    runs-on: ubuntu-latest\n"),
    "CI-3": (".github/workflows/pin.yml", "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: some-org/action@main\n"),
    "CI-4": (".github/workflows/perm.yml", "on: push\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n"),
    "CI-5": (".github/workflows/echo.yml", "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.TOKEN }}\n"),
    "SH-1": ("entry.sh", "#!/bin/sh\nsource <(curl -s \"$VAULT_GET_ADDR/get_secret.sh\")\n"),
    "API-3": ("api.py", "from fastapi import APIRouter\nr = APIRouter()\n@r.get(\"/tickets\")\ndef tickets():\n    return []\n"),
    "K8S-2": ("dep.yaml", "apiVersion: apps/v1\nkind: Deployment\nspec:\n  containers:\n    - image: nginx:latest\n"),
    "CRY-2": ("c2.py", "password_hash = hashlib.md5(password.encode()).hexdigest()\n"),
    "DATA-3": ("d3.py", "logger.info(f\"body {request.json}\")\n"),
}

# presence checks: rule id -> single-file repository that mentions the subject but never the expected control
PRESENCE_SAMPLES = {
    "oidc-state": ({"o.py": "import authlib\nurl = 'https://idp/authorize?response_type=code'\n"}, ["SSO-OIDC-3", "SSO-OIDC-5"]),
    "oidc-scope": ({"o.py": "scope = 'openid profile'\n"}, ["SSO-OIDC-4", "SES-6"]),
    "session": ({"s.js": "const session = require('express-session');\n"}, ["SES-5"]),
    "admin": ({"m.py": "def admin_panel(user):\n    return user.is_admin\n"}, ["MFA-2", "LOG-2", "LOG-1"]),
    "ssn": ({"d.py": "ssn = form['ssn']\n"}, ["DATA-7", "DATA-8"]),
    "saml": ({"s.py": "from onelogin.saml2.auth import OneLogin_Saml2_Auth\n"}, ["SSO-SAML-2", "SSO-SAML-3"]),
    "jwt": ({"j.js": "const jwt = require('jsonwebtoken');\njwt.verify(t, key);\n"}, ["SSO-JWT-5"]),
    "flask-app": ({"app.py": "from flask import Flask\napp = Flask(__name__)\n"}, ["API-4", "API-5", "CFG-4", "ERR-2"]),
    "dockerfile": ({"Dockerfile": "FROM alpine:3.19\nCMD [\"sh\"]\n"}, ["DKR-3"]),
    "k8s-workload": ({"d.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n          image: nginx@sha256:abc\n"}, ["K8S-3", "K8S-4"]),
    "k8s-ingress": ({"i.yaml": "apiVersion: networking.k8s.io/v1\nkind: Ingress\nspec:\n  rules:\n    - host: a.example.com\n"}, ["K8S-5"]),
}

# rules already proven by the vulnerable fixture app (tests/appsec-static-audit/test_skill.py) or by test_detection.CASES
FIXTURE_COVERED = {"INJ-SQL-1", "INJ-SQL-2", "INJ-CMD-1", "INJ-CMD-2", "SSRF-1", "DESER-1", "XSS-1", "SSO-JWT-2", "SSO-SAML-1", "SSO-BYP-1", "SES-1", "SES-1B", "SES-3",
                   "DESER-2", "API-3", "CRY-1", "CRY-3", "CRY-4", "CRY-5", "CRY-6", "DATA-2", "DATA-4", "DATA-1", "API-1", "CFG-1", "CFG-2", "IAC-1", "IAC-2", "IAC-3",
                   "IAC-4", "IAC-5", "K8S-1", "DKR-1", "DKR-2", "DEP-1", "DEP-2", "DEP-3", "ERR-1", "ACC-2", "MISC-PROMPT-1", "SEC-HIST-1", "PATH-1", "REDIR-1", "ACC-1"}
# not unit-tested individually: file-level handlers or rules whose only trigger is exercised through the scanner itself
OTHER_COVERED = {"SEC-FILE-1", "SEC-FILE-2", "DATA-4", "XSS-4"}


def test_every_line_rule_has_a_working_sample():
    files = {f"s_{rule}/{name}": content for rule, (name, content) in LINE_SAMPLES.items()}   # own folder: some languages are detected by file name
    s = td.scan(files)
    fired = {(f["rule"], f["file"]) for f in s["findings"]}
    missing = [rule for rule, (name, _c) in LINE_SAMPLES.items() if (rule, f"s_{rule}/{name}") not in fired]
    assert not missing, f"rule samples that did not fire: {missing}"


def test_every_presence_check_fires_when_the_control_is_absent():
    missing = []
    for key, (files, expected) in PRESENCE_SAMPLES.items():
        got = {f["rule"] for f in td.scan(files)["findings"]}
        missing += [f"{r} ({key})" for r in expected if r not in got]
    assert not missing, f"presence checks that did not fire: {missing}"


def test_every_rule_is_covered_by_some_test():
    all_rules = {r["id"] for r in R.RULES} | {p["id"] for p in R.PRESENCE}
    covered = set(LINE_SAMPLES) | {r for _f, rs in PRESENCE_SAMPLES.values() for r in rs} | FIXTURE_COVERED | OTHER_COVERED
    for _n, (_f, must, _mn) in td.CASES.items():
        covered |= must
    uncovered = sorted(all_rules - covered)
    assert not uncovered, "rules with no test (add a sample to LINE_SAMPLES / PRESENCE_SAMPLES): " + ", ".join(uncovered)


if __name__ == "__main__":
    bad = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS ", name)
            except AssertionError as e:
                bad += 1
                print("FAIL ", name, "\n  ", str(e)[:900])
    sys.exit(1 if bad else 0)
