#!/usr/bin/env python3
"""Collect verifiable facts about a repository for README generation.

Prints JSON: manifests, scripts, services, env vars, entry points, route hints, CI, tests, tree.
Everything is read from files; nothing is executed or installed.

Usage: python discover.py [REPO_PATH] [--depth 3] [--out facts.json]
"""
import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):      # never crash on characters the console encoding cannot show (e.g. cp1252 on Windows)
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", "target", ".next", ".nuxt", ".cache", "vendor",
               "coverage", ".tox", ".idea", ".mypy_cache", ".pytest_cache", ".gradle", "bin", "obj", ".terraform", "out", ".turbo", "site-packages"}
MAX_READ = 400_000
LANG = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust",
        ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".rb": "Ruby", ".php": "PHP", ".swift": "Swift", ".c": "C", ".cpp": "C++", ".h": "C/C++",
        ".scala": "Scala", ".ex": "Elixir", ".sh": "Shell", ".ps1": "PowerShell", ".sql": "SQL", ".tf": "Terraform", ".vue": "Vue", ".svelte": "Svelte",
        ".html": "HTML", ".css": "CSS", ".scss": "SCSS"}
MANIFESTS = {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
             "Gemfile", "composer.json", "mix.exs", "Makefile", "justfile", "Taskfile.yml", "Dockerfile", "Chart.yaml", "serverless.yml", "Jenkinsfile",
             ".gitlab-ci.yml", ".nvmrc", ".python-version", ".tool-versions", "AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "LICENSE", "tsconfig.json",
             "vite.config.ts", "vite.config.js", "next.config.js", "webpack.config.js", ".env.example", ".env.sample", ".env.template", "openapi.yaml",
             "openapi.yml", "openapi.json", "swagger.json", "swagger.yaml", ".pre-commit-config.yaml", ".editorconfig"}
MANIFEST_GLOBS = ("requirements*.txt", "Dockerfile*", "docker-compose*.y*ml", "compose*.y*ml", "*.csproj", "*.sln", "*.tf", "*.env.example")
ENTRY_NAMES = {"main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "__main__.py", "server.py", "cli.py", "index.js", "server.js", "app.js", "main.js", "index.ts",
               "server.ts", "main.ts", "app.ts", "main.go", "main.rs", "lib.rs", "Program.cs", "Main.java", "Application.java", "index.php", "config.ru"}
ENV_PATTERNS = [r"process\.env\.([A-Z][A-Z0-9_]+)", r"process\.env\[['\"]([A-Z][A-Z0-9_]+)['\"]\]", r"import\.meta\.env\.([A-Z][A-Z0-9_]+)",
                r"os\.environ(?:\.get)?\[?\(?['\"]([A-Z][A-Z0-9_]+)['\"]", r"os\.getenv\(\s*['\"]([A-Z][A-Z0-9_]+)['\"]", r"getenv\(\s*['\"]([A-Z][A-Z0-9_]+)['\"]",
                r"System\.getenv\(\s*\"([A-Z][A-Z0-9_]+)\"", r"Environment\.GetEnvironmentVariable\(\s*\"([A-Z][A-Z0-9_]+)\""]
SHELL_VAR = re.compile(r"\$\{([A-Z][A-Z0-9_]+)(?::?[-?][^}]*)?\}|\$([A-Z][A-Z0-9_]+)\b")
SHELL_EXT = {".sh", ".bash"}
SHELL_ASSIGN = r"(?:^|[;&(\s])(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?|for\s+|read\s+(?:-\w+\s+)*)?{v}(?:=|\s+in\b)"
INDEX_NAMES = {"index.js", "index.ts"}
BOOTSTRAP = re.compile(r"\.listen\(|createServer\(|bootstrapApplication|platformBrowserDynamic|bootstrapModule|createRoot\(|ReactDOM\.render|\bexpress\(\)|new Vue\(|createApp\(|^#!|NestFactory|process\.argv|commander|yargs", re.M)
QUALITY = re.compile(r"(^|/)(\.eslintrc[^/]*|eslint\.config\.\w+|\.prettierrc[^/]*|prettier\.config\.\w+|ruff\.toml|\.ruff\.toml|\.flake8|mypy\.ini|\.editorconfig|\.pre-commit-config\.yaml|tox\.ini|noxfile\.py|"
                     r"jest\.config\.\w+|vitest\.config\.\w+|pytest\.ini|\.golangci\.ya?ml|\.rubocop\.yml|commitlint\.config\.\w+|\.husky/[^/]+|renovate\.json|dependabot\.ya?ml|codecov\.ya?ml|\.coveragerc|sonar-project\.properties|checkstyle[^/]*\.xml|\.swiftlint\.yml)$")
PROJECT_FILES = {"LICENSE", "LICENSE.md", "LICENSE.txt", "MAINTAINERS", "CODEOWNERS", ".github/CODEOWNERS", "SECURITY.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "CHANGELOG.md", "NOTICE", "GOVERNANCE.md"}
OBS = re.compile(r"(^|/)(prometheus[^/]*\.ya?ml|otel[^/]*\.ya?ml|grafana/.*|datadog[^/]*\.ya?ml|alert[^/]*rules?\.ya?ml|logstash[^/]*\.conf|fluent[^/]*\.conf|loki[^/]*\.ya?ml)$")
MODEL_PATTERNS = [(r"^class\s+(\w+)\((?:[\w.]*\bModel|db\.Model)\)", "Django/Flask model"), (r"^class\s+(\w+)\([\w.]*Base\):", "SQLAlchemy model"),
                  (r"__tablename__\s*=\s*['\"](\w+)", "SQLAlchemy table"), (r"@Entity[\s\S]{0,120}?class\s+(\w+)", "JPA entity"), (r"CREATE TABLE(?: IF NOT EXISTS)?\s+[`\"]?(\w+)", "SQL table"),
                  (r"mongoose\.model\(\s*['\"](\w+)", "Mongoose model"), (r"sequelize\.define\(\s*['\"](\w+)", "Sequelize model"), (r"^model\s+(\w+)\s*\{", "Prisma model"),
                  (r"@Entity\([^)]*\)\s*(?:export\s+)?class\s+(\w+)", "TypeORM entity")]
DEP_CATEGORIES = {
    "web/framework": ["express", "fastify", "koa", "flask", "fastapi", "django", "spring", "gin", "echo", "rails", "laravel", "next", "react", "vue", "angular", "svelte", "nest", "aspnet"],
    "database/orm": ["pg", "postgres", "psycopg", "mysql", "sqlite", "mongo", "redis", "sequelize", "typeorm", "prisma", "sqlalchemy", "gorm", "hibernate", "jpa", "entityframework", "npgsql", "knex"],
    "messaging/jobs": ["kafka", "rabbit", "amqp", "celery", "bull", "sqs", "nats", "pubsub", "socket.io", "stackexchange.redis"],
    "cloud/infra": ["aws", "boto3", "azure", "google-cloud", "gcp", "firebase", "terraform", "kubernetes", "docker"],
    "auth/security": ["passport", "jwt", "jsonwebtoken", "oauth", "auth0", "keycloak", "authlib", "bcrypt", "helmet", "cors"],
    "ml/data": ["torch", "tensorflow", "keras", "jax", "numpy", "pandas", "scipy", "scikit", "sklearn", "onnx", "openvino", "nncf", "transformers", "xgboost", "lightgbm",
                "mlflow", "wandb", "opencv", "pillow", "matplotlib", "spark", "dask", "airflow", "langchain", "openai", "anthropic", "huggingface"],
    "configuration": ["hydra", "omegaconf", "pydantic", "dynaconf", "python-dotenv", "dotenv", "viper", "config"],
    "cli": ["click", "typer", "argparse", "fire", "commander", "yargs", "cobra"],
    "testing": ["pytest", "jest", "vitest", "mocha", "jasmine", "cypress", "playwright", "karma", "junit", "testng", "phpunit", "xunit", "nunit", "rspec", "minitest", "testing-library"],
    "tooling": ["eslint", "prettier", "ruff", "black", "flake8", "mypy", "webpack", "vite", "babel", "typescript", "tsc", "nodemon", "gunicorn", "uvicorn"],
}
CODE_EXT = {k for k in LANG if k not in (".html", ".css", ".scss", ".sql", ".tf")}
CONFIG_FILE = re.compile(r"(^|/)(config|configs|conf|settings|cfg)(/|$)|(^|/)(config|settings|application|appsettings|bootstrap)[\w.-]*\.(ya?ml|json|toml|ini|cfg|conf|properties)$|(^|/)\.env[\w.-]*$", re.I)
ROUTE_PATTERNS = [(r"@(?:app|router|bp|api)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)", "Flask/FastAPI"),
                  (r"@(?:app|bp)\.route\(\s*['\"]([^'\"]+)", "Flask"),
                  (r"\b(?:app|router|server)\.(get|post|put|delete|patch)\(\s*['\"`]([^'\"`]+)", "Express-style"),
                  (r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?\{?\s*\"([^\"]+)", "Spring"),
                  (r"\bpath\(\s*['\"]([^'\"]*)['\"]", "Django urls"),
                  (r"\.(?:Handle|HandleFunc|GET|POST|PUT|DELETE)\(\s*\"([^\"]+)", "Go http/gin")]
TEST_DEPS = {"pytest", "unittest", "nose", "jest", "vitest", "mocha", "jasmine", "cypress", "playwright", "@playwright/test", "karma", "ava", "tap", "testing-library",
             "rspec", "minitest", "junit", "testng", "phpunit", "xunit", "nunit"}


def rel(p, root):
    return p.relative_to(root).as_posix()


def list_files(root, cap):
    """Tracked files when in git (honors .gitignore), else a pruned walk."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"], capture_output=True, text=True, timeout=30)
        if out.returncode == 0 and out.stdout.strip():
            fs = [root / f for f in out.stdout.splitlines()]
            return [f for f in fs if f.is_file() and not (set(f.relative_to(root).parts[:-1]) & IGNORE_DIRS)][:cap], "git"
    except Exception:
        pass
    res = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in IGNORE_DIRS]  # prune before descending
        res += [Path(dp) / f for f in fns]
        if len(res) >= cap:
            return res[:cap], "walk"
    return res, "walk"


def read(p, limit=MAX_READ):
    try:
        if p.stat().st_size > limit:
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def tree(files, root, depth):
    nodes = {}
    for f in files:
        parts = f.relative_to(root).parts
        cur = nodes
        for i, part in enumerate(parts[:depth]):
            cur = cur.setdefault(part + ("/" if i < len(parts) - 1 else ""), {})
    lines = []
    def walk(d, prefix=""):
        keys = sorted(d, key=lambda k: (not k.endswith("/"), k.lower()))
        for i, k in enumerate(keys):
            last = i == len(keys) - 1
            lines.append(prefix + ("└── " if last else "├── ") + k)
            walk(d[k], prefix + ("    " if last else "│   "))
    walk(nodes)
    return "\n".join(lines[:400])


def parse_package_json(p, root):
    try:
        d = json.loads(read(p))
    except Exception:
        return None
    deps = {**d.get("dependencies", {}), **d.get("devDependencies", {})}
    return {"file": rel(p, root), "name": d.get("name"), "version": d.get("version"), "description": d.get("description"), "main": d.get("main"),
            "bin": d.get("bin"), "type": d.get("type"), "engines": d.get("engines"), "packageManager": d.get("packageManager"),
            "scripts": d.get("scripts", {}), "workspaces": d.get("workspaces"),
            "dependency_versions": dict(list(d.get("dependencies", {}).items())[:60]),
            "dev_dependency_versions": dict(list(d.get("devDependencies", {}).items())[:60]),
            "dependencies": sorted(d.get("dependencies", {}))[:40], "devDependencies": sorted(d.get("devDependencies", {}))[:40],
            "test_deps": sorted(set(deps) & TEST_DEPS)}


def parse_pyproject(p, root):
    txt = read(p)
    try:
        import tomllib
        d = tomllib.loads(txt)
    except Exception:
        d = None
    if d is None:
        name = re.search(r'^name\s*=\s*"([^"]+)"', txt, re.M)
        return {"file": rel(p, root), "name": name and name.group(1), "note": "tomllib unavailable or parse failed; limited fields"}
    pr = d.get("project", {})
    poetry = d.get("tool", {}).get("poetry", {})
    return {"file": rel(p, root), "name": pr.get("name") or poetry.get("name"), "version": pr.get("version") or poetry.get("version"),
            "description": pr.get("description") or poetry.get("description"), "requires_python": pr.get("requires-python") or poetry.get("dependencies", {}).get("python"),
            "dependency_specs": (pr.get("dependencies", []) or [f"{k} {v}" for k, v in poetry.get("dependencies", {}).items()])[:60],
            "scripts": pr.get("scripts") or poetry.get("scripts") or {}, "dependencies": [re.split(r"[<>=!~\[; ]", x)[0] for x in pr.get("dependencies", [])][:40] or sorted(poetry.get("dependencies", {}))[:40],
            "build_backend": d.get("build-system", {}).get("build-backend"), "tools": sorted(d.get("tool", {}))}


def parse_go_mod(p, root):
    t = read(p)
    return {"file": rel(p, root), "module": (re.search(r"^module\s+(\S+)", t, re.M) or [None, None])[1], "go": (re.search(r"^go\s+(\S+)", t, re.M) or [None, None])[1],
            "requires": [" ".join(x.split()[:2]) for x in re.findall(r"^\s*(?:require\s+)?([\w./~-]+\s+v[\w.+-]+)", t, re.M)][:60]}


def parse_cargo(p, root):
    try:
        import tomllib
        d = tomllib.loads(read(p))
    except Exception:
        return {"file": rel(p, root), "note": "tomllib unavailable"}
    deps = {k: (v if isinstance(v, str) else v.get("version", "*")) for k, v in d.get("dependencies", {}).items()}
    return {"file": rel(p, root), "name": d.get("package", {}).get("name"), "edition": d.get("package", {}).get("edition"), "dependencies": dict(list(deps.items())[:60])}


def parse_pom(p, root):
    t = read(p)
    deps = re.findall(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?", t)
    return {"file": rel(p, root), "artifact": (re.search(r"<artifactId>([^<]+)</artifactId>", t) or [None, None])[1],
            "java": (re.search(r"<(?:java\.version|maven\.compiler\.source|release)>([^<]+)<", t) or [None, None])[1],
            "dependencies": [f"{g}:{a}" + (f":{v}" if v else "") for g, a, v in deps][:60]}


def parse_csproj(p, root):
    t = read(p)
    return {"file": rel(p, root), "target": (re.search(r"<TargetFramework>([^<]+)<", t) or [None, None])[1], "sdk": (re.search(r'<Project Sdk="([^"]+)"', t) or [None, None])[1],
            "output_type": (re.search(r"<OutputType>([^<]+)<", t) or [None, None])[1],
            "packages": [f"{n}" + (f" {v}" if v else "") for n, v in re.findall(r'<PackageReference Include="([^"]+)"(?:\s+Version="([^"]+)")?', t)][:60]}


def parse_makefile(p, root):
    targets = re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", read(p), re.M)
    return {"file": rel(p, root), "targets": [t for t in dict.fromkeys(targets) if not t.startswith(".")]}


def parse_compose(p, root):
    txt = read(p)
    services = {}
    m = re.search(r"^services:\s*\n((?:[ \t]+.*\n?|\n)+)", txt, re.M)
    if m:
        cur = None
        for line in m.group(1).splitlines():
            s = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
            if s:
                cur = s.group(1); services[cur] = {"image": None, "build": False, "ports": [], "depends_on": []}
            elif cur:
                if re.match(r"^\s{4}image:\s*(.+)", line): services[cur]["image"] = line.split("image:", 1)[1].strip()
                elif re.match(r"^\s{4}build:", line): services[cur]["build"] = True
                elif re.match(r"^\s+-\s*['\"]?\d+[:\d.]*", line) and "ports" in txt:
                    v = re.match(r"^\s+-\s*['\"]?([\d.:]+)", line)
                    if v and ":" in v.group(1): services[cur]["ports"].append(v.group(1))
                elif re.match(r"^\s{6}-\s*([A-Za-z0-9_.-]+)\s*$", line): services[cur]["depends_on"].append(line.strip()[2:])
    return {"file": rel(p, root), "services": services}


def parse_dockerfile(p, root):
    t = read(p)
    return {"file": rel(p, root), "from": re.findall(r"^FROM\s+(\S+)", t, re.M | re.I), "expose": re.findall(r"^EXPOSE\s+(.+)", t, re.M | re.I),
            "cmd": re.findall(r"^(?:CMD|ENTRYPOINT)\s+(.+)", t, re.M | re.I)}


def parse_workflow(p, root):
    t = read(p)
    return {"file": rel(p, root), "name": (re.search(r"^name:\s*(.+)", t, re.M) or [None, None])[1], "on": (re.search(r"^on:\s*(.*)", t, re.M) or [None, ""])[1].strip() or "see file",
            "jobs": re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", t.split("jobs:", 1)[1] if "jobs:" in t else "", re.M),
            "run": [x.strip() for x in re.findall(r"^\s*-?\s*run:\s*(.+)", t, re.M)][:30]}


def env_example(p, root):
    return {"file": rel(p, root), "vars": [m.group(1) for m in re.finditer(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", read(p), re.M)]}


def is_bootstrap(f):
    """index.js/ts is usually a barrel file that only re-exports; keep it as an entry point only if it starts something."""
    return bool(BOOTSTRAP.search(read(f, 60000)))


def shell_env(txt):
    """Variables a shell script reads from its environment: ${VAR}/$VAR that the script never assigns itself."""
    names = {a or b for a, b in SHELL_VAR.findall(txt)}
    return {v for v in names if not re.search(SHELL_ASSIGN.format(v=re.escape(v)), txt, re.M)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--max-files", type=int, default=20000, help="stop listing after this many files (guard for huge or non-repo folders)")
    ap.add_argument("--out")
    a = ap.parse_args()
    root = Path(a.path).resolve()
    files, how = list_files(root, a.max_files)
    facts = {"root": str(root), "file_listing": how, "file_count": len(files), "truncated": len(files) >= a.max_files}
    if facts["truncated"]:
        print(f"WARNING: stopped at {a.max_files} files; this may not be a single repository. Point at a project root or raise --max-files.", file=sys.stderr)
    facts["empty_repo"] = not [f for f in files if f.name not in {"README.md", "LICENSE", ".gitignore", "AGENTS.md"}]
    ext = Counter(LANG.get(f.suffix.lower()) for f in files if LANG.get(f.suffix.lower()))
    facts["languages"] = dict(ext.most_common())
    m = {}
    def add(kind, v):
        if v: m.setdefault(kind, []).append(v)
    env_vars, entry, routes, tests, readmes, docs, agent_files = {}, [], [], [], [], [], []
    quality, project_files, data_hints, adr, observability, config_files, shell_scripts = [], [], [], [], [], [], []
    for f in files:
        r = rel(f, root); n = f.name
        if n == "package.json": add("package.json", parse_package_json(f, root))
        elif n == "pyproject.toml": add("pyproject", parse_pyproject(f, root))
        elif n in ("Makefile", "justfile"): add("make", parse_makefile(f, root))
        elif re.match(r"(docker-compose|compose).*\.ya?ml$", n): add("compose", parse_compose(f, root))
        elif n.startswith("Dockerfile"): add("dockerfile", parse_dockerfile(f, root))
        elif n in (".env.example", ".env.sample", ".env.template") or n.endswith(".env.example"): add("env_files", env_example(f, root))
        elif r.startswith(".github/workflows/") and n.endswith((".yml", ".yaml")): add("ci", parse_workflow(f, root))
        elif n.endswith(".csproj"): add("dotnet", parse_csproj(f, root))
        elif n == "go.mod": add("go_mod", parse_go_mod(f, root))
        elif n == "Cargo.toml": add("cargo", parse_cargo(f, root))
        elif n == "pom.xml": add("maven", parse_pom(f, root))
        elif n in ("Gemfile", "composer.json", "build.gradle", "build.gradle.kts", "mix.exs", "setup.py", "Pipfile", "Jenkinsfile", ".gitlab-ci.yml", "Chart.yaml", "serverless.yml") or n.endswith((".csproj", ".sln")):
            add("other_manifests", r)
        elif re.match(r"requirements.*\.txt$", n): add("requirements", {"file": r, "packages": [re.split(r"[<>=!~\[; ]", l.strip())[0] for l in read(f).splitlines() if l.strip() and not l.startswith(("#", "-"))][:40],
                                                                  "specs": [l.strip() for l in read(f).splitlines() if l.strip() and not l.startswith(("#", "-"))][:60]})
        if n in {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.json", "swagger.yaml"}: add("api_specs", r)
        if n.lower().startswith("readme"): readmes.append(r)
        if n in ("AGENTS.md", "CLAUDE.md"): agent_files.append(r)
        if n in {".nvmrc", ".python-version", ".tool-versions"}: add("version_files", {"file": r, "content": read(f).strip()[:80]})
        if r.endswith(".tf"): add("terraform", r)
        if n in ENTRY_NAMES and (n not in INDEX_NAMES or is_bootstrap(f)): entry.append(r)
        if QUALITY.search(r): quality.append(r)
        if n in PROJECT_FILES or r in PROJECT_FILES or re.match(r"(?i)^(\.github/)?(codeowners|security\.md|code_of_conduct\.md|contributing\.md|changelog\.md|maintainers|license.*)$", r):
            project_files.append(r)
        if re.search(r"(^|/)(docs?/(adr|decisions?)|adr|decisions)/", r): adr.append(r)
        if OBS.search(r): observability.append(r)
        if re.search(r"(^|/)(migrations?|alembic|db/migrate|prisma)(/|$)|schema\.prisma$|\.sql$", r): data_hints.append({"file": r, "kind": "migration/schema file", "name": n})
        if f.suffix.lower() in CODE_EXT and re.search(r"(^|/)(tests?|__tests__|spec|e2e)(/|$)|(\.|_)(test|spec)\.\w+$|(^|/)test_[^/]*$", r) and not r.startswith(("data/", "datasets/")):
            tests.append(r)
        if CONFIG_FILE.search(r) and f.suffix.lower() in (".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", "") and n not in ("package.json", "package-lock.json", "tsconfig.json"):
            config_files.append(r)
        if f.suffix.lower() in (".sh", ".ps1", ".bat", ".cmd", ".bash"):
            first = next((l.strip().lstrip("#:REMrem ").strip() for l in read(f, 20000).splitlines()[:6] if l.strip() and not l.startswith("#!")), "")
            shell_scripts.append({"file": r, "note": first[:100]})
        if r.startswith(("docs/", "doc/")): docs.append(r)
        if f.suffix.lower() in (".yaml", ".yml") and re.search(r"^kind:\s*(Deployment|Service|StatefulSet|Ingress|CronJob)", read(f), re.M): add("kubernetes", r)
        if f.suffix.lower() in LANG or n in ("Dockerfile", "docker-compose.yml") or n.startswith(".env"):
            txt = read(f)
            if not txt: continue
            if f.suffix.lower() in LANG and f.suffix.lower() not in (".html", ".css", ".scss", ".sql"):
                if re.search(r"if __name__\s*==\s*['\"]__main__['\"]", txt) and r not in entry: entry.append(r)
                for pat, kind in MODEL_PATTERNS:
                    for nm in re.findall(pat, txt)[:15]:
                        data_hints.append({"file": r, "kind": kind, "name": nm})
                for pat in ENV_PATTERNS:
                    for v in re.findall(pat, txt):
                        env_vars.setdefault(v, set()).add(r)
                if f.suffix.lower() in SHELL_EXT:
                    for v in shell_env(txt): env_vars.setdefault(v, set()).add(r)
                for pat, fw in ROUTE_PATTERNS:
                    for hit in re.finditer(pat, txt):
                        g = hit.groups(); routes.append({"file": r, "framework": fw, "method": g[0] if len(g) > 1 else None, "path": g[-1]})
            elif n.startswith("docker-compose") or n.startswith("compose"):
                for v in re.findall(r"\$\{([A-Z][A-Z0-9_]+)", txt): env_vars.setdefault(v, set()).add(r)
    facts["manifests"] = m
    names = set()
    for pj in m.get("package.json", []): names |= set(pj["dependency_versions"]) | set(pj["dev_dependency_versions"])
    for py in m.get("pyproject", []): names |= {re.split(r"[<>=!~\[; ]", x)[0].lower() for x in py.get("dependency_specs", [])}
    for rq in m.get("requirements", []): names |= {x.lower() for x in rq["packages"]}
    for g in m.get("go_mod", []): names |= {x.split()[0] for x in g["requires"]}
    for c in m.get("cargo", []): names |= set(c.get("dependencies", {}))
    for mv in m.get("maven", []): names |= set(mv["dependencies"])
    for dn in m.get("dotnet", []): names |= {x.split()[0].lower() for x in dn["packages"]}
    facts["stack_hints"] = {cat: sorted(n for n in names if any(k in n.lower() for k in keys)) for cat, keys in DEP_CATEGORIES.items()}
    facts["stack_hints"] = {k: v for k, v in facts["stack_hints"].items() if v}
    facts["quality_tools"] = sorted(set(quality))
    facts["project_files"] = sorted(set(project_files))
    facts["adr_files"] = sorted(set(adr))[:30]
    facts["observability_files"] = sorted(set(observability))[:30]
    facts["data_model_hints"] = data_hints[:120]
    facts["config_files"] = sorted(set(config_files))[:60]
    facts["shell_scripts"] = sorted(shell_scripts, key=lambda x: x["file"])[:40]
    facts["entry_points"] = sorted(entry)
    facts["env_vars"] = {k: sorted(v)[:5] for k, v in sorted(env_vars.items())}
    facts["route_hints"] = routes[:80]
    facts["tests"] = {"files": len(tests), "examples": tests[:15], "note": "name-based heuristic; open the files to confirm they are real automated tests (evaluation or demo scripts can match)"}
    facts["existing_readmes"] = readmes
    facts["agent_instruction_files"] = agent_files
    facts["docs_files"] = docs[:30]
    top = sorted({f.relative_to(root).parts[0] for f in files if len(f.relative_to(root).parts) > 1})
    facts["top_level_dirs"] = top
    facts["top_level_files"] = sorted(f.name for f in files if len(f.relative_to(root).parts) == 1)
    facts["tree"] = tree(files, root, a.depth)
    out = json.dumps(facts, indent=1, default=list)
    if a.out:
        Path(a.out).write_text(out, encoding="utf-8")
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
