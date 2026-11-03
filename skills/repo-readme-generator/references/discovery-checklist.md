# Discovery checklist

Run `scripts/discover.py` first, then read the files it points to. The script finds candidates; you must open them to understand responsibilities and relationships.

## Always read
- Existing README, docs/, CONTRIBUTING, AGENTS.md / CLAUDE.md, CHANGELOG (purpose, conventions, history).
- Manifests: package.json, pyproject.toml, requirements*.txt, go.mod, Cargo.toml, pom.xml, build.gradle*, Gemfile, composer.json, *.csproj.
- Build/run: Makefile, justfile, Taskfile, scripts/, Dockerfile*, docker-compose*, Procfile.
- Config: .env.example, config/, settings files, application.yml, appsettings.json.
- CI/CD and infra: .github/workflows, .gitlab-ci.yml, Jenkinsfile, terraform, helm, k8s manifests, serverless.yml.
- Tests: test directories, runner config (pytest.ini, jest.config, vitest.config, tox.ini).

## Extra facts for a documentation suite
`discover.py` also reports: `stack_hints` (frameworks, databases, messaging, cloud, auth, tooling found in dependencies), per-manifest dependency versions, `data_model_hints` (SQL tables, ORM models, migrations, Prisma schemas), `quality_tools` (linters, formatters, pre-commit, coverage), `config_files` (YAML/JSON/TOML/INI under config dirs, `.env*`), `shell_scripts` (candidate setup/run commands that have no manifest entry), `adr_files`, `observability_files`, `project_files` (LICENSE, MAINTAINERS, CODEOWNERS, SECURITY, CONTRIBUTING). Use them as pointers, then read the files. Treat `tests` and `stack_hints` as heuristics: confirm in the files before stating them.
- **Design decisions:** read ADRs, long code comments, commit messages (`git log --oneline` is safe), and PR templates before inferring rationale.
- **Data model:** open each model or migration listed; record fields, keys, relationships.
- **Security:** read auth middleware, CORS and TLS settings, secret handling, and note hardcoded sample credentials by file only.
- **Operations:** read health checks, logging setup, monitoring and alert configs, backup scripts.

## Tracing architecture (do this, do not guess)
1. **Entry points**: from `entry_points`, manifest `bin`/`main`/`scripts`, Dockerfile CMD, compose commands. Open each and note what it starts.
2. **Modules**: list top-level source directories. For each, read the main file and the imports that cross directory boundaries. A component is a unit with its own responsibility and a clear location, not every file.
3. **Dependencies between components**: follow imports/requires and HTTP/RPC/queue calls. Draw an edge only when you saw the import or call.
4. **Data stores**: look for ORM models, migrations, connection strings, compose images (postgres, redis, mongo), SQL files.
5. **External integrations**: SDK imports, base URLs in config, webhooks, cloud services named in infra code.
6. **Clients**: web frontends, CLIs, mobile apps, other services calling the APIs.
7. **Execution flow**: read startup code top to bottom: config load, DB connect, route/handler registration, workers, shutdown hooks.

## Monorepos
Document the workspace layout once, then one Component Inventory row per package/service. Link to a package README when it exists instead of repeating it.

## What you may and may not run
Safe, read-only: `--help`, `--version`, `git ls-files`, `make -n <target>`, `docker compose config`, `npm run` (no args, lists scripts), `python -m py_compile`, linters in check mode.
Needs approval: installing dependencies, starting servers or containers, running migrations, hitting external networks, anything that writes outside README.md.
When you did not run a command, document it as "from <file>, not executed".

## Ecosystem hints
- **Node**: scripts in package.json are the source of truth for build/run/test; check `engines`, `packageManager`, workspaces.
- **Python**: pyproject `[project.scripts]`, `requires-python`, tox/nox, `manage.py`, ASGI/WSGI app objects, Alembic migrations.
- **Java/Kotlin**: Maven/Gradle wrappers, Spring profiles, `application.*`.
- **Go**: `cmd/*/main.go`, go.mod version, Makefile targets.
- **.NET**: *.sln project graph, launchSettings.json, appsettings.*.
- **Docker-first repos**: compose services are often the best component list; confirm against code.
