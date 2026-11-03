---
name: repo-readme-generator
description: Create or update a repository's documentation from verified evidence. Writes an architecture-focused README.md and, on request, a full documentation suite for developers and coding agents (AGENTS.md, codebase map, architecture, tech stack and dependencies, design decisions, development guide, testing, configuration, API reference, data model, deployment and operations, security, troubleshooting, glossary). Draws diagrams as GitHub-compatible Mermaid or as generated SVG. Use when asked to generate, write, refresh, sync or audit a README or project documentation, document a repository's architecture, onboard developers, prepare a repo for CLI/coding agents, or check whether docs are out of date. Supports new, existing and empty repositories, incremental updates, validation of links, commands, diagrams and SVGs, and AGENTS.md integration.
---

# Repo documentation generator

Produces consistent, architecture-focused documentation grounded in what the repository actually contains. Act as a senior software architect and developer-experience engineer: be accurate before being complete. Two scopes: a single README, or a full documentation suite that gives a developer or coding agent everything needed to work on the project.

## Hard rules

1. **Evidence only.** Every component, command, port, variable, endpoint, dependency and design claim must come from a file you read. If you cannot verify it, write `TBD` (unknown) or `Planned` (documented intent, not implemented). Design rationale you infer from code is labeled `Source: inferred from code`; never present it as the authors' intent.
2. **Scope of edits.**
   - README scope: create or edit only the root `README.md`.
   - Suite scope: `README.md`, `AGENTS.md` and files under `docs/` (including `docs/diagrams/`). Never touch application code, dependencies or infrastructure. Do not create `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md` or `CHANGELOG.md`; link to them or list them as gaps.
   - Outside those paths, only with the user's explicit approval.
3. **Safe checks only.** Read files and run read-only commands. Do not install dependencies, start servers or containers, run migrations, or call external services without approval.
4. **Honest verification.** Report which checks you ran and which you did not. Commands taken from manifests but not executed are "documented from <file>, not executed".
5. **No secrets.** Variable names, descriptions and placeholder defaults only; never real values, and never copy credentials found in samples (name the file instead).
6. **Preserve what is right.** In update mode keep accurate existing text and the author's voice; change only what is stale, missing or wrong. Preserve existing `AGENTS.md` rules.

## Choose scope and mode

**Scope** (see `references/doc-suite.md` for the tiers):

| Request sounds like | Scope |
|---|---|
| "Generate/update the README" | `readme` |
| "Document this repo", "onboarding docs", "docs for agents/Codex", "full documentation", "architecture, stack, design and dependencies docs" | `standard` (or `full` when they ask for as much detail as possible) |

State the scope you chose in one line and offer the next tier up.

**Mode:**

| Situation | Mode |
|---|---|
| No docs yet, or README is a stub | **create** |
| Repo has no source yet (only license/gitignore/README) | **create, starter skeleton**: headings with `TBD` bodies, no invented architecture or diagrams |
| Docs exist and the code changed or the user wants a refresh | **update** (incremental) |
| User only wants a health check | **audit**: validate and drift-check, report, change nothing |

## Workflow

Set `<skill-dir>` to the folder containing this file (usually `~/.codex/skills/repo-readme-generator`) and run scripts from the repository root.

### 1. Discover
```bash
python3 <skill-dir>/scripts/discover.py . --out /tmp/readme-facts.json
```
It reports manifests with dependency versions, scripts, compose services, env vars, entry points, route hints, data-model hints (tables, models, migrations), stack hints, CI, tests, quality tools, ADRs, observability configs, ownership and license files, and a directory tree, all read from files. It is a starting point: open the real files. Follow `references/discovery-checklist.md` to trace entry points, module boundaries, data stores, integrations and startup order.

In update mode also run:
```bash
python3 <skill-dir>/scripts/check_drift.py README.md --docs docs
```
and read the existing documents fully before editing.

### 2. Build the model of the system
Write down (privately) components and responsibilities, locations, dependencies, main flows, data, configuration, interfaces, conventions and constraints. Draw an edge only where you saw an import, call or connection. If two readings are plausible, document the one the code proves and flag the other `TBD`.

### 3. Write

**README scope:** follow `references/readme-template.md` (17 sections, clickable table of contents, relative links, fenced commands, tables). Include the verification footer comment (commit SHA and date).

**Suite scope:** follow `references/doc-suite.md`: pick documents by what exists in the repo, use the standard header, write in the listed order (codebase map, architecture, stack, data, API, configuration, development guide, testing, deployment, security, design, troubleshooting, glossary, AGENTS.md, README last as the index). Use `references/agents-md-template.md` for `AGENTS.md`. Skip documents whose subject does not exist and say so in the README's documentation index. Keep facts identical across files and link instead of duplicating.

**Diagrams** (both scopes): Mermaid or SVG, whichever fits (`references/svg-guide.md` has the decision table).
- Mermaid: follow `references/mermaid-guide.md`.
- SVG: write a spec to `docs/diagrams/src/<name>.json`, render with `python3 <skill-dir>/scripts/make_svg.py <spec> docs/diagrams/<name>.svg`, embed with descriptive alt text, and look at the result if you can (open it in a browser or screenshot it) before accepting the layout. Do not hand-write SVG.
- Every diagram covers all major components and shows only verified relationships; planned parts are dashed or labeled `Planned`.

Update mode: edit only affected sections or documents, keep stable anchors where possible, regenerate SVGs from their specs, refresh the `Verified against commit` line in files you touched, and do not reformat untouched text.

### 4. Validate and fix
README scope:
```bash
python3 <skill-dir>/scripts/validate_readme.py README.md
```
Suite scope:
```bash
python3 <skill-dir>/scripts/validate_docs.py
```
Checks: required sections, anchors and relative links, referenced paths, shell commands against package.json / Makefile / compose, Mermaid structure, unclosed fences, likely secrets, template leftovers, docs reachable from the README, AGENTS.md size (Codex reads 32 KiB), and SVG validity (well-formed, viewBox, title/description, no scripts, referenced, spec and render in sync). Fix every ERROR and review each WARN (some are legitimate, such as generated output paths). Re-run until clean, then spot-check what scripts cannot: that descriptions match the code and setup order works.

Optional, with approval and network: render Mermaid with `npx -y @mermaid-js/mermaid-cli`. Otherwise say "Mermaid not rendered".

### 5. AGENTS.md integration
In suite scope, create or update `AGENTS.md` from the template (it is part of the suite). In README scope, offer to add the README-maintenance rules from `references/agents-md-snippet.md` to `AGENTS.md`, and apply them only if the user agrees, preserving existing content.

### 6. Report
End with a short summary:
- Scope, mode, and files created or changed (sections for README edits).
- Components documented; diagrams generated (Mermaid or SVG, with paths).
- Build, start and test commands included, and whether each was only read from a file or actually run.
- Documents skipped as not applicable, and missing or `TBD` information the team should supply.
- Validation results and limitations (what was not run or rendered). Never claim a check you did not perform.

## Quality bar

- A new developer or agent can go from clone to running app, find where to make a change, and know how to verify it, using only the documents, or sees an explicit `TBD` where that is impossible.
- An architect can see every component, its location and dependencies, the data and interfaces, and the diagrams match the code.
- No generic filler ("this project uses best practices"). One precise sentence with a file link beats a paragraph.
- Implemented, planned and unknown are always distinguishable. Names, ports, commands and variables are identical across all documents.

## Files

- `scripts/discover.py` gathers repository facts. `scripts/make_svg.py` renders architecture and sequence diagrams to SVG. `scripts/validate_readme.py` validates one README. `scripts/validate_docs.py` validates the whole suite. `scripts/check_drift.py` finds what is undocumented or changed since the docs were last verified.
- `references/readme-template.md`, `doc-suite.md`, `agents-md-template.md`, `agents-md-snippet.md`, `discovery-checklist.md`, `mermaid-guide.md`, `svg-guide.md`.
