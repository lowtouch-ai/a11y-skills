---
name: repo-readme-generator
description: Create or update a repository's root README.md from verified evidence, with architecture-focused structure, GitHub-compatible Mermaid diagrams, component inventory, setup/build/run/test instructions, configuration and deployment docs. Use when asked to generate, write, refresh, sync or audit a README, document a repository's architecture, onboard developers, or check whether README.md is out of date. Works on new, existing and empty repositories, supports incremental updates, validates links, commands and diagrams, and can add README-maintenance rules to AGENTS.md.
---

# Repo README generator

Produces a consistent, architecture-focused root `README.md` grounded in what the repository actually contains. Act as a senior software architect and developer-experience engineer: be accurate before being complete.

## Hard rules

1. **Evidence only.** Every component, command, port, variable and endpoint must come from a file you read. If you cannot verify it, write `TBD` (unknown) or `Planned` (documented intent, not implemented). Never invent.
2. **Scope.** Create or edit only the root `README.md`. Do not change application code, dependencies or infrastructure. Editing `AGENTS.md` is a separate, opt-in step (see below).
3. **Safe checks only.** Read files and run read-only commands. Do not install dependencies, start servers or containers, run migrations, or call external services without the user's approval.
4. **Honest verification.** Report which checks you ran and which you did not. Commands taken from manifests but not executed are "documented from <file>, not executed".
5. **No secrets.** List variable names, descriptions and placeholder defaults; never real values.
6. **Preserve what is right.** In update mode keep accurate existing text and the author's voice; change only what is stale, missing or wrong.

## Choose the mode

| Situation | Mode |
|---|---|
| No README, or README is a stub | **create** |
| Repo has no source yet (only license/gitignore/README) | **create, starter skeleton**: headings with `TBD` bodies, no invented architecture or diagram |
| README exists and the user wants it refreshed or the code changed | **update** (incremental) |
| User only wants a health check | **audit**: run validation and drift check, report, change nothing |

## Workflow

Set `<skill-dir>` to the folder containing this file (usually `~/.codex/skills/repo-readme-generator`) and run scripts from the repository root.

### 1. Discover
```bash
python3 <skill-dir>/scripts/discover.py . --out /tmp/readme-facts.json
```
It lists manifests, scripts, compose services, env vars, entry points, route hints, CI workflows, tests and a directory tree, all read from files. It is a starting point: now open the real files. Follow `references/discovery-checklist.md` to trace entry points, module boundaries, data stores, integrations and startup order.

In update mode also run:
```bash
python3 <skill-dir>/scripts/check_drift.py README.md
```
and read the existing README fully before editing.

### 2. Build the model of the system
Write down (privately) the components, what each is responsible for, where it lives, what it depends on, and the main flows. Draw an edge only where you saw an import, call or connection. If two readings are plausible, document the one the code proves and flag the other as `TBD`.

### 3. Write or update the README
Follow `references/readme-template.md`: 17 sections in fixed order, a clickable table of contents, relative links to real files, fenced shell commands, tables for stack, components and configuration. Include the verification footer comment (commit SHA and date). Every section keeps its heading; if a section does not apply, say why in one line.

- Diagrams: follow `references/mermaid-guide.md`. The architecture diagram must contain every component in the Component Inventory and nothing unverified.
- Commands: only commands found in manifests, scripts, Makefiles, Dockerfiles, compose or CI. Keep setup order consistent with the real dependencies (for example database before migrations before server).
- Update mode: edit only affected sections, keep stable anchors where possible, refresh the footer commit, and do not reformat untouched text.

### 4. Validate and fix
```bash
python3 <skill-dir>/scripts/validate_readme.py README.md
```
It checks required sections, in-page anchors and relative links, referenced paths, shell commands against package.json / Makefile / compose, Mermaid structure, unclosed fences and likely secrets. Fix every ERROR and review each WARN (some are legitimate, such as generated output paths). Re-run until clean. Then spot-check by hand what scripts cannot: that component descriptions match the code, and that setup order works.

Optional, with approval and network: render Mermaid with `npx -y @mermaid-js/mermaid-cli` (see the guide). Otherwise state "Mermaid not rendered".

### 5. AGENTS.md integration (offer, do not assume)
Offer to add the README-maintenance rules from `references/agents-md-snippet.md` to `AGENTS.md`, so future changes trigger README updates. Apply them only if the user agrees, preserving existing AGENTS.md content. This is the only file besides README.md this skill may touch.

### 6. Report
End with a short summary:
- Mode, and README sections created or changed.
- Components documented; diagrams generated.
- Build, start and test commands included, and whether each was only read from a file or actually run.
- Missing or `TBD` information the team should supply.
- Validation results and limitations (what was not run or rendered). Never claim a check you did not perform.

## Quality bar

- A new developer can go from clone to running app using only the README, or sees an explicit `TBD` where that is impossible.
- An architect can see every component, its location and its dependencies, and the diagram matches the code.
- No generic filler ("this project uses best practices"). Prefer one precise sentence with a file link.
- Implemented, planned and unknown are always distinguishable.

## Files

- `scripts/discover.py` gathers repository facts. `scripts/validate_readme.py` validates a README. `scripts/check_drift.py` finds what changed or is undocumented since the README was last verified.
- `references/readme-template.md`, `discovery-checklist.md`, `mermaid-guide.md`, `agents-md-snippet.md`.
