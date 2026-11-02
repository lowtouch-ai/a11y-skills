# AGENTS.md integration

Add this block to the repository's `AGENTS.md` (create the file if the user wants it) so Codex keeps the README current during normal development. Only edit AGENTS.md when the user asks for it or approves; keep any existing content and place this under its own heading. If a CLAUDE.md is the repo's instruction file, offer the same block there.

```markdown
## README maintenance

The root `README.md` documents architecture, setup, build, run, test and configuration. Keep it accurate as part of every change.

Update the README (use the `repo-readme-generator` skill in update mode) when a change:
- adds, removes, renames or re-wires a service, module, package or major directory;
- changes an entry point, port, route, public API, event, or CLI command;
- adds or changes a build, run, test or lint command, or a package.json / Makefile / pyproject script;
- adds, removes or changes an environment variable or config file;
- changes a runtime or dependency version requirement, a datastore, or an external integration;
- changes Dockerfiles, compose files, CI/CD workflows or infrastructure code.

Before finishing such a change:
1. `python <skill-dir>/scripts/check_drift.py README.md` and fix what it reports.
2. Edit only the affected README sections; preserve accurate existing text.
3. `python <skill-dir>/scripts/validate_readme.py README.md` and resolve errors.
4. Mention in the final message which README sections changed.

Never document behavior that is not implemented; mark it `Planned` or `TBD`.
```

`<skill-dir>` is the installed skill folder, for example `~/.codex/skills/repo-readme-generator`.
