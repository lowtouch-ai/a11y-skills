# Verification checklist

Run this after the validators pass and before the final report. The validators prove the documents are well formed; this proves they are right. Check against source files, not against other documents you wrote.

## What to re-check, by claim type

| Claim | How to verify |
|---|---|
| Version (language, framework, dependency, runtime) | Open the manifest or pin file and compare the exact string. Note when a version comes from a parent or property. |
| Command | Confirm the script or target exists in `package.json`, `Makefile`, compose file, CI workflow or script, and that the working directory is right. Do not run it unless approved; say "not executed". |
| Port, URL, route, endpoint | Find the line in config or code. Recount endpoints; class-level and method-level mappings combine. |
| Environment variable or setting | Find the reader in code or config. Confirm the default and whether it is required. Check it is a real environment variable, not a script-local variable. |
| Component and its dependency (prose or diagram edge) | Find the import, call, client or config that connects them. No evidence, no edge. |
| Entry point and startup order | Open the entry file and follow it to the next step. |
| Count or number ("232 endpoints", "31 controllers", "12 tests") | Recompute with a search; state what the search covered. |
| File or directory purpose | Open it or list its contents. |
| Design rationale | Must be labeled `Source: inferred from code` unless an ADR or comment states it. |
| Anything marked Implemented | A file proves it exists and is wired in, not just declared. |

## How much to check

- README and `AGENTS.md`: every factual claim.
- Each other document: all numbers, versions, commands, paths and diagram edges, plus at least ten other claims chosen across its sections.
- Update mode: also re-check untouched sections that mention anything you changed.
- On a very large repository, say which areas were checked exhaustively and which by sample.

## Handling results

1. Correct every mismatch in all documents that repeat it (names, ports and commands must stay identical across files).
2. Replace unconfirmable claims with `TBD` or `Planned`, or remove them.
3. Re-run the validators after edits.
4. Report the numbers honestly: claims checked, corrected, downgraded, not checked. If you only sampled, say so. Never write "fully verified" for a sample.

## Independent review (when a subagent is available)

Give the reviewer the documents and the repository path only. Ask it to list each claim it cannot confirm in the code, with the file it looked at. Do not share your own conclusions, so it does not just agree. Treat its list as leads: check each one yourself before changing a document.
