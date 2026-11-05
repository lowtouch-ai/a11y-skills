# krithi-skills

Reusable Codex skills from lowtouch.ai, built for the Krithi SDLC workflow.

## What is Krithi?

[Krithi](https://krithi.ai) is [lowtouch.ai](https://www.lowtouch.ai/agents/krithi/)'s agentic software delivery workflow. It turns a ticket into a reviewed pull request, running on the customer's own infrastructure (on-prem, private cloud or air-gapped), so code does not leave the customer's environment.

Work moves through four stages, and a human approves each one before anything merges to main:

| Stage | What happens |
|---|---|
| Plan | Requirements and sprint planning, with traceability back to legacy code and customer feedback. |
| Code | Code is generated and self-reviewed against the approved requirement. |
| Test | Playwright-based UI, API, performance and regression tests; defects go back to the coding stage. |
| Compliance audit | Security scans (SAST, dependency, secrets) and accessibility checks against standards such as OWASP ASVS and WCAG 2.2 AA. |

An orchestration agent routes each task to the model that suits it (Claude Code, Codex, Kimi or Gemma) and syncs status with Jira, Azure DevOps or ServiceNow. Krithi is aimed at engineering teams with a backlog and too few engineers, especially in regulated environments, for work such as legacy modernization, greenfield builds, data pipelines and platform migrations. lowtouch.ai also offers it as a managed service ([Velocity Pods](https://www.lowtouch.ai/agents/krithi/)), where its engineers run Krithi and own the review gates.

The skills in this repository are reusable building blocks for that kind of work: accessibility scanning and agent-ready documentation.

## Skills

| Skill | What it does |
|---|---|
| [`repo-readme-generator`](#repo-readme-generator) | Creates or updates a repo's README, or a full documentation suite with `AGENTS.md` and diagrams, from verified evidence. |
| [`appsec-static-audit`](#appsec-static-audit) | Source-code-only security audit of one repository or several (OWASP, SSO, secrets, dependencies and SBOM, IaC, CI/CD, PII/FTI) with a timestamped enterprise report, SARIF output and a CI gate, mapped to NIST 800-53, IRS Pub 1075 and EOTSS. |
| [`wave-a11y-scan`](#wave-a11y-scan) | WAVE-style accessibility scan of web pages with a client-ready report (WCAG 2.x, Section 508 note). |

In Codex, install a skill with the command in its section, then restart Codex. Skills are installed as folders under `~/.codex/skills/` (or `$CODEX_HOME/skills/` if you set `CODEX_HOME`).

## repo-readme-generator

Creates or updates a repo's README, or a full documentation suite with `AGENTS.md` and diagrams, from verified evidence. Details: [`SKILL.md`](skills/repo-readme-generator/SKILL.md).

### Install

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/repo-readme-generator
```

### Test

Open Codex in the folder you want to work on and run:

```
$repo-readme-generator create the README for this repo
```

For the full documentation suite:

```
$repo-readme-generator document this repo fully
```

### Update

To get the latest version, use either option, then restart Codex.

Option 1: ask the installer to update from the URL:

```
$skill-installer update https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/repo-readme-generator
```

Option 2: remove the installed folder and install it again:

```
rm -rf ~/.codex/skills/repo-readme-generator
```

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/repo-readme-generator
```

### Uninstall

```
rm -rf ~/.codex/skills/repo-readme-generator
```

## appsec-static-audit

Source-code-only security audit of one repository or several, for any organization or stack. A scanner finds candidates (injection and other OWASP issues with data-flow tracking, access control, SSO/JWT/SAML, sessions, secrets including git history, dependency vulnerabilities from a bundled OSV snapshot, SBOM, cryptography, PII/FTI handling, IaC, Docker/Kubernetes, GitHub Actions); the agent then reads the code, confirms or rejects each candidate and writes a timestamped Markdown report with tables, severity, file and line evidence, concrete fixes and mappings to NIST 800-53, IRS Pub 1075 and EOTSS. It needs only Python 3 and git, makes no network calls, never modifies the audited repositories, and writes `security-audit/security-audit-report_<timestamp>.md` plus `sbom.cdx.json`, `scan.json` and `triage.json` (and optionally a SARIF file). Details: [`SKILL.md`](skills/appsec-static-audit/SKILL.md).

### Install

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/appsec-static-audit
```

### Test

Open Codex in the folder you want to work on and run:

```
$appsec-static-audit audit this repository for security
```

### Sample prompts

Run these in Codex from the folder you want to audit (replace the paths and names with your own).

```
$appsec-static-audit audit this repository for security
```

Several repositories as one report (see "One repository or several" below):

```
$appsec-static-audit audit ../platform ../shared-libs ../installer as one workspace called "Acme Platform", exclude **/node_modules and **/target
```

Re-auditing the same code and proving nothing was lost:

```
$appsec-static-audit re-audit this repository into ./security-audit-new and compare with the previous review in ./security-audit-old: list every finding confirmed before and not confirmed now, and why.
```

### One repository or several

```
python3 ~/.codex/skills/appsec-static-audit/scripts/audit.py <repo> --out ./security-audit --name "App name"
python3 ~/.codex/skills/appsec-static-audit/scripts/audit.py <repo-a> <repo-b> <repo-c> --out ./security-audit --name "Platform"
```

With several repositories every path in the report is prefixed with the repository folder name (`repo-a/src/app.py`), components are `repo-a/component`, dependency findings are raised per repository, the SBOM and counts are combined, and each repository's branch, full commit and dirty flag are recorded and shown in the report. Give `--sarif` and `--osv-results` as `NAME=FILE` so they are bound to the right repository, and pass `--repo` once per checkout when rendering so citations and verification packets can find the code.

Useful options: `--exclude GLOB` (repeatable; applies inside each repository), `--jobs N` (parallel scanning, default up to 8), `--suppressions FILE`, `--previous scan.json`, `--no-git-history`, `--advisory-db FILE`. Scanning is parallel and deterministic; on a 2-million-line repository it takes a few minutes.

### What you get

- **Report** (`security-audit-report_<timestamp>.md`): executive summary, scope and limitations, findings register, a control checklist per domain (No., Issue, Status, Evidence), detailed findings with exploit scenario, impact, evidence and fix, compliance mapping, dependencies and SBOM, remediation roadmap, and appendices for scan coverage (scanner fingerprint, repository revisions, per-component coverage and review status) and rejected candidates.
- **Stable IDs**: a finding keeps its `FND-nnn` number across re-scans, so an existing `triage.json` stays valid.
- **Honest status**: controls nobody reviewed show as `NOT ASSESSED`, never as a pass. Low-confidence candidates are capped at Medium until confirmed. The report states how many candidates were decided one by one versus by bulk rule.
- **Verification**: confirmed Critical and High findings can be re-checked blind by a second reader; the report records who agreed, who disputed and whether the verdict is tied to the exact packet reviewed.
- **Re-audits**: `--previous-triage` lists every earlier confirmed finding that this review does not confirm, with its status now.
- **Pipelines**: `--emit-sarif` for code-scanning tools, `--fail-on High` for CI gates, and a suppression policy file for accepted risks and known false positives.

### Maintainers

Run the tests after changing a rule, script or the checklist:

```
python3 -m pytest tests/appsec-static-audit
python3 tests/appsec-static-audit/test_skill.py
```

The dependency advisory snapshot (`references/advisory-db.json.gz`) is built from OSV.dev and should be refreshed regularly; the report warns when it is more than 90 days old. This needs network access and is never run during an audit:

```
python3 skills/appsec-static-audit/tools/build_advisory_db.py
```

A prompt for shipping changes to the skill itself:

```
run the appsec-static-audit tests, then commit and push, open a pull request to main and merge it
```

### Update

To get the latest version, use either option, then restart Codex.

Option 1: ask the installer to update from the URL:

```
$skill-installer update https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/repo-readme-generator
```

Option 2: remove the installed folder and install it again:

```
rm -rf ~/.codex/skills/repo-readme-generator
```

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/repo-readme-generator
```

### Uninstall

```
rm -rf ~/.codex/skills/repo-readme-generator
```

## appsec-static-audit

Source-code-only security audit of one repository or several, for any organization or stack. A scanner finds candidates (injection and other OWASP issues with data-flow tracking, access control, SSO/JWT/SAML, sessions, secrets including git history, dependency vulnerabilities from a bundled OSV snapshot, SBOM, cryptography, PII/FTI handling, IaC, Docker/Kubernetes, GitHub Actions); the agent then reads the code, confirms or rejects each candidate and writes a timestamped Markdown report with tables, severity, file and line evidence, concrete fixes and mappings to NIST 800-53, IRS Pub 1075 and EOTSS. It needs only Python 3 and git, makes no network calls, never modifies the audited repositories, and writes `security-audit/security-audit-report_<timestamp>.md` plus `sbom.cdx.json`, `scan.json` and `triage.json` (and optionally a SARIF file). Details: [`SKILL.md`](skills/appsec-static-audit/SKILL.md).

### Install

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/appsec-static-audit
```

### Test

Open Codex in the folder you want to work on and run:

```
$appsec-static-audit audit this repository for security
```

### Sample prompts

Run these in Codex from the folder you want to audit (replace the paths and names with your own).

```
$appsec-static-audit audit this repository for security
```

Several repositories as one report (see "One repository or several" below):

```
$appsec-static-audit audit ../platform ../shared-libs ../installer as one workspace called "Acme Platform", exclude **/node_modules and **/target
```

Re-auditing the same code and proving nothing was lost:

```
$appsec-static-audit re-audit this repository into ./security-audit-new and compare with the previous review in ./security-audit-old: list every finding confirmed before and not confirmed now, and why.
```

### One repository or several

```
python3 ~/.codex/skills/appsec-static-audit/scripts/audit.py <repo> --out ./security-audit --name "App name"
python3 ~/.codex/skills/appsec-static-audit/scripts/audit.py <repo-a> <repo-b> <repo-c> --out ./security-audit --name "Platform"
```

With several repositories every path in the report is prefixed with the repository folder name (`repo-a/src/app.py`), components are `repo-a/component`, dependency findings are raised per repository, the SBOM and counts are combined, and each repository's branch, full commit and dirty flag are recorded and shown in the report. Give `--sarif` and `--osv-results` as `NAME=FILE` so they are bound to the right repository, and pass `--repo` once per checkout when rendering so citations and verification packets can find the code.

Useful options: `--exclude GLOB` (repeatable; applies inside each repository), `--jobs N` (parallel scanning, default up to 8), `--suppressions FILE`, `--previous scan.json`, `--no-git-history`, `--advisory-db FILE`. Scanning is parallel and deterministic; on a 2-million-line repository it takes a few minutes.

### What you get

- **Report** (`security-audit-report_<timestamp>.md`): executive summary, scope and limitations, findings register, a control checklist per domain (No., Issue, Status, Evidence), detailed findings with exploit scenario, impact, evidence and fix, compliance mapping, dependencies and SBOM, remediation roadmap, and appendices for scan coverage (scanner fingerprint, repository revisions, per-component coverage and review status) and rejected candidates.
- **Stable IDs**: a finding keeps its `FND-nnn` number across re-scans, so an existing `triage.json` stays valid.
- **Honest status**: controls nobody reviewed show as `NOT ASSESSED`, never as a pass. Low-confidence candidates are capped at Medium until confirmed. The report states how many candidates were decided one by one versus by bulk rule.
- **Verification**: confirmed Critical and High findings can be re-checked blind by a second reader; the report records who agreed, who disputed and whether the verdict is tied to the exact packet reviewed.
- **Re-audits**: `--previous-triage` lists every earlier confirmed finding that this review does not confirm, with its status now.
- **Pipelines**: `--emit-sarif` for code-scanning tools, `--fail-on High` for CI gates, and a suppression policy file for accepted risks and known false positives.

### Maintainers

Run the tests after changing a rule, script or the checklist:

```
python3 -m pytest tests/appsec-static-audit
python3 tests/appsec-static-audit/test_skill.py
```

The dependency advisory snapshot (`references/advisory-db.json.gz`) is built from OSV.dev and should be refreshed regularly; the report warns when it is more than 90 days old. This needs network access and is never run during an audit:

```
python3 skills/appsec-static-audit/tools/build_advisory_db.py
```

Sample prompts for working on the skill itself:

```
run the appsec-static-audit tests and fix anything that fails
```

```
commit and push the changes
```

```
open a pull request to main for this branch, then merge it
```

### Update

To get the latest version, use either option, then restart Codex.

Option 1: ask the installer to update from the URL:

```
$skill-installer update https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/appsec-static-audit
```

Option 2: remove the installed folder and install it again:

```
rm -rf ~/.codex/skills/appsec-static-audit
```

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/appsec-static-audit
```

### Uninstall

```
rm -rf ~/.codex/skills/appsec-static-audit
```

On Windows (PowerShell):

```
Remove-Item -Recurse -Force "$env:USERPROFILE\.codex\skills\appsec-static-audit"
```

Files the skill wrote into your projects (`security-audit/`) are not removed with the skill; delete them separately if you no longer need them.

## wave-a11y-scan

WAVE-style accessibility scan of web pages with a client-ready report (WCAG 2.x, Section 508 note). It installs its own dependencies (Playwright and Chromium, about 150 MB) the first time it runs. Automated checks do not prove a page is accessible; manual keyboard and screen-reader testing is still required. Details: [`SKILL.md`](skills/wave-a11y-scan/SKILL.md).

### Install

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/wave-a11y-scan
```

### Test

Open Codex in the folder you want to work on and run:

```
$wave-a11y-scan scan https://example.com
```

### Update

To get the latest version, use either option, then restart Codex.

Option 1: ask the installer to update from the URL:

```
$skill-installer update https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/wave-a11y-scan
```

Option 2: remove the installed folder and install it again:

```
rm -rf ~/.codex/skills/wave-a11y-scan
```

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/wave-a11y-scan
```

### Uninstall

```
rm -rf ~/.codex/skills/wave-a11y-scan
```

Files the skill wrote into your projects (`a11y-report/`) are not removed with the skill. It also leaves Playwright and its Chromium download in the pip and Playwright caches; remove them with `python3 -m pip uninstall playwright` and by deleting `~/.cache/ms-playwright`.

## Uninstalling from inside Codex

`$skill-installer` can only list and install skills; it has no uninstall command. You can still ask Codex to do the removal in plain language:

```
Delete the skill folder ~/.codex/skills/appsec-static-audit
```

Codex runs the delete for you. The folder is outside your project, so Codex asks you to approve the command. Restart Codex afterwards so the skill list refreshes. Do not remove the skills in `~/.codex/skills/.system/` (for example `skill-installer`); Codex manages those. If you use Codex inside WSL, the skills live in the WSL home directory, not the Windows one.
