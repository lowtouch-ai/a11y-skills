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
| [`appsec-static-audit`](#appsec-static-audit) | Source-code-only security audit (OWASP, SSO, secrets, IaC, SBOM, PII/FTI) with a timestamped enterprise report mapped to NIST 800-53, IRS Pub 1075 and EOTSS. |
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

To get the latest version, remove the installed folder and install it again, then restart Codex:

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

Source-code-only security audit (OWASP, SSO, secrets, IaC, SBOM, PII/FTI) with a timestamped enterprise report mapped to NIST 800-53, IRS Pub 1075 and EOTSS. It needs only Python 3 and git; it makes no network calls and writes `security-audit/security-audit-report_<timestamp>.md` plus an SBOM. Details: [`SKILL.md`](skills/appsec-static-audit/SKILL.md).

### Install

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/appsec-static-audit
```

### Test

Open Codex in the folder you want to work on and run:

```
$appsec-static-audit audit this repository for security
```

### Update

To get the latest version, remove the installed folder and install it again, then restart Codex:

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

To get the latest version, remove the installed folder and install it again, then restart Codex:

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
