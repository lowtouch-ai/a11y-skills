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
| [`wave-a11y-scan`](skills/wave-a11y-scan) | WAVE-style accessibility scan of web pages with a client-ready report (WCAG 2.x, Section 508 note). |
| [`repo-readme-generator`](skills/repo-readme-generator) | Creates or updates a repo's README, or a full documentation suite with `AGENTS.md` and diagrams, from verified evidence. |

## Install

In Codex, run the command for the skill you want, then restart Codex.

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/wave-a11y-scan
```

```
$skill-installer install https://github.com/lowtouch-ai/krithi-skills/tree/main/skills/repo-readme-generator
```

`wave-a11y-scan` installs its own dependencies (Playwright and Chromium, about 150 MB) the first time it runs.

## Test

Open Codex in the folder you want to work on and run:

```
$wave-a11y-scan scan https://example.com
```

```
$repo-readme-generator create the README for this repo
```

For the full documentation suite: `$repo-readme-generator document this repo fully`

## More

- Skill details: [`wave-a11y-scan/SKILL.md`](skills/wave-a11y-scan/SKILL.md), [`repo-readme-generator/SKILL.md`](skills/repo-readme-generator/SKILL.md)
- Automated checks do not prove a page is accessible; manual keyboard and screen-reader testing is still required.
