# SVG diagrams

Use `scripts/make_svg.py` to turn a small JSON spec into a clean, valid, accessible SVG (labelled boxes, grouped columns or rows, routed arrows, legend, `<title>` and `<desc>`). Never hand-write SVG coordinates: generated output is consistent and can be regenerated when the architecture changes.

## Mermaid or SVG?

| Choose | When |
|---|---|
| **Mermaid** (default in README and docs) | The diagram is small or medium, readers view it on GitHub, you want text diffs and easy edits, or it needs `alt`/`loop`/`par` blocks (sequence) or ER/state/class syntax |
| **SVG** | The user asks for SVG; the diagram must look the same outside GitHub (PDF, wiki, Confluence, slides, package docs); it has many nodes or needs a legend and clear lanes; Mermaid layout comes out tangled |
| **Both** | README gets a compact Mermaid overview; `docs/architecture.md` gets the detailed SVG |

Keep every diagram under about 25 nodes; split by subsystem instead of shrinking text.

## Workflow

1. Write the spec to `docs/diagrams/src/<name>.json`.
2. Render: `python3 <skill-dir>/scripts/make_svg.py docs/diagrams/src/<name>.json docs/diagrams/<name>.svg`
3. Embed with meaningful alt text and explain the diagram in prose underneath:
   `![Logical architecture: browser clients call vote and result services; a worker moves votes from Redis to PostgreSQL](diagrams/architecture.svg)`
4. Look at the result if a browser is available (for example open the SVG, or screenshot it inside an HTML `<img>`), and fix the spec if labels collide or lines cross awkwardly. Reorder `nodes`, or change `groups`, then re-render.
5. Commit both the spec and the SVG. On updates, edit the spec and re-render; never edit the SVG by hand.

## Architecture spec

```json
{
  "title": "Voting app architecture",
  "description": "Optional sentence for screen readers (generated from nodes and edges if omitted).",
  "direction": "LR",
  "groups": [{"id": "clients", "label": "Clients"}, {"id": "services", "label": "Services"}, {"id": "data", "label": "Data stores"}],
  "nodes": [
    {"id": "ui",  "label": "Browser UI", "sub": "vote/templates", "group": "clients",  "kind": "client"},
    {"id": "api", "label": "vote (Flask)", "sub": "vote/app.py",  "group": "services", "kind": "service"},
    {"id": "q",   "label": "Redis", "sub": "votes list",          "group": "data",     "kind": "store"}
  ],
  "edges": [{"from": "ui", "to": "api", "label": "POST /"}, {"from": "api", "to": "q", "label": "RPUSH", "style": "solid"}]
}
```

- `direction`: `LR` makes groups columns left to right, `TB` makes them rows top to bottom. List groups in flow order: clients, entry points, services, data stores, external integrations.
- `kind`: `client`, `service`, `store` (cylinder), `external`, `tool`, `planned` (dashed; use for unimplemented components).
- `sub`: second line, usually the source path. `label` is the component name used in the docs.
- `style`: `solid` or `dashed` (use dashed for optional, async or configured-but-unused links).
- Edges that skip a group are routed around the diagram automatically.
- Every node must correspond to a row in the Component Inventory and every edge to something you verified.

## Sequence spec

```json
{
  "type": "sequence", "title": "Vote flow",
  "participants": [{"id": "U", "label": "Browser"}, {"id": "V", "label": "vote"}, {"id": "Q", "label": "Redis"}],
  "messages": [
    {"from": "U", "to": "V", "label": "POST /"},
    {"from": "V", "to": "Q", "label": "RPUSH votes"},
    {"from": "V", "to": "U", "label": "HTML + cookie", "style": "dashed"}
  ]
}
```

Messages are drawn top to bottom in the order listed; `from` equal to `to` draws a self-call. For branches or loops use a Mermaid sequence diagram instead.

## Checks

`scripts/validate_docs.py` verifies: well-formed XML, `viewBox`, `<title>`/`<desc>`, no scripts or event handlers, no external references, labels present, referenced from a Markdown file, and spec/SVG pairing (spec newer than SVG means re-render).
