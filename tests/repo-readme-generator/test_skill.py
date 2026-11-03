#!/usr/bin/env python3
"""Self-test for repo-readme-generator scripts. Run: python tests/repo-readme-generator/test_skill.py"""
import json, subprocess, sys
from pathlib import Path

here = Path(__file__).resolve().parent
root = here.parent.parent
S = root / "skills/repo-readme-generator/scripts"
fx = here / "fixtures"
fails = []
import re, shutil, tempfile, xml.etree.ElementTree as ET
tmp = Path(tempfile.mkdtemp())

def run(*a):
    return subprocess.run([sys.executable, *map(str, a)], capture_output=True, text=True)

def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name); print(detail)

# discover
d = json.loads(run(S / "discover.py", fx / "node-app").stdout)
check("discover: entry point", "src/server.js" in d["entry_points"])
check("discover: env vars", set(d["env_vars"]) >= {"DATABASE_URL", "REDIS_URL", "PORT"})
check("discover: compose services", set(d["manifests"]["compose"][0]["services"]) == {"api", "db", "cache"})
check("discover: routes", len(d["route_hints"]) == 3)

# good README validates cleanly
g = run(S / "validate_readme.py", fx / "node-app/README.md", "--json")
items = json.loads(g.stdout)
errors = [i for i in items if i["level"] == "ERROR"]
check("validate: good README has no errors", g.returncode == 0 and not errors, g.stdout)
check("validate: good README has no section warnings", not [i for i in items if i["check"] == "sections"], g.stdout)

# bad README is caught
b = json.loads(run(S / "validate_readme.py", fx / "bad-readme.md", "--root", fx / "node-app", "--json").stdout)
kinds = {(i["level"], i["check"]) for i in b}
for want in [("ERROR", "link"), ("ERROR", "anchor"), ("ERROR", "command"), ("ERROR", "mermaid"), ("ERROR", "secret"), ("ERROR", "fence"), ("WARN", "sections")]:
    check(f"validate: bad README flags {want[1]}", want in kinds, json.dumps(b)[:600])
check("validate: bad README exits 1", run(S / "validate_readme.py", fx / "bad-readme.md", "--root", fx / "node-app").returncode == 1)

# regression: flags such as `up -d` must not be read as a compose service name
flagmd = fx / "node-app/README.flags.md"
flagmd.write_text("# t\n\n```shell\ndocker compose --profile seed up -d\ndocker compose up -d db\n```\n")
try:
    out = run(S / "validate_readme.py", flagmd, "--root", fx / "node-app").stdout
    check("validate: `up -d` is not treated as a service", "service '-d'" not in out, out)
finally:
    flagmd.unlink()

# drift: complete README has none of the key drift; stripped README has plenty
ok = run(S / "check_drift.py", fx / "node-app/README.md").stdout
check("drift: complete README reports no drift", "No drift detected" in ok, ok)
stripped = fx / "node-app/README.stripped.md"
stripped.write_text("# orders-api\n\nJust a stub.\n")
try:
    bad = run(S / "check_drift.py", stripped).stdout
    check("drift: finds undocumented env vars", "DATABASE_URL" in bad, bad)
    check("drift: finds undocumented npm scripts", "npm script `dev`" in bad, bad)
    check("drift: finds undocumented compose services", "Compose service `cache`" in bad, bad)
finally:
    stripped.unlink()

# ---- validator accepts valid-but-unusual Markdown/Mermaid and still catches real errors
ec = fx / "edge-cases"
res = json.loads(run(S / "validate_readme.py", ec / "README.md", "--json").stdout)
errs = [i for i in res if i["level"] == "ERROR"]
check("validate edge cases: only the genuinely broken reference link is an error",
      len(errs) == 1 and errs[0]["check"] == "link" and "missing.md" in errs[0]["message"], json.dumps(errs))
check("validate edge cases: Setext headings count as headings", not [i for i in res if "exactly one H1" in i["message"]])
real = fx / "edge-cases/README.real.md"
real.write_text("# T\n\n```mermaid\nflowchart TB\n    A[Open (x] --> B\n    subgraph s\n        C\n```\n\n```mermaid\nsequenceDiagram\n    A->>B: x\n    alt a\n        B-->>A: y\n```\n")
try:
    rs = json.loads(run(S / "validate_readme.py", real, "--json").stdout)
    mm = [i["message"] for i in rs if i["check"] == "mermaid" and i["level"] == "ERROR"]
    check("mermaid: unbalanced flowchart bracket still caught", any("Unbalanced" in m for m in mm), str(mm))
    check("mermaid: subgraph without end still caught", any("opener" in m for m in mm), str(mm))
    check("mermaid: sequence alt without end still caught", len([m for m in mm if "opener" in m]) >= 2, str(mm))
finally:
    real.unlink()
sec = fx / "edge-cases/README.sections.md"
sec.write_text("# T\n\n## Project Overview\n\n## Running tests\n")
try:
    rs = json.loads(run(S / "validate_readme.py", sec, "--json").stdout)
    miss = [i["message"] for i in rs if i["check"] == "sections"]
    check("sections: one heading cannot satisfy both Running and Testing", any("Running the Application" in m for m in miss) != any("Testing" in m for m in miss), str(miss))
finally:
    sec.unlink()

# ---- non-UTF-8 console must not crash the validators
uni = fx / "edge-cases/README.unicode.md"
uni.write_text("# T\n\nSee `docs/\u2192missing\u00d7file.md` and [x](docs/\u2192gone.md).\n", encoding="utf-8")
try:
    import os
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    r = subprocess.run([sys.executable, str(S / "validate_readme.py"), str(uni)], capture_output=True, text=True, env=env)
    check("encoding: validator survives characters a cp1252 console cannot print", "Traceback" not in r.stderr and "error(s)" in r.stdout, r.stderr[-300:])
finally:
    uni.unlink()

# ---- make_svg gives clear errors instead of tracebacks
def svg_err(spec):
    f = tmp / "e.json"; f.write_text(json.dumps(spec))
    r = run(S / "make_svg.py", f, tmp / "e.svg")
    return r.returncode, r.stderr + r.stdout
gs = [{"id": "g", "label": "G"}]
for name, spec, needle in [
    ("unknown kind", {"groups": gs, "nodes": [{"id": "a", "label": "A", "group": "g", "kind": "database"}]}, "kind 'database'"),
    ("unknown group", {"groups": gs, "nodes": [{"id": "a", "label": "A", "group": "zz"}]}, "group 'zz'"),
    ("duplicate node id", {"groups": gs, "nodes": [{"id": "a", "label": "A", "group": "g"}, {"id": "a", "label": "B", "group": "g"}]}, "duplicate node id"),
    ("self edge", {"groups": gs, "nodes": [{"id": "a", "label": "A", "group": "g"}], "edges": [{"from": "a", "to": "a"}]}, "itself"),
    ("missing label", {"groups": gs, "nodes": [{"id": "a", "group": "g"}]}, "label is missing"),
    ("oversized label", {"groups": gs, "nodes": [{"id": "a", "label": "x" * 300, "group": "g"}]}, "max 60"),
    ("sequence unknown participant", {"type": "sequence", "participants": [{"id": "a", "label": "A"}], "messages": [{"from": "a", "to": "q"}]}, "not a participant"),
]:
    code, out = svg_err(spec)
    check(f"svg validation: {name} gives a clear error", code != 0 and "Traceback" not in out and needle in out, out[-250:])
bad_json = tmp / "nj.json"; bad_json.write_text("not json")
r = run(S / "make_svg.py", bad_json, tmp / "nj.svg")
check("svg validation: invalid JSON gives a clear error", r.returncode != 0 and "Traceback" not in r.stderr and "cannot read spec" in r.stderr, r.stderr[-200:])

# ---- discovery: real-world gaps found on a PyTorch repo
ml = tmp / "ml"
(ml / "configs").mkdir(parents=True); (ml / "data/test").mkdir(parents=True); (ml / "mpi").mkdir()
(ml / "requirements.txt").write_text("torch\nnumpy>=1.2\nhydra-core\nonnxruntime-gpu\n")
(ml / "data/test/.gitkeep").write_text("")
(ml / "configs/train.yaml").write_text("epochs: 3\n")
(ml / "mpi/run.sh").write_text("#!/bin/bash\n# launch training on all nodes\nmpirun python train.py\n")
(ml / "train.py").write_text("if __name__ == '__main__':\n    pass\n")
mld = json.loads(run(S / "discover.py", ml).stdout)
check("discover: ML stack hints (torch, numpy, hydra)", {"torch", "numpy"} <= set(mld["stack_hints"].get("ml/data", [])) and "hydra-core" in mld["stack_hints"].get("configuration", []), str(mld["stack_hints"]))
check("discover: a .gitkeep under data/test is not a test", mld["tests"]["files"] == 0, str(mld["tests"]))
check("discover: config files listed", "configs/train.yaml" in mld["config_files"], str(mld["config_files"]))
check("discover: shell scripts listed with their purpose", any(x["file"] == "mpi/run.sh" and "launch training" in x["note"] for x in mld["shell_scripts"]), str(mld["shell_scripts"]))

# ---- paths relative to a subfolder and .gitignore entries are not reported as missing
gi = tmp / "gi"
(gi / "modeling").mkdir(parents=True); (gi / "data/train").mkdir(parents=True)
(gi / ".gitignore").write_text("/saved_models/\n")
(gi / "README.md").write_text("# T\n\nDefaults: `../data/train` and `../saved_models`; output goes to `saved_models/`.\n")
rg = json.loads(run(S / "validate_readme.py", gi / "README.md", "--json").stdout)
check("validate: ../ paths and gitignored paths are not flagged", not [i for i in rg if i["check"] == "path-ref"], str([i["message"] for i in rg if i["check"] == "path-ref"]))

# ---- SVG generation
docs_fx = fx / "node-app-docs"
spec = docs_fx / "docs/diagrams/src/architecture.json"
r = run(S / "make_svg.py", spec, tmp / "a.svg")
check("svg: architecture renders", r.returncode == 0, r.stderr)
tree = ET.parse(tmp / "a.svg").getroot()
texts = " ".join((e.text or "") for e in tree.iter() if e.tag.endswith("text"))
check("svg: node labels present", "API server" in texts and "PostgreSQL" in texts and "HTTP clients" in texts, texts)
check("svg: accessible (title, desc, viewBox)", tree.get("viewBox") and any(e.tag.endswith("title") for e in tree.iter()) and any(e.tag.endswith("desc") for e in tree.iter()))
check("svg: planned node is dashed and marked", "(Planned)" in texts and "stroke-dasharray" in (tmp / "a.svg").read_text())
seq = docs_fx / "docs/diagrams/src/order-listing.json"
check("svg: sequence renders", run(S / "make_svg.py", seq, tmp / "s.svg").returncode == 0 and "GET /orders" in (tmp / "s.svg").read_text())
bad_spec = tmp / "bad.json"
bad_spec.write_text(json.dumps({"groups": [{"id": "g", "label": "G"}], "nodes": [{"id": "a", "label": "A", "group": "g"}], "edges": [{"from": "a", "to": "ghost"}]}))
check("svg: unknown edge node is rejected", run(S / "make_svg.py", bad_spec, tmp / "b.svg").returncode != 0)
tb = tmp / "tb.json"
tb.write_text(json.dumps({"direction": "TB", "groups": [{"id": "a", "label": "Top"}, {"id": "b", "label": "Middle"}, {"id": "c", "label": "Bottom"}],
    "nodes": [{"id": "x", "label": "X", "group": "a"}, {"id": "y", "label": "Y", "group": "b"}, {"id": "z", "label": "Z", "group": "c", "kind": "store"}],
    "edges": [{"from": "x", "to": "y"}, {"from": "y", "to": "z"}, {"from": "x", "to": "z", "label": "skip"}]}))
check("svg: top-to-bottom with a skipping edge renders valid XML", run(S / "make_svg.py", tb, tmp / "tb.svg").returncode == 0 and ET.parse(tmp / "tb.svg") is not None)

# ---- documentation suite validation
ok = run(S / "validate_docs.py", "--root", docs_fx, "--strict")
check("docs: complete suite passes even in --strict", ok.returncode == 0, ok.stdout)
suite = tmp / "suite"
shutil.copytree(docs_fx, suite)
(suite / "docs/diagrams/unsafe.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><script>alert(1)</script><text>x</text></svg>')
(suite / "docs/diagrams/broken.svg").write_text("<svg><oops")
(suite / "docs/diagrams/src/orphan.json").write_text("{}")
(suite / "docs/unlinked.md").write_text("# Unlinked\n\nReplace {{project}} here.\n")
(suite / "AGENTS.md").write_text("# AGENTS.md\n\n" + "x" * 40000)
(suite / "docs/architecture.md").write_text((suite / "docs/architecture.md").read_text() + "\n![x](diagrams/unsafe.svg)\n![y](diagrams/broken.svg)\n")
res = json.loads(run(S / "validate_docs.py", "--root", suite, "--json").stdout)
found = {(i["level"], i["check"]) for i in res}
for want in [("ERROR", "svg"), ("ERROR", "template"), ("ERROR", "diagram-spec"), ("WARN", "index"), ("WARN", "agents")]:
    check(f"docs: broken suite flags {want[1]}", want in found, str(sorted(found)))
check("docs: unsafe SVG script is an error", any(i["level"] == "ERROR" and "script" in i["message"] for i in res))
check("docs: malformed SVG is an error", any(i["level"] == "ERROR" and "well-formed" in i["message"] for i in res))
check("docs: broken suite exits 1", run(S / "validate_docs.py", "--root", suite).returncode == 1)
(suite / "docs/diagrams/src/architecture.json").touch()
stale = json.loads(run(S / "validate_docs.py", "--root", suite, "--json").stdout)
check("docs: spec newer than svg is flagged", any(i["check"] == "diagram-spec" and "newer" in i["message"] for i in stale))

# ---- drift across the suite
stub = tmp / "drift"
shutil.copytree(docs_fx, stub)
(stub / "README.md").write_text("# orders-api\n\nStub.\n")
with_docs = run(S / "check_drift.py", stub / "README.md").stdout
without = run(S / "check_drift.py", stub / "README.md", "--docs", "nonexistent").stdout
(stub / "AGENTS.md").unlink()
check("drift: variables documented under docs/ are not reported", "Environment variable `DATABASE_URL`" not in with_docs, with_docs)
check("drift: without docs the same variables are reported", "Environment variable `DATABASE_URL`" in without, without)

# ---- drift: stale tree entries (trees usually start with "." so the old check never fired), generated dirs, system vars
dr = tmp / "dr"
(dr / "src").mkdir(parents=True)
(dr / ".gitignore").write_text("dist/\nsaved_models/\n")
(dr / "run.sh").write_text("#!/bin/bash\necho ${PWD} ${MY_API_URL}\n")
(dr / "src/app.py").write_text("print(1)\n")
(dr / "README.md").write_text("# demo\n\n```text\n.\n├── src/\n├── dist/\n├── node_modules/\n├── saved_models/\n├── gone_dir/\n└── run.sh\n```\n\nUses `MY_API_URL`, entry `src/app.py`.\n")
dro = run(S / "check_drift.py", dr / "README.md").stdout
check("drift: stale tree entry is reported even when the tree starts with '.'", "Tree entry `gone_dir/` no longer exists" in dro, dro)
check("drift: gitignored and dependency dirs in a tree are not reported stale", "`dist/`" not in dro and "`node_modules/`" not in dro and "`saved_models/`" not in dro, dro)
check("drift: system variables such as PWD are not reported", "`PWD`" not in dro, dro)

# ---- richer discovery
dd = json.loads(run(S / "discover.py", docs_fx).stdout)
check("discover: dependency versions", dd["manifests"]["package.json"][0]["dependency_versions"].get("express") == "^4.19.0")
check("discover: stack hints", "express" in dd["stack_hints"].get("web/framework", []) and "pg" in dd["stack_hints"].get("database/orm", []))

# ---- discovery false positives seen on a large monorepo: barrel index files, shell-local variables, JS template literals
fp = tmp / "fp"
(fp / "lib/widgets").mkdir(parents=True)
(fp / "server").mkdir()
(fp / "lib/index.ts").write_text("export * from './widgets';\nexport { A } from './a';\n")
(fp / "lib/widgets/index.ts").write_text("import { A } from '../a';\nexport default A;\n")
(fp / "server/index.js").write_text("const app = require('express')();\napp.listen(process.env.RATE_LIMIT || 3000);\n")
(fp / "build.sh").write_text("#!/bin/bash\nUI_DIR=$(pwd)\nfor T in a b; do echo ${T}; done\necho ${UI_DIR} ${DEPLOY_TOKEN} $NODE_PATH\nperl -pe 's/x/$ENV{HOME}/' f\n")
(fp / "lib/Header.tsx").write_text("const h = `${HEADER_HEIGHT}px`;\n")
fpd = json.loads(run(S / "discover.py", fp).stdout)
check("discover: a re-export-only index.ts is not an entry point", "lib/index.ts" not in fpd["entry_points"] and "lib/widgets/index.ts" not in fpd["entry_points"], str(fpd["entry_points"]))
check("discover: an index.js that starts a server is an entry point", "server/index.js" in fpd["entry_points"], str(fpd["entry_points"]))
check("discover: variables a shell script assigns itself are not env vars", not {"UI_DIR", "T"} & set(fpd["env_vars"]), str(fpd["env_vars"]))
check("discover: variables a shell script only reads are env vars", {"DEPLOY_TOKEN", "NODE_PATH"} <= set(fpd["env_vars"]), str(fpd["env_vars"]))
check("discover: a Perl $ENV{...} hash in a shell script is not an env var", "ENV" not in fpd["env_vars"], str(fpd["env_vars"]))
check("discover: ${X} in a TSX template literal is not an env var", "HEADER_HEIGHT" not in fpd["env_vars"], str(fpd["env_vars"]))
check("discover: process.env reads are still found", "RATE_LIMIT" in fpd["env_vars"], str(fpd["env_vars"]))

# ---- the skill instructs the model to audit its claims against the code before reporting
skill_md = (S.parent / "SKILL.md").read_text(encoding="utf-8")
check("skill: workflow has a verify-against-code step before the report", skill_md.index("### 5. Verify against the code") < skill_md.index("### 7. Report"))
check("skill: verification checklist exists and is referenced", (S.parent / "references/verification-checklist.md").is_file() and "references/verification-checklist.md" in skill_md)
check("skill: every referenced file exists", all((S.parent / "references" / m).is_file() for m in re.findall(r"references/([\w.-]+\.md)", skill_md)))
check("skill: report requires verification results", "Verification results" in skill_md)

print("\nOK" if not fails else f"\n{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
