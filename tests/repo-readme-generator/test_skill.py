#!/usr/bin/env python3
"""Self-test for repo-readme-generator scripts. Run: python tests/repo-readme-generator/test_skill.py"""
import json, subprocess, sys
from pathlib import Path

here = Path(__file__).resolve().parent
root = here.parent.parent
S = root / "skills/repo-readme-generator/scripts"
fx = here / "fixtures"
fails = []

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

print("\nOK" if not fails else f"\n{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
