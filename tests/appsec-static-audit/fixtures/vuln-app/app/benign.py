# Code that earlier versions of the scanner flagged wrongly; none of this should raise a finding.
import logging, subprocess, urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)
controller = {"kind": "x"}
VAULT_REF = {"password": "VAULT:DB_PASSWORD"}
MARKER = Path("/tmp/secrets_seeded_marker")
HEADERS = {"X-Atlassian-Token": "no-check"}
TOKEN_ENV_NAME = "CODEX_API_TOKEN"

def helpers(runner, value, tokens, args, path):
    kind = controller.get("kind")
    runner.write_text("#!/bin/sh\nexec " + value)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    logger.info("Actual token count from static messages: %s", tokens)
    logger.warning("No password found for the username")
    return any(type(v) is type(c) for c in args for v in [value]), _require(path)
