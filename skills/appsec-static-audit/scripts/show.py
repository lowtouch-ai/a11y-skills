#!/usr/bin/env python3
"""Print source lines with secrets masked, for safe review while triaging.

Usage: show.py FILE[:START[:END]] [...]
Masks known secret formats, credential-looking literals, SSNs, and the body of private keys. Read-only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit import redact_line  # noqa: E402


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for arg in sys.argv[1:]:
        parts = arg.rsplit(":", 2) if arg.count(":") >= 1 and arg.rsplit(":", 1)[-1].isdigit() else [arg]
        if len(parts) == 3 and parts[1].isdigit():
            path, lo, hi = parts[0], int(parts[1]), int(parts[2])
        elif len(parts) == 2 and parts[1].isdigit():
            path, lo, hi = parts[0], int(parts[1]), int(parts[1]) + 20
        else:
            path, lo, hi = arg, 1, 10 ** 9
        print(f"== {path}")
        in_key = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if "-----BEGIN" in line and "PRIVATE KEY" in line:
                    in_key = True
                shown = "[PRIVATE KEY MATERIAL MASKED]" if in_key else redact_line(line.rstrip("\n"))
                if "-----END" in line and "PRIVATE KEY" in line:
                    in_key = False
                if lo <= i <= hi:
                    print(f"{i}: {shown}")


if __name__ == "__main__":
    main()
