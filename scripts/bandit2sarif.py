#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Convert bandit JSON output to SARIF 2.1.0 for GitHub Code Scanning.

bandit's built-in SARIF formatter is not always available; this tiny,
dependency-free converter lets CI upload SAST results reliably.
Usage: bandit -r src -f json -o bandit.json && python scripts/bandit2sarif.py bandit.json bandit.sarif
"""
from __future__ import annotations
import json
import sys
from pathlib import Path


def _safe_path(arg: str, *, must_exist: bool) -> Path:
    """Validate a CLI path argument before touching the filesystem.

    Prevents path-traversal / arbitrary-FS-access from faulty CLI args:
    resolve and ensure the path is either pre-existing inside the current
    working tree, or (for outputs) a normal file path. Rejects absolute paths
    pointing outside CWD and any '..' escape.
    """
    p = Path(arg)
    if p.is_absolute():
        raise SystemExit(f"refusing absolute path (FS restriction): {arg}")
    resolved = p.resolve()
    cwd = Path.cwd().resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError:
        raise SystemExit(f"refusing path outside working tree: {arg}")
    if must_exist and not resolved.is_file():
        raise SystemExit(f"input file not found: {arg}")
    return resolved


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: bandit2sarif.py <in.json> <out.sarif>", file=sys.stderr)
        return 2
    src = _safe_path(sys.argv[1], must_exist=True)
    out = _safe_path(sys.argv[2], must_exist=False)
    data = json.loads(src.read_text())

    rules: dict[str, dict] = {}
    results = []
    base = str(Path.cwd().resolve())
    for r in data.get("results", []):
        test = r.get("test_id", r.get("test_name", "B"))
        rid = f"bandit-{test}"
        rules.setdefault(rid, {
            "id": rid,
            "shortDescription": {"text": r.get("test_name", test)},
            "fullDescription": {"text": r.get("issue_text", "")},
            "helpUri": "https://bandit.readthedocs.io/en/latest/blacklists/",
        })
        fname = r.get("filename", "")
        try:
            rel = str(Path(fname).resolve()).replace(base, "").lstrip("/")
        except Exception:
            rel = fname
        results.append({
            "ruleId": rid,
            "level": "warning",
            "message": {"text": r.get("issue_text", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {
                        "startLine": r.get("line_number", 1),
                        "endLine": r.get("line_number", 1),
                    },
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Bandit",
                    "informationUri": "https://bandit.readthedocs.io/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    out.write_text(json.dumps(sarif, indent=2))
    print(f"[bandit2sarif] wrote {len(results)} results -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
