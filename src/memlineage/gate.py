#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sensitive-action gate (Capa A, hard block).

Before the agent performs an irreversible/sensitive action, we check whether
the *justification* (the entries recalled and used to decide the action)
descends from an untrusted-path ancestor in the lineage DAG. If so, the gate
HARD-blocks (FPR ~ 0 because it is cryptographic, not heuristic) and escalates.

Constitution #2: this gate relies on write-time origin binding, not a trust
score. It cannot be evaded by the agent paraphrasing external content, because
the lineage edge weight is fixed at derivation time (max-of-strong-edges).
"""

from __future__ import annotations

from dataclasses import dataclass
from .lineage import LineageGraph
from .types import MemoryEntry


@dataclass
class GateVerdict:
    allowed: bool
    reason: str
    untrusted_ancestors: list[str]


class SensitiveActionGate:
    def __init__(self, lineage: LineageGraph, store) -> None:
        self._lineage = lineage
        self._store = store

    def check(
        self, action: str, justification_entry_ids: list[str]
    ) -> GateVerdict:
        """Hard-block if any justification entry is on an untrusted path."""
        untrusted: list[str] = []
        for eid in justification_entry_ids:
            if self._lineage.is_untrusted_path(eid):
                untrusted.append(eid)
        if untrusted:
            return GateVerdict(
                allowed=False,
                reason=(
                    f"Action '{action}' justification descends from untrusted "
                    f"lineage: {untrusted}"
                ),
                untrusted_ancestors=untrusted,
            )
        return GateVerdict(allowed=True, reason="clean", untrusted_ancestors=[])
