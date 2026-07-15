#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derivation DAG with max-of-strong-edges propagation (Capa A, lineage).

Implements the core invariant of MemLineage (2605.14421): Untrusted-Path
Persistence. An edge weight cannot rise above the maximum of its sources.
Therefore a memory derived (even transitively) from an EXTERNAL/untrusted
ancestor can NEVER be laundered into INTERNAL/trusted by the agent's own
summarization, paraphrase, or trusted-tool echo. This directly defeats the
"laundering" channels TMA-NM (2606.24322) proves defeat content/lineage
defenses that re-derive verdict at dispatch.
"""

from __future__ import annotations

from .types import MemoryEntry, TrustTier

# Numeric weight per tier. Lower = less trusted. Edges inherit the MAX of
# source weights, so untrusted can only stay or get worse down the chain.
_TIER_WEIGHT: dict[TrustTier, int] = {
    TrustTier.INTERNAL: 0,
    TrustTier.USER: 1,
    TrustTier.UNVERIFIED: 2,
    TrustTier.EXTERNAL: 3,
}

# Threshold: a node with effective weight >= this is "untrusted path".
UNTRUSTED_THRESHOLD = _TIER_WEIGHT[TrustTier.UNVERIFIED]


def _min_tier_for_weight(w: int) -> TrustTier:
    inv = {v: k for k, v in _TIER_WEIGHT.items()}
    return inv.get(w, TrustTier.EXTERNAL)


class LineageGraph:
    """Directed acyclic graph of memory derivation."""

    def __init__(self) -> None:
        # node -> set of parent ids it was derived from
        self._parents: dict[str, set[str]] = {}
        # node -> effective weight (max-of-strong-edges)
        self._weight: dict[str, int] = {}
        # node -> declared write-time tier
        self._declared: dict[str, TrustTier] = {}

    def add_node(self, entry: MemoryEntry) -> None:
        self._declared[entry.entry_id] = entry.tier
        base = _TIER_WEIGHT[entry.tier]
        self._parents.setdefault(entry.entry_id, set())
        for pid in entry.derived_from:
            if pid in self._weight or pid in self._declared:
                self._parents[entry.entry_id].add(pid)
        # effective weight = max(own declared, max of parents) => cannot rise
        self._recompute(entry.entry_id)

    def _recompute(self, node: str) -> None:
        # propagate bottom-up-ish (parents first); simple recursive w/ memo
        visited: set[str] = set()

        def eff(n: str) -> int:
            if n in visited:
                return self._weight.get(n, _TIER_WEIGHT[TrustTier.EXTERNAL])
            visited.add(n)
            own = _TIER_WEIGHT[self._declared.get(n, TrustTier.UNVERIFIED)]
            parents = self._parents.get(n, set())
            if not parents:
                w = own
            else:
                w = max([own] + [eff(p) for p in parents])
            self._weight[n] = w
            return w

        eff(node)
        # update propagated tiers on all reachable descendants lazily:
        # we just recompute the touched node and any node listing it as parent
        for child, pars in self._parents.items():
            if node in pars:
                self._recompute(child)

    def effective_tier(self, entry_id: str) -> TrustTier:
        w = self._weight.get(entry_id, _TIER_WEIGHT[TrustTier.UNVERIFIED])
        return _min_tier_for_weight(w)

    def is_untrusted_path(self, entry_id: str) -> bool:
        """True if the node or any ancestor is external/unverified."""
        return self._weight.get(
            entry_id, _TIER_WEIGHT[TrustTier.UNVERIFIED]
        ) >= UNTRUSTED_THRESHOLD

    def ancestors(self, entry_id: str) -> set[str]:
        out: set[str] = set()
        stack = list(self._parents.get(entry_id, set()))
        while stack:
            p = stack.pop()
            if p in out:
                continue
            out.add(p)
            stack.extend(self._parents.get(p, set()))
        return out
