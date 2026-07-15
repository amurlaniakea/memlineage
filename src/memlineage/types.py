#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Memory entry types shared across layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustTier(str, Enum):
    """Origin tiers. These are DECLARED at write-time from the principal,
    not derived by a mutable trust score. A memory's tier can never be
    upgraded after write (Constitution #2: no laundering)."""

    INTERNAL = "internal"      # the agent itself, under its own authority
    USER = "user"              # a trusted human operator
    EXTERNAL = "external"      # untrusted external content (recalled doc, web, tool echo)
    UNVERIFIED = "unverified"  # unknown principal, no key


@dataclass
class MemoryEntry:
    entry_id: str
    content: Any
    source: str               # principal id (e.g. "user:alice", "external:web")
    tier: TrustTier
    created_at: float
    content_hash: str
    signature: str | None = None
    public_key_pem: str | None = None
    # Lineage: ids of entries whose retrieval influenced this write.
    derived_from: list[str] = field(default_factory=list)
    # Effective trust weight after lineage propagation (set by LineageGraph).
    effective_tier: TrustTier = TrustTier.UNVERIFIED
    tags: list[str] = field(default_factory=list)


@dataclass
class RecallContext:
    """What was retrieved when a NEW memory was written. Used to populate
    the derivation DAG (Capa A)."""

    retrieved_ids: list[str]
