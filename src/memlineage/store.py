#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Signed memory store with cryptographic provenance (Capa A, core).

CORRECTED per audit: `tier` is NEVER a caller-chosen argument. It is derived
from the registered principal that signs the entry. An attacker without the
internal principal's private key cannot produce an INTERNAL-signed entry, so
the lineage graph's untrusted-path propagation is now rooted in real
cryptographic origin, not a mutable label.

If the caller is unknown to the KeyRegistry (no key), the entry is rejected
at write time — provenance is mandatory, not optional.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from .keyreg import KeyRegistry
from .types import MemoryEntry, TrustTier
from .crypto import sha256_hex


class MemoryStore:
    def __init__(self, registry: KeyRegistry) -> None:
        self._registry = registry
        self._entries: dict[str, MemoryEntry] = {}

    def write(
        self,
        content: Any,
        source: str,
        derived_from: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> MemoryEntry:
        """Write a memory. `tier` is derived from the signing principal, NOT
        passed by the caller. Raises if `source` is unknown to the registry."""
        if not self._registry.known_principal(source):
            raise PermissionError(
                f"unknown principal '{source}': provenance required, write refused"
            )
        tier = TrustTier(self._registry.tier_of(source))
        signer = self._registry.signer_for(source)
        entry_id = uuid.uuid4().hex
        created_at = time.time()
        content_hash = sha256_hex(
            str(content).encode("utf-8")
            if not isinstance(content, (bytes, bytearray))
            else content
        )
        sig, pub = signer.sign_entry(
            entry_id=entry_id, content=content, source=source,
            created_at=created_at, content_hash=content_hash,
        )
        entry = MemoryEntry(
            entry_id=entry_id, content=content, source=source, tier=tier,
            created_at=created_at, content_hash=content_hash,
            signature=sig, public_key_pem=pub,
            derived_from=list(derived_from or []),
            effective_tier=tier, tags=list(tags or []),
        )
        self._entries[entry_id] = entry
        return entry

    def get(self, entry_id: str) -> MemoryEntry | None:
        return self._entries.get(entry_id)

    def all(self) -> list[MemoryEntry]:
        return list(self._entries.values())

    def verify(self, entry: MemoryEntry) -> bool:
        if entry.signature is None or entry.public_key_pem is None:
            return False
        if sha256_hex(
            str(entry.content).encode("utf-8")
            if not isinstance(entry.content, (bytes, bytearray))
            else entry.content
        ) != entry.content_hash:
            return False
        return self._registry.verify_entry(
            entry_id=entry.entry_id, content=entry.content, source=entry.source,
            created_at=entry.created_at, content_hash=entry.content_hash,
            signature=entry.signature, public_key_pem=entry.public_key_pem,
        )
