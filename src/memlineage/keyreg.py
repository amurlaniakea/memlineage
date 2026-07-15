#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Key registry: binds each principal to its OWN Ed25519 keypair.

Principle (Constitution #2, enforced at last): origin-binding must be
cryptographic and write-time. The tier of a memory is NOT chosen by the
caller — it is derived from WHICH KEY signed it. A principal "internal" holds
a private key only it knows; an external principal (web, tool echo) holds its
own distinct key. An attacker who calls write() with tier=INTERNAL but cannot
produce a signature from the internal private key is rejected.

SECURITY INVARIANT (audit finding #2):
  `register()` may ONLY be called during trusted initialization (by the
  operator / deployment code). Once `freeze()` is called, the registry is
  immutable for the rest of the process. Runtime agent logic, retrieved
  content, or any untrusted code path MUST NOT be able to call register() to
  mint itself an "internal" principal. Freezing is the enforcement: after
  freeze(), register() raises RegistryFrozenError. The operator is expected to
  register all legitimate principals at boot, then freeze() before the agent
  starts handling untrusted input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .crypto import KeyPair, Signer, sha256_hex


class RegistryFrozenError(Exception):
    """Raised when register() is called after the registry was frozen."""


@dataclass(frozen=True)
class Principal:
    principal_id: str
    tier: str  # declared tier of THIS principal (internal/user/external/unverified)


class KeyRegistry:
    """Maps principal_id -> (keypair, declared tier)."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}
        self._tiers: dict[str, str] = {}
        self._frozen = False

    # ----- trusted initialization only -----
    def register(self, principal: Principal) -> None:
        if self._frozen:
            raise RegistryFrozenError(
                f"registry frozen; cannot register '{principal.principal_id}'. "
                "Register all principals at boot, then freeze()."
            )
        if principal.principal_id in self._keys:
            raise ValueError(f"principal {principal.principal_id} already registered")
        self._keys[principal.principal_id] = KeyPair.generate()
        self._tiers[principal.principal_id] = principal.tier

    def freeze(self) -> None:
        """Lock the registry. No further register() allowed. Call once at boot,
        after all legitimate principals are registered and BEFORE the agent
        processes untrusted input."""
        self._frozen = True

    @property
    def frozen(self) -> bool:
        return self._frozen

    def tier_of(self, principal_id: str) -> str:
        return self._tiers.get(principal_id, "unverified")

    def signer_for(self, principal_id: str) -> Signer:
        kp = self._keys.get(principal_id)
        if kp is None:
            raise KeyError(f"unknown principal: {principal_id}")
        return Signer(kp)

    def public_pem_for(self, principal_id: str) -> str:
        kp = self._keys.get(principal_id)
        if kp is None:
            raise KeyError(f"unknown principal: {principal_id}")
        return kp.public_pem()

    def known_principal(self, principal_id: str) -> bool:
        return principal_id in self._keys

    def verify_entry(self, *, entry_id, content, source, created_at,
                     content_hash, signature, public_key_pem) -> bool:
        if not self.known_principal(source):
            return False
        expected_pem = self.public_pem_for(source)
        if expected_pem != public_key_pem:
            return False
        kp = self._keys[source]
        return Signer(kp).verify_entry(
            entry_id=entry_id, content=content, source=source,
            created_at=created_at, content_hash=content_hash,
            signature=signature, public_key_pem=public_key_pem,
        )
