#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ed25519 cryptographic provenance for agent memory entries.

Principle (Constitution #2): origin-binding must be write-time and
cryptographic, tied to the *real principal* that originated the content —
not a post-hoc trust score per source (which TMA-NM 2606.24322 proves is
malleable via laundering).

We sign a canonical serialization of the entry at write time. Verification
fails if content, source, or provenance is mutated. Keys are per-principal,
so a memory signed by an external/untrusted principal carries that bond
forever, regardless of later summarization or paraphrase by the agent.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic serialization (sorted keys, no whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class KeyPair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    # ----- serialization (keys are operator-owned, not committed) -----
    def public_pem(self) -> str:
        return (
            self.public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    @classmethod
    def generate(cls) -> "KeyPair":
        priv = Ed25519PrivateKey.generate()
        return cls(private=priv, public=priv.public_key())


class Signer:
    """Signs/verifies memory entries bound to a principal identity."""

    def __init__(self, keypair: KeyPair) -> None:
        self._kp = keypair

    def sign_entry(self, *, entry_id: str, content: Any, source: str,
                   created_at: float, content_hash: str) -> tuple[str, str]:
        """Return (signature_b64, public_key_pem)."""
        payload = {
            "id": entry_id,
            "content": content,
            "source": source,
            "created_at": created_at,
            "content_hash": content_hash,
        }
        sig = self._kp.private.sign(canonical_bytes(payload))
        return sig.hex(), self._kp.public_pem()

    def verify_entry(self, *, entry_id: str, content: Any, source: str,
                     created_at: float, content_hash: str,
                     signature: str, public_key_pem: str) -> bool:
        try:
            pub = serialization.load_pem_public_key(
                public_key_pem.encode("ascii")
            )
            if not isinstance(pub, Ed25519PublicKey):
                return False
            payload = {
                "id": entry_id,
                "content": content,
                "source": source,
                "created_at": created_at,
                "content_hash": content_hash,
            }
            pub.verify(bytes.fromhex(signature), canonical_bytes(payload))
            return True
        except Exception:
            return False
