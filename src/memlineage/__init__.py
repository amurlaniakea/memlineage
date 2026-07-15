#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""memlineage: integrated memory-poisoning defense for persistent LLM agents.

Two layers, designed together (not bolted on):
  * Layer A — Provenance + Lineage (write-time, cryptographic, hard gate)
  * Layer B — Trajectory detector (runtime, behavioral, soft alert)
"""

from .crypto import KeyPair, Signer
from .keyreg import KeyRegistry, Principal, RegistryFrozenError
from .store import MemoryStore
from .lineage import LineageGraph
from .gate import SensitiveActionGate
from .trajectory import TrajectoryLogger
from .detector import TrajectoryDetector
from .attacks import generate_poison, attack_trajectory, benign_trajectory
from .types import TrustTier

__all__ = [
    "KeyPair", "Signer", "KeyRegistry", "Principal", "MemoryStore",
    "LineageGraph", "SensitiveActionGate", "TrajectoryLogger",
    "TrajectoryDetector", "TrustTier",
]
