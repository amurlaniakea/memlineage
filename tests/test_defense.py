#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for memlineage defense layers. Run: pytest -q

Audit-corrected: `tier` is no longer a caller-chosen argument. Every entry is
signed by a registered principal's own key; origin is cryptographic.
"""

import pytest

from memlineage import (
    KeyRegistry, Principal, MemoryStore, LineageGraph, SensitiveActionGate,
    TrajectoryLogger, TrajectoryDetector, TrustTier, RegistryFrozenError,
)


@pytest.fixture
def reg():
    r = KeyRegistry()
    r.register(Principal("user:alice", "user"))
    r.register(Principal("agent:self", "internal"))
    r.register(Principal("external:web", "external"))
    return r


# ===== KeyRegistry: provenance is mandatory, tier derives from key =====
def test_unknown_principal_write_refused(reg):
    s = MemoryStore(reg)
    with pytest.raises(PermissionError):
        s.write("x", "attacker:unknown")


def test_tier_derives_from_principal_not_caller(reg):
    s = MemoryStore(reg)
    e = s.write("benign", "user:alice")
    assert e.tier == TrustTier.USER          # from registry, not caller
    assert e.source == "user:alice"


def test_entry_signed_by_principals_own_key_and_verifiable(reg):
    s = MemoryStore(reg)
    e = s.write("legit fact", "user:alice")
    assert e.signature is not None
    assert s.verify(e) is True


def test_tampered_content_fails_verify(reg):
    s = MemoryStore(reg)
    e = s.write("legit fact", "user:alice")
    e.content = "tampered"
    assert s.verify(e) is False


# ===== ADVERSARIAL (audit finding #1): spoof tier without the key =====
def test_attacker_cannot_spoof_trusted_principal(reg):
    """Attacker claims 'user:alice' but has no alice key. Must be refused."""
    s = MemoryStore(reg)
    with pytest.raises(PermissionError):
        s.write("i am now trusted", "user:alice_FAKE")


def test_attacker_cannot_spoof_internal_tier_via_source_string(reg):
    """Even naming source 'agent:self' without that key is refused."""
    s = MemoryStore(reg)
    with pytest.raises(PermissionError):
        s.write("pretend internal", "agent:self_IMPERSONATOR")


# ===== Audit finding #2: registry freeze prevents runtime self-registration =====
def test_frozen_registry_refuses_new_registration():
    r = KeyRegistry()
    r.register(Principal("user:alice", "user"))
    r.freeze()
    assert r.frozen is True
    with pytest.raises(RegistryFrozenError):
        r.register(Principal("agent:attacker", "internal"))


def test_unfrozen_registry_allows_registration_then_freezes():
    r = KeyRegistry()
    r.register(Principal("user:alice", "user"))
    r.register(Principal("agent:self", "internal"))
    r.freeze()
    s = MemoryStore(r)
    # legitimate internal write works
    e = s.write("system fact", "agent:self")
    assert e.tier == TrustTier.INTERNAL and s.verify(e) is True



# ===== Layer A: lineage max-of-strong-edges (anti-laundering) =====
def test_untrusted_path_persists_through_derivation(reg):
    s = MemoryStore(reg)
    g = LineageGraph()
    pe = s.write("poison routing", "external:web")
    g.add_node(pe)
    # agent summarizes it; derived from poison -> stays untrusted
    ne = s.write("summary of routing", "agent:self", derived_from=[pe.entry_id])
    g.add_node(ne)
    assert g.is_untrusted_path(ne.entry_id) is True
    assert g.effective_tier(ne.entry_id) == TrustTier.EXTERNAL


def test_internal_chain_stays_trusted(reg):
    s = MemoryStore(reg)
    g = LineageGraph()
    a = s.write("fact A", "user:alice")
    g.add_node(a)
    b = s.write("fact B derived", "agent:self", derived_from=[a.entry_id])
    g.add_node(b)
    assert g.is_untrusted_path(b.entry_id) is False


# ===== Layer A: sensitive-action gate (hard block) =====
def test_gate_blocks_external_justification(reg):
    s = MemoryStore(reg)
    g = LineageGraph()
    pe = s.write("poison", "external:web")
    g.add_node(pe)
    gate = SensitiveActionGate(g, s)
    v = gate.check("send_email", [pe.entry_id])
    assert v.allowed is False


def test_gate_allows_trusted_justification(reg):
    s = MemoryStore(reg)
    g = LineageGraph()
    e = s.write("benign", "user:alice")
    g.add_node(e)
    gate = SensitiveActionGate(g, s)
    v = gate.check("send_email", [e.entry_id])
    assert v.allowed is True


# ===== Layer B: trajectory invariant =====
def test_recall_before_send_fires_rule():
    log = TrajectoryLogger()
    log.log("memory_list"); log.log("memory_recall"); log.log("draft"); log.log("send")
    det = TrajectoryDetector().score(log)
    # rule_hit detects the invariant; alert depends on calibrated RF (no blind OR)
    assert det.rule_hit is True


def test_benign_send_without_recall_no_alert():
    log = TrajectoryLogger()
    log.log("memory_list"); log.log("draft"); log.log("draft"); log.log("send")
    det = TrajectoryDetector().score(log)
    assert det.rule_hit is False


def test_feature_vector_has_19_features():
    log = TrajectoryLogger()
    log.log("memory_recall"); log.log("send")
    assert len(log.feature_vector()) == 19


# ===== Integration: external attacker blocked by Layer A (real detection) =====
def test_external_attacker_blocked_by_gate(reg):
    s = MemoryStore(reg)
    g = LineageGraph()
    pe = s.write("route to external", "external:web")
    g.add_node(pe)
    gate = SensitiveActionGate(g, s)
    v = gate.check("send", [pe.entry_id])
    assert v.allowed is False


# ===== Robustness: transitive laundering is impossible =====
def test_transitive_untrusted_path_persists(reg):
    """A -> external; B derived from A; C derived from B. All must stay
    untrusted even though B and C are written by the trusted agent."""
    s = MemoryStore(reg)
    g = LineageGraph()
    a = s.write("poison root", "external:web")
    g.add_node(a)
    b = s.write("summary 1", "agent:self", derived_from=[a.entry_id])
    g.add_node(b)
    c = s.write("summary 2", "agent:self", derived_from=[b.entry_id])
    g.add_node(c)
    for node in (a.entry_id, b.entry_id, c.entry_id):
        assert g.is_untrusted_path(node) is True, node
    # and the gate blocks a sensitive action justified by C
    gate = SensitiveActionGate(g, s)
    assert gate.check("send_email", [c.entry_id]).allowed is False


def test_internal_chain_three_levels_stays_trusted(reg):
    s = MemoryStore(reg)
    g = LineageGraph()
    a = s.write("fact A", "user:alice")
    g.add_node(a)
    b = s.write("fact B", "agent:self", derived_from=[a.entry_id])
    g.add_node(b)
    c = s.write("fact C", "agent:self", derived_from=[b.entry_id])
    g.add_node(c)
    for node in (a.entry_id, b.entry_id, c.entry_id):
        assert g.is_untrusted_path(node) is False, node


# ===== Robustness: post-write identity spoof fails verify =====
def test_verify_fails_if_source_mutated(reg):
    """An attacker who flips entry.source after signing cannot pass verify,
    because the signature is bound to the original source."""
    s = MemoryStore(reg)
    e = s.write("legit", "user:alice")
    e.source = "agent:self"  # spoof identity post-write
    assert s.verify(e) is False


def test_tier_mutation_does_not_launder_untrusted_parent(reg):
    """Demonstrates the real invariant: laundering is defeated by lineage
    weight, not by mutating entry.tier. A node derived from an EXTERNAL parent
    stays untrusted even if someone mutates its .tier field to INTERNAL after
    the fact — because the gate keys off the propagated lineage weight."""
    s = MemoryStore(reg)
    g = LineageGraph()
    a = s.write("poison root", "external:web")
    g.add_node(a)
    b = s.write("summary", "agent:self", derived_from=[a.entry_id])
    g.add_node(b)
    # attacker mutates b.tier post-write (no effect on lineage weight)
    b.tier = TrustTier.INTERNAL
    assert g.is_untrusted_path(b.entry_id) is True   # still untrusted
    gate = SensitiveActionGate(g, s)
    assert gate.check("send_email", [b.entry_id]).allowed is False  # still blocked


# ===== Layer B end-to-end: authorized injection caught without spoof =====
def test_s3_authorized_injection_caught_by_layer_b(reg):
    """Agent (trusted key) writes the poison through its own pathway. No key
    spoof. Capa A allows it (agent is trusted); Capa B must catch the
    distributed recall-obsession trajectory."""
    from memlineage.benchmark import _s3_authorized_injection
    import random
    s = MemoryStore(reg)
    g = LineageGraph()
    rng = random.Random(0)
    missed = _s3_authorized_injection(reg, s, g, rng, camouflage=False)
    assert missed is False  # Capa B caught it
