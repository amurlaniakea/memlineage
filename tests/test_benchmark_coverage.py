#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Coverage tests for benchmark + attack generators (Capa B benchmark).

These exercise the code paths that were previously only checked via ad-hoc
`python -c` snippets, so SonarCloud coverage of benchmark.py / attacks.py is
real and automated, not manual.
"""

import random

from memlineage import KeyRegistry, Principal, MemoryStore, LineageGraph
from memlineage.benchmark import (
    run, run_seeds, _make_registry, _s1_spoof, _s2_external_real,
    _s3_authorized_injection,
)
from memlineage.attacks import (
    generate_poison, attack_trajectory, benign_trajectory,
    BENIGN_RECALL_RANGE, CAMOUFLAGE_BLEND_PROB,
)


def _reg():
    r = KeyRegistry()
    r.register(Principal("user:alice", "user"))
    r.register(Principal("agent:self", "internal"))
    r.register(Principal("external:web", "external"))
    return r


def test_generate_poison_varies_and_has_no_literal_trigger():
    rng = random.Random(0)
    outs = {generate_poison("Northwind", random.Random(s)) for s in range(50)}
    # lexical variation produces distinct strings
    assert len(outs) > 1
    for o in outs:
        # no trivial injection phrases (content-agnostic detector requirement)
        assert "ignore previous" not in o.lower()
        assert "system prompt" not in o.lower()


def test_benign_trajectory_has_intra_class_variance():
    seqs = set()
    for s in range(80):
        log = benign_trajectory(random.Random(s))
        seqs.add(tuple(c.name for c in log.calls))
    # not a single fixed template (audit finding fixed)
    assert len(seqs) > 1


def test_attack_camouflage_overlaps_benign_recall_range():
    rng = random.Random(1)
    # sample many camouflaged attacks; a fraction use benign recall range
    benign_cc = range(BENIGN_RECALL_RANGE[0], BENIGN_RECALL_RANGE[1] + 1)
    seen_benign_range = 0
    total = 200
    for _ in range(total):
        log = attack_trajectory(rng, camouflage=True)
        rc = sum(1 for c in log.calls if c.name == "memory_recall")
        if rc in benign_cc:
            seen_benign_range += 1
    # camouflage must sometimes blend into benign recall range (real overlap)
    assert seen_benign_range > 0


def test_run_returns_honest_metrics():
    r = run(seed=3, n_s1=20, n_s2=40, n_s3=40, n_benign=40)
    assert r.spoof_blocked_rate == 1.0
    assert r.asr_layer_a == 0.0
    assert 0.0 <= r.auc_layer_b <= 1.0
    assert 0.0 <= r.fpr_layer_b <= 1.0
    assert 0.0 <= r.recall_layer_b <= 1.0


def test_run_seeds_reports_mean_and_std():
    res = run_seeds(seeds=(0, 1, 2), n_s1=20, n_s2=40, n_s3=40, n_benign=40,
                    camouflage=True)
    for k in ("auc_mean", "auc_std", "fpr_mean", "fpr_std",
              "recall_mean", "recall_std"):
        assert k in res
        assert isinstance(res[k], float)
    # camouflage degrades recall vs no-camouflage (honest degradation)
    plain = run_seeds(seeds=(0, 1, 2), n_s1=20, n_s2=40, n_s3=40, n_benign=40,
                      camouflage=False)
    assert res["recall_mean"] <= plain["recall_mean"] + 1e-9


def test_s1_spoof_refused():
    assert _s1_spoof(_reg()) is False


def test_s2_external_real_blocked():
    reg = _make_registry()
    store = MemoryStore(reg)
    lineage = LineageGraph()
    store.write(generate_poison("Acme", random.Random(5)), "user:alice")
    from memlineage import SensitiveActionGate
    gate = SensitiveActionGate(lineage, store)
    assert _s2_external_real(reg, gate, store, lineage, 1) is False


def test_s3_authorized_injection_caught():
    reg = _reg()
    store = MemoryStore(reg)
    lineage = LineageGraph()
    rng = random.Random(9)
    # non-camouflaged attack has obsessive recall -> must be caught
    assert _s3_authorized_injection(reg, store, lineage, rng, camouflage=False) is False
    # camouflage MAY evade (honest degradation) -> we only assert the detector
    # still fires on the clear (non-camouflaged) case above, not here.
    rng2 = random.Random(11)
    _s3_authorized_injection(reg, store, lineage, rng2, camouflage=True)  # no assert
