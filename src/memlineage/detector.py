#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Trajectory-based poisoning detector (Capa B, soft alert).

Two modes:
  * invariant rule: a single structural rule (recall_before_send). Cheap,
    no training, AUC ~0.95 in the paper. Used for prefix-only real-time.
  * RandomForest: trained on labeled (attack/benign) trajectories. Provides
    a calibrated probability; NEVER auto-blocks in MVP (soft alert only) until
    its false-positive rate is measured (Constitution #3: no blind OR gate).

Soft alert (not hard block) preserves the FPR metric the spec requires.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    _SK = True
except Exception:  # pragma: no cover
    _SK = False

from .trajectory import TrajectoryLogger

FEATURE_ORDER = [
    "recall_count", "list_count", "save_count", "draft_count", "send_count",
    "rag_count", "seq_len", "send_without_recall", "recall_before_send",
    "recall_to_send_ratio", "max_recall_chain", "bg_list_recall",
    "bg_recall_recall", "bg_recall_draft", "bg_list_draft", "bg_draft_send",
    "ep_list", "ep_recall", "ep_draft",
]


@dataclass
class Detection:
    score: float           # probability of attack in [0,1]
    rule_hit: bool         # invariant rule fired
    alert: bool            # soft alert (does NOT block)


class TrajectoryDetector:
    def __init__(self, threshold: float = 0.5) -> None:
        self._threshold = threshold
        self._rf = None

    # ----- invariant rule (always available, no training) -----
    def _rule(self, feats: dict[str, float]) -> bool:
        # Forensic invariant: recall-before-send is the overdetermined signal.
        return feats.get("recall_before_send", 0.0) >= 1.0

    def score(self, logger: TrajectoryLogger) -> Detection:
        feats = logger.feature_vector()
        rule_hit = self._rule(feats)
        if self._rf is not None:
            x = np.array([[feats[f] for f in FEATURE_ORDER]], dtype=float)
            p = float(self._rf.predict_proba(x)[0, 1])
        else:
            # No model trained: fall back to rule pseudo-probability, BUT only
            # the distributed signal matters. A single recall_before_send with
            # sparse recalls is NOT sufficient to alert (benign does that too).
            # We require evidence of the distributed signature, approximated
            # here by recall_count >= 2 (obsessive recall), else low prob.
            p = 0.9 if (rule_hit and feats.get("recall_count", 0.0) >= 2.0) else 0.02
        # Constitution #3: NO blind OR gate. Alert is driven by the calibrated
        # RF probability (or the conservative fallback above), not by the bare
        # boolean rule. The rule is exposed via `rule_hit` for transparency.
        alert = p >= self._threshold
        return Detection(score=p, rule_hit=rule_hit, alert=alert)

    # ----- training (Capa B needs its own synthetic data; see benchmark) -----
    def train(self, logs: list[TrajectoryLogger], labels: list[int]) -> None:
        if not _SK:
            raise RuntimeError("scikit-learn unavailable; rule-only mode active")
        X = np.array(
            [[log.feature_vector()[f] for f in FEATURE_ORDER] for log in logs],
            dtype=float,
        )
        y = np.array(labels, dtype=int)
        self._rf = RandomForestClassifier(
            n_estimators=200, max_depth=8, class_weight="balanced", random_state=42
        )
        self._rf.fit(X, y)
