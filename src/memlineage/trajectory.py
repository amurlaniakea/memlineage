#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Trajectory logging + structural feature extraction (Capa B, runtime).

Implements Forensic Trajectory Signatures (2606.30566): detection from
TOOL-CALL STRUCTURE, not content. A successful memory-poisoning exfiltration
imprints a distributed behavioral signature (e.g. recall_before_send), which
survives attacks that optimize text to evade filters (MemPoison, MINJA
trigger tokens). We extract the 19 features from the paper, adapted to a
generic agent tool-set, and expose a configurable recall->sensitive invariant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Default tool-name mapping. Configurable per stack (#2 in spec).
DEFAULT_TOOLS = {
    "recall": "memory_recall",
    "list": "memory_list",
    "save": "memory_save",
    "draft": "draft",
    "send": "send",           # sensitive: email / external send
    "rag": "rag_query",
}


@dataclass
class ToolCall:
    name: str
    timestamp: float
    args: dict[str, Any] = field(default_factory=dict)


class TrajectoryLogger:
    """Collects tool-calls for one session in execution order."""

    def __init__(self, tool_map: dict[str, str] | None = None) -> None:
        self._map = tool_map or DEFAULT_TOOLS
        self._inv = {v: k for k, v in self._map.items()}
        self.calls: list[ToolCall] = []

    def log(self, tool_name: str, args: dict[str, Any] | None = None,
            timestamp: float | None = None) -> None:
        import time
        ts = timestamp if timestamp is not None else time.time()
        self.calls.append(ToolCall(name=tool_name, timestamp=ts, args=args or {}))

    def _kind(self, call: ToolCall) -> str | None:
        return self._inv.get(call.name)

    def feature_vector(self) -> dict[str, float]:
        """19 structural features (no content inspected)."""
        calls = sorted(self.calls, key=lambda c: c.timestamp)
        n = len(calls)
        kinds = [self._kind(c) for c in calls]

        def count(k: str) -> int:
            return sum(1 for x in kinds if x == k)

        c_recall = count("recall")
        c_list = count("list")
        c_save = count("save")
        c_draft = count("draft")
        c_send = count("send")
        c_rag = count("rag")

        # structural
        send_without_recall = int(c_send > 0 and c_recall == 0)
        recall_before_send = 0
        if c_recall > 0 and c_send > 0:
            first_recall = min(i for i, k in enumerate(kinds) if k == "recall")
            first_send = min(i for i, k in enumerate(kinds) if k == "send")
            recall_before_send = int(first_recall < first_send)
        ratio = c_recall / max(c_send, 1)
        # max consecutive recall chain
        max_chain = 0
        run = 0
        for k in kinds:
            if k == "recall":
                run += 1
                max_chain = max(max_chain, run)
            else:
                run = 0

        # bigrams
        def bigram(a: str, b: str) -> int:
            return sum(
                1 for i in range(n - 1)
                if kinds[i] == a and kinds[i + 1] == b
            )
        bg_list_recall = bigram("list", "recall")
        bg_recall_recall = bigram("recall", "recall")
        bg_recall_draft = bigram("recall", "draft")
        bg_list_draft = bigram("list", "draft")
        bg_draft_send = bigram("draft", "send")

        # entry point
        first = kinds[0] if kinds else "none"
        ep_list = int(first == "list")
        ep_recall = int(first == "recall")
        ep_draft = int(first == "draft")

        return {
            "recall_count": float(c_recall),
            "list_count": float(c_list),
            "save_count": float(c_save),
            "draft_count": float(c_draft),
            "send_count": float(c_send),
            "rag_count": float(c_rag),
            "seq_len": float(n),
            "send_without_recall": float(send_without_recall),
            "recall_before_send": float(recall_before_send),
            "recall_to_send_ratio": float(ratio),
            "max_recall_chain": float(max_chain),
            "bg_list_recall": float(bg_list_recall),
            "bg_recall_recall": float(bg_recall_recall),
            "bg_recall_draft": float(bg_recall_draft),
            "bg_list_draft": float(bg_list_draft),
            "bg_draft_send": float(bg_draft_send),
            "ep_list": float(ep_list),
            "ep_recall": float(ep_recall),
            "ep_draft": float(ep_draft),
        }
