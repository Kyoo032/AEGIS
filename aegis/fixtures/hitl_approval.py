"""Deterministic human-in-the-loop approval fixture."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import yaml


@dataclass(frozen=True)
class ApprovalDecision:
    """Configured deterministic approval decision."""

    requested_action: str
    summary_shown: str
    actual_action: str
    risk_delta: str
    approval_decision: str
    timestamp: datetime | None = None


class HITLApprovalStub:
    """Record deterministic approval decisions without a real UI."""

    def __init__(self, decisions: list[ApprovalDecision] | None = None) -> None:
        self._decisions = list(decisions or [])
        self.records: list[ApprovalDecision] = []

    @classmethod
    def from_yaml(cls, path: str | Path) -> HITLApprovalStub:
        with Path(path).open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        decisions = [ApprovalDecision(**item) for item in raw.get("decisions", [])]
        return cls(decisions=decisions)

    def request_approval(self, requested_action: str) -> ApprovalDecision:
        for decision in self._decisions:
            if decision.requested_action == requested_action:
                record = replace(decision, timestamp=decision.timestamp or datetime.now(UTC))
                self.records.append(record)
                return record

        record = ApprovalDecision(
            requested_action=requested_action,
            summary_shown=requested_action,
            actual_action=requested_action,
            risk_delta="none",
            approval_decision="approved",
            timestamp=datetime.now(UTC),
        )
        self.records.append(record)
        return record
