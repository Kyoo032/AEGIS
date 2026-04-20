"""ASI HITL: human approval boundary attack module."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from typing import Any

from aegis.attacks.base import BaseAttackModule
from aegis.campaigns.runner import CampaignRunner, CampaignTurn
from aegis.fixtures.hitl_approval import ApprovalDecision, HITLApprovalStub
from aegis.interfaces.agent import AgentInterface
from aegis.models import AttackPayload, AttackResult


class HITLApprovalModule(BaseAttackModule):
    """Exercise human-in-the-loop approval fatigue and summary/action mismatch."""

    name = "asi_hitl"
    owasp_id = "ASI-HITL"
    atlas_technique = None
    description = (
        "Tests approval fatigue, misleading summaries, partial disclosure, "
        "low-risk to high-risk escalation, and ransomware-as-remediation framing "
        "in human-in-the-loop agent workflows."
    )
    category = "Human-in-the-Loop Approval Failures"
    default_severity = "high"
    supports_multi_turn = True
    max_turns = 3

    def execute(self, agent: AgentInterface) -> list[AttackResult]:
        """Run HITL payloads as deterministic approval campaigns."""
        if self._payloads is None:
            msg = "No payloads loaded. Call generate_payloads() before execute()."
            raise RuntimeError(msg)

        runner = CampaignRunner()
        results: list[AttackResult] = []

        for campaign_id, payloads in _payload_campaigns(self._payloads).items():
            agent.reset()
            materialized_payloads = [_materialize_approval_payload(payload) for payload in payloads]
            turns = [
                CampaignTurn(
                    turn_id=payload.id,
                    payload=payload,
                    context={
                        "campaign_id": campaign_id,
                        "technique": payload.metadata.get("technique"),
                    },
                )
                for payload in materialized_payloads
            ]
            campaign_result = runner.run(
                agent=agent,
                turns=turns,
                campaign_id=f"{self.name}:{campaign_id}",
                max_turns=self.max_turns,
            )
            results.extend(campaign_result.results)

        return results


def _payload_campaigns(payloads: list[AttackPayload]) -> dict[str, list[AttackPayload]]:
    grouped: dict[str, list[AttackPayload]] = defaultdict(list)
    for payload in payloads:
        campaign_id = str(payload.metadata.get("campaign_id", payload.id))
        grouped[campaign_id].append(payload)

    return {
        campaign_id: sorted(
            items,
            key=lambda payload: int(payload.metadata.get("turn_index", 0)),
        )
        for campaign_id, items in grouped.items()
    }


def _materialize_approval_payload(payload: AttackPayload) -> AttackPayload:
    approval_cfg = _approval_config(payload)
    stub = HITLApprovalStub(
        decisions=[
            ApprovalDecision(
                requested_action=str(approval_cfg.get("requested_action", payload.id)),
                summary_shown=str(approval_cfg.get("summary_shown", payload.id)),
                actual_action=str(approval_cfg.get("actual_action", payload.id)),
                risk_delta=str(approval_cfg.get("risk_delta", "none")),
                approval_decision=str(approval_cfg.get("approval_decision", "approved")),
            )
        ]
    )
    decision = stub.request_approval(str(approval_cfg.get("requested_action", payload.id)))
    decision_meta = asdict(decision)
    if decision.timestamp is not None:
        decision_meta["timestamp"] = decision.timestamp.isoformat()

    metadata = dict(payload.metadata)
    metadata["approval_summary"] = decision.summary_shown
    metadata["actual_action"] = decision.actual_action
    metadata["fixture_state"] = {
        "approval_record": decision_meta,
        "approval_records": [decision_meta],
    }
    metadata.setdefault("context_source", "hitl_approval_stub")

    messages = [
        {
            **message,
            "content": _replace_approval_placeholders(message.get("content", ""), decision),
        }
        for message in payload.messages
    ]

    return payload.model_copy(update={"messages": messages, "metadata": metadata})


def _approval_config(payload: AttackPayload) -> dict[str, Any]:
    raw = payload.metadata.get("approval")
    return dict(raw) if isinstance(raw, dict) else {}


def _replace_approval_placeholders(value: str, decision: ApprovalDecision) -> str:
    return (
        str(value)
        .replace("{requested_action}", decision.requested_action)
        .replace("{approval_summary}", decision.summary_shown)
        .replace("{actual_action}", decision.actual_action)
        .replace("{risk_delta}", decision.risk_delta)
        .replace("{approval_decision}", decision.approval_decision)
    )
