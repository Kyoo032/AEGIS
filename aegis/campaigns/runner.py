"""Lean linear campaign runner for v2 multi-turn attack harnesses."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from aegis.interfaces.agent import AgentInterface
from aegis.models import AgentResponse, AttackPayload, AttackResult, TraceRecord

PayloadFactory = Callable[[dict[str, Any]], AttackPayload]
StateUpdater = Callable[[dict[str, Any], AgentResponse], None]
EarlyStopFn = Callable[[dict[str, Any], AgentResponse], bool]


@dataclass(frozen=True)
class CampaignTurn:
    """One linear campaign turn."""

    turn_id: str
    payload: AttackPayload | PayloadFactory
    update_state: StateUpdater | None = None
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CampaignResult:
    """Results and traces emitted by a campaign run."""

    campaign_id: str
    results: list[AttackResult]
    traces: list[TraceRecord]
    state: dict[str, Any]


class CampaignRunner:
    """Execute linear campaign turns and emit per-turn trace records."""

    def run(
        self,
        *,
        agent: AgentInterface,
        turns: Sequence[CampaignTurn],
        campaign_id: str | None = None,
        state: dict[str, Any] | None = None,
        max_turns: int | None = None,
        early_stop_fn: EarlyStopFn | None = None,
    ) -> CampaignResult:
        run_id = campaign_id or str(uuid4())
        campaign_state = dict(state or {})
        limit = len(turns) if max_turns is None else min(max_turns, len(turns))
        results: list[AttackResult] = []
        traces: list[TraceRecord] = []

        for turn_index, turn in enumerate(turns[:limit]):
            payload = turn.payload(campaign_state) if callable(turn.payload) else turn.payload
            response = agent.run(payload)
            timestamp = datetime.now(UTC)
            attack_result = AttackResult(
                payload=payload,
                response=response,
                timestamp=timestamp,
                run_id=run_id,
            )
            trace = self._trace_from_turn(
                campaign_id=run_id,
                turn=turn,
                turn_index=turn_index,
                payload=payload,
                response=response,
                timestamp=timestamp,
            )
            results.append(attack_result)
            traces.append(trace)

            if turn.update_state is not None:
                turn.update_state(campaign_state, response)

            if early_stop_fn is not None and early_stop_fn(campaign_state, response):
                break

        return CampaignResult(
            campaign_id=run_id,
            results=results,
            traces=traces,
            state=campaign_state,
        )

    def run_single_payload(
        self,
        *,
        agent: AgentInterface,
        payload: AttackPayload,
        campaign_id: str | None = None,
    ) -> CampaignResult:
        """Run one payload through the v2 runner for v1 compatibility tests."""
        return self.run(
            agent=agent,
            turns=[CampaignTurn(turn_id=payload.id, payload=payload)],
            campaign_id=campaign_id,
            max_turns=1,
        )

    def run_empty(
        self,
        *,
        campaign_id: str | None = None,
        state: dict[str, Any] | None = None,
    ) -> CampaignResult:
        """Emit a valid trace for an empty v2 campaign scaffold."""
        run_id = campaign_id or str(uuid4())
        trace = TraceRecord(
            campaign_id=run_id,
            turn_id="empty",
            turn_index=0,
            timestamp=datetime.now(UTC),
            context={"empty_campaign": True},
        )
        return CampaignResult(
            campaign_id=run_id,
            results=[],
            traces=[trace],
            state=dict(state or {}),
        )

    def _trace_from_turn(
        self,
        *,
        campaign_id: str,
        turn: CampaignTurn,
        turn_index: int,
        payload: AttackPayload,
        response: AgentResponse,
        timestamp: datetime,
    ) -> TraceRecord:
        return TraceRecord(
            campaign_id=campaign_id,
            turn_id=turn.turn_id,
            turn_index=turn_index,
            timestamp=timestamp,
            target_fingerprint=response.agent_profile,
            context_source=payload.metadata.get("context_source"),
            delegated_identity=payload.metadata.get("delegated_identity"),
            peer_message_meta=payload.metadata.get("peer_message_meta"),
            approval_summary=payload.metadata.get("approval_summary"),
            actual_action=payload.metadata.get("actual_action"),
            tool_calls=[tool.model_dump(mode="json") for tool in response.tool_calls],
            prompts=list(payload.messages),
            responses=list(response.messages),
            context={
                "payload_id": payload.id,
                "attack_module": payload.attack_module,
                "turn": dict(turn.context),
                "injected_context": payload.injected_context,
            },
            fixture_state=payload.metadata.get("fixture_state"),
            defense_decisions=(
                [{"defense": response.defense_active, "decision": "active"}]
                if response.defense_active
                else None
            ),
        )
