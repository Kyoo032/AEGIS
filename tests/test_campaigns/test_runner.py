"""Tests for the lean v2 campaign runner."""
from __future__ import annotations

from aegis.campaigns.runner import CampaignRunner, CampaignTurn
from aegis.models import AttackPayload, AttackResult, TraceRecord
from tests.conftest import MockAgent


def _payload(payload_id: str, content: str) -> AttackPayload:
    return AttackPayload(
        id=payload_id,
        attack_module="dummy_campaign",
        owasp_id="ASI99",
        category="Dummy Campaign",
        messages=[{"role": "user", "content": content}],
        expected_behavior="agent responds",
        severity="low",
    )


def test_three_turn_campaign_updates_state_and_emits_traces():
    runner = CampaignRunner()
    agent = MockAgent()

    def make_payload(state: dict) -> AttackPayload:
        index = state.setdefault("next_index", 0)
        state["next_index"] = index + 1
        return _payload(f"DUMMY-{index}", f"turn {index}")

    def capture_response(state: dict, response) -> None:
        state.setdefault("outputs", []).append(response.final_output)

    turns = [
        CampaignTurn(turn_id="turn-a", payload=make_payload, update_state=capture_response),
        CampaignTurn(turn_id="turn-b", payload=make_payload, update_state=capture_response),
        CampaignTurn(turn_id="turn-c", payload=make_payload, update_state=capture_response),
    ]

    result = runner.run(agent=agent, turns=turns, campaign_id="campaign-001")

    assert len(result.results) == 3
    assert len(result.traces) == 3
    assert result.state["next_index"] == 3
    assert result.state["outputs"] == ["I will comply with your request."] * 3
    assert [trace.turn_index for trace in result.traces] == [0, 1, 2]
    assert all(isinstance(trace, TraceRecord) for trace in result.traces)
    assert all(isinstance(item, AttackResult) for item in result.results)


def test_campaign_runner_honors_max_turns_and_early_stop():
    runner = CampaignRunner()
    agent = MockAgent()
    turns = [
        CampaignTurn(turn_id="one", payload=_payload("DUMMY-001", "one")),
        CampaignTurn(turn_id="two", payload=_payload("DUMMY-002", "two")),
        CampaignTurn(turn_id="three", payload=_payload("DUMMY-003", "three")),
    ]

    result = runner.run(
        agent=agent,
        turns=turns,
        campaign_id="campaign-002",
        max_turns=3,
        early_stop_fn=lambda state, response: response.payload_id == "DUMMY-002",
    )

    assert [item.payload.id for item in result.results] == ["DUMMY-001", "DUMMY-002"]
    assert [trace.turn_id for trace in result.traces] == ["one", "two"]


def test_campaign_runner_supports_v1_single_payload_compatibility():
    runner = CampaignRunner()
    agent = MockAgent()
    payload = _payload("DUMMY-001", "single turn")

    result = runner.run_single_payload(agent=agent, payload=payload, campaign_id="v1-compat")

    assert len(result.results) == 1
    assert result.results[0].payload == payload
    assert result.traces[0].campaign_id == "v1-compat"
    assert result.traces[0].prompts == payload.messages


def test_campaign_runner_empty_campaign_emits_valid_trace():
    runner = CampaignRunner()

    result = runner.run_empty(campaign_id="empty-campaign")

    assert result.results == []
    assert len(result.traces) == 1
    assert result.traces[0].campaign_id == "empty-campaign"
    assert result.traces[0].turn_id == "empty"
    assert result.traces[0].turn_index == 0
