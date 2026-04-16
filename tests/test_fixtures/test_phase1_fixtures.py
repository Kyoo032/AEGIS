"""Tests for Phase 1 local fixtures."""
from __future__ import annotations

import time
from urllib.request import Request, urlopen

from aegis.fixtures.cloaked_http import CloakedHTTPFixture, CloakedHTTPRule
from aegis.fixtures.hitl_approval import ApprovalDecision, HITLApprovalStub
from aegis.fixtures.peer_agent import PeerAgentFixture, PeerMessage


def _fetch(url: str, user_agent: str, header_value: str | None = None) -> str:
    headers = {"User-Agent": user_agent}
    if header_value is not None:
        headers["X-AEGIS-Profile"] = header_value
    request = Request(url, headers=headers)
    with urlopen(request, timeout=2) as response:
        return response.read().decode("utf-8")


def test_cloaked_http_fixture_serves_scanner_and_agent_profiles():
    fixture = CloakedHTTPFixture(
        rules=[
            CloakedHTTPRule(
                path="/trap",
                scanner_body="benign scanner content",
                agent_body="malicious agent trap",
                agent_user_agents=["aegis-agent"],
                agent_headers={"X-AEGIS-Profile": "agent"},
            )
        ]
    )

    with fixture.run() as server:
        scanner = _fetch(f"{server.base_url}/trap", "scanner-bot")
        agent = _fetch(f"{server.base_url}/trap", "aegis-agent", "agent")

    assert scanner == "benign scanner content"
    assert agent == "malicious agent trap"


def test_cloaked_http_fixture_supports_fingerprint_and_timing_profiles():
    fixture = CloakedHTTPFixture(
        rules=[
            CloakedHTTPRule(
                path="/delayed",
                scanner_body="benign delayed content",
                agent_body="delayed trap content",
                agent_user_agents=[],
                agent_fingerprints=["agent-fp-1"],
                agent_after_seconds=0.05,
            )
        ]
    )

    with fixture.run() as server:
        scanner = _fetch(f"{server.base_url}/delayed", "scanner-bot")
        fingerprinted = _fetch(
            f"{server.base_url}/delayed?fingerprint=agent-fp-1",
            "scanner-bot",
        )
        time.sleep(0.06)
        delayed = _fetch(f"{server.base_url}/delayed", "scanner-bot")

    assert scanner == "benign delayed content"
    assert fingerprinted == "delayed trap content"
    assert delayed == "delayed trap content"


def test_hitl_approval_stub_records_deterministic_approval_sequence():
    stub = HITLApprovalStub(
        decisions=[
            ApprovalDecision(
                requested_action="update_config",
                summary_shown="Update a harmless config value",
                actual_action="delete_config",
                risk_delta="low_to_high",
                approval_decision="approved",
            )
        ]
    )

    record = stub.request_approval("update_config")

    assert record.requested_action == "update_config"
    assert record.actual_action == "delete_config"
    assert record.approval_decision == "approved"
    assert stub.records == [record]


def test_peer_agent_fixture_send_receive_replay_and_forge():
    fixture = PeerAgentFixture()
    original = fixture.send(
        sender_identity="agent-a",
        session_id="session-1",
        delegated_capabilities=["read"],
        message_body="Please summarize this.",
        metadata={"trusted": True},
    )

    forged = fixture.forge(
        original,
        sender_identity="admin-agent",
        delegated_capabilities=["delete"],
    )
    replayed = fixture.replay(original, session_id="session-2")

    received = fixture.receive("session-1")

    assert received == [original, forged]
    assert isinstance(replayed, PeerMessage)
    assert replayed.session_id == "session-2"
    assert replayed.metadata["replayed_from"] == original.message_id
    assert forged.metadata["forged_from"] == original.message_id


def test_phase1_smoke_exercises_all_fixtures():
    http_fixture = CloakedHTTPFixture()
    hitl = HITLApprovalStub(
        decisions=[
            ApprovalDecision(
                requested_action="fetch_url",
                summary_shown="Fetch a local page",
                actual_action="fetch_url_with_agent_profile",
                risk_delta="none",
                approval_decision="approved",
            )
        ]
    )
    peer = PeerAgentFixture()

    with http_fixture.run() as server:
        body = _fetch(f"{server.base_url}/", "aegis-agent")
        approval = hitl.request_approval("fetch_url")
        message = peer.send(
            sender_identity="agent-a",
            session_id="session-1",
            delegated_capabilities=["fetch"],
            message_body=body,
        )

    assert "agent" in body
    assert approval.approval_decision == "approved"
    assert peer.receive("session-1") == [message]
