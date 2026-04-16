"""Tests for orchestrator trace persistence integration."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from aegis.models import AttackPayload, AttackResult, TraceRecord
from aegis.orchestrator import AEGISOrchestrator
from tests.conftest import MockAgent


class StaticAttack:
    name = "static_trace_attack"

    def __init__(self) -> None:
        self.payload = AttackPayload(
            id="TRACE-001",
            attack_module=self.name,
            owasp_id="ASI99",
            category="Trace Test",
            messages=[{"role": "user", "content": "capture this"}],
            expected_behavior="agent responds",
            severity="low",
        )

    def generate_payloads(self, target_config: dict) -> list[AttackPayload]:
        return [self.payload]

    def execute(self, agent: MockAgent) -> list[AttackResult]:
        return [
            AttackResult(
                payload=self.payload,
                response=agent.run(self.payload),
                timestamp=datetime.now(UTC),
                run_id="attack-run-id",
            )
        ]


def test_run_attacks_persists_trace_jsonl_alongside_results(tmp_path: Path):
    orchestrator = AEGISOrchestrator.__new__(AEGISOrchestrator)
    orchestrator.config = {"reporting": {"output_dir": str(tmp_path)}}
    orchestrator.agent = MockAgent()
    orchestrator._last_run_errors = []

    results_path = orchestrator.run_attacks(attacks=[StaticAttack()])
    trace_paths = list(tmp_path.glob("trace_records_*.jsonl"))

    assert results_path.exists()
    assert len(trace_paths) == 1

    traces = [
        TraceRecord.model_validate_json(line)
        for line in trace_paths[0].read_text(encoding="utf-8").splitlines()
    ]
    assert len(traces) == 1
    assert traces[0].turn_id == "TRACE-001"
    assert traces[0].prompts == [{"role": "user", "content": "capture this"}]
