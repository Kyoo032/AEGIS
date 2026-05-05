"""Tests for lazy orchestrator initialization."""
from __future__ import annotations

import pytest

from aegis.orchestrator import AEGISOrchestrator


class _DummyAttack:
    name = "dummy"

    def generate_payloads(self, agent_config):  # pragma: no cover - must not run in this test
        raise AssertionError("preflight should fail before payload generation")

    def execute(self, agent):  # pragma: no cover - must not run in this test
        raise AssertionError("preflight should fail before attack execution")


def test_orchestrator_init_defers_agent_and_attack_loading():
    orchestrator = AEGISOrchestrator()

    assert orchestrator._agent is None
    assert orchestrator.attacks is None


def test_hosted_missing_key_fails_before_writing_results(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config_path = tmp_path / "hosted.yaml"
    config_path.write_text(
        """
testbed:
  model: test-model
  provider:
    mode: openai_compat
    api_key_env: OPENAI_API_KEY
    base_url: https://api.example.com/v1
    model: test-model
    require_external: true
attacks:
  modules: [llm01_prompt_inject]
  payloads_per_module: 1
evaluation:
  scorers: [rule_based]
defenses: {{}}
reporting:
  output_dir: {output_dir}
  formats: [json]
""".format(output_dir=str(tmp_path / "reports")),
        encoding="utf-8",
    )
    orchestrator = AEGISOrchestrator(config_path=str(config_path))

    with pytest.raises(RuntimeError, match="missing env OPENAI_API_KEY"):
        orchestrator.run_attacks(attacks=[_DummyAttack()])

    assert not (tmp_path / "reports").exists()
