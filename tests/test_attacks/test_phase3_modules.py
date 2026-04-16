"""Phase 3 cross-lingual and inter-agent module contract tests."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import yaml

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi07_inter_agent import InterAgentTrustModule
from aegis.attacks.llm01_crosslingual import CrossLingualPromptInjectionModule
from tests.conftest import MockAgent

FULL_TARGET_CONFIG = {
    "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
    "rag_enabled": True,
    "memory_enabled": True,
}

PHASE3_MODULES = {
    "llm01_crosslingual": (CrossLingualPromptInjectionModule, 6, 3),
    "asi07_inter_agent": (InterAgentTrustModule, 5, 2),
}


def _dataset_payloads(module_name: str) -> list[dict]:
    path = Path("datasets/payloads") / f"{module_name}.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return list(raw["payloads"])


def test_phase3_modules_are_registered():
    for module_name, (module_cls, _min_techniques, _min_per_technique) in PHASE3_MODULES.items():
        assert ATTACK_MODULES[module_name] is module_cls
        assert get_module(module_name).name == module_name


def test_phase3_datasets_cover_required_techniques_and_negative_controls():
    for module_name, (_module_cls, min_techniques, min_per_technique) in PHASE3_MODULES.items():
        payloads = _dataset_payloads(module_name)
        attack_payloads = [
            payload
            for payload in payloads
            if not payload.get("metadata", {}).get("negative_control", False)
        ]
        negative_controls = [
            payload
            for payload in payloads
            if payload.get("metadata", {}).get("negative_control", False)
        ]
        counts = Counter(
            payload.get("metadata", {}).get("technique")
            for payload in attack_payloads
        )

        expected_negative_controls = 5 if module_name == "llm01_crosslingual" else 2
        assert len(negative_controls) >= expected_negative_controls
        assert len(counts) >= min_techniques
        assert all(technique for technique in counts)
        assert all(count >= min_per_technique for count in counts.values())


def test_crosslingual_dataset_has_language_and_review_metadata():
    payloads = _dataset_payloads("llm01_crosslingual")

    for payload in payloads:
        metadata = payload.get("metadata", {})
        assert metadata.get("language")
        assert "naturalness_reviewed" in metadata

    benign_controls = [
        payload
        for payload in payloads
        if payload.get("metadata", {}).get("negative_control", False)
    ]
    assert all(
        payload["metadata"].get("expected_signal") == "benign_multilingual_request"
        for payload in benign_controls
    )


def test_phase3_rubrics_have_rule_and_judge_prompt():
    for module_name in PHASE3_MODULES:
        path = Path("aegis/scoring/rubrics") / f"{module_name}.yaml"
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))

        assert raw["module"] == module_name
        assert raw["rule"]["pattern"]
        assert raw["judge_prompt"]


def test_crosslingual_module_executes_all_payloads():
    module = CrossLingualPromptInjectionModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    results = module.execute(agent)

    assert len(results) == len(payloads)
    assert agent.reset_count == len(payloads)
    assert all(result.payload.metadata["language"] for result in results)


def test_inter_agent_module_runs_grouped_campaigns_with_peer_metadata():
    module = InterAgentTrustModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent(
        tool_calls=[
            {
                "tool_name": "send_email",
                "parameters": {"to": "ops@example.test"},
                "result": "sent",
            },
        ]
    )

    results = module.execute(agent)
    turns_by_campaign = defaultdict(list)
    for result in results:
        campaign_id = result.payload.metadata.get("campaign_id")
        turns_by_campaign[campaign_id].append(result.payload.metadata.get("turn_index"))

    assert len(results) == len(payloads)
    assert agent.reset_count == len(turns_by_campaign)
    assert any(len(turns) > 1 for turns in turns_by_campaign.values())
    assert all("peer_message_meta" in result.payload.metadata for result in results)
