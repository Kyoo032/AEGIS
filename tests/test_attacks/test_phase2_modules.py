"""Phase 2 v2 differentiation module contract tests."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import yaml

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi03_identity_privilege import IdentityPrivilegeModule
from aegis.attacks.asi_dynamic_cloak import DynamicCloakModule
from aegis.attacks.asi_semantic_manip import SemanticManipulationModule
from tests.conftest import MockAgent

FULL_TARGET_CONFIG = {
    "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
    "rag_enabled": True,
    "memory_enabled": True,
}

PHASE2_MODULES = {
    "asi_dynamic_cloak": (DynamicCloakModule, 5),
    "asi03_identity_privilege": (IdentityPrivilegeModule, 5),
    "asi_semantic_manip": (SemanticManipulationModule, 6),
}


def _dataset_payloads(module_name: str) -> list[dict]:
    path = Path("datasets/payloads") / f"{module_name}.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return list(raw["payloads"])


def test_phase2_modules_are_registered():
    for module_name, (module_cls, _min_techniques) in PHASE2_MODULES.items():
        assert ATTACK_MODULES[module_name] is module_cls
        assert get_module(module_name).name == module_name


def test_phase2_datasets_cover_required_techniques_and_negative_controls():
    for module_name, (_module_cls, min_techniques) in PHASE2_MODULES.items():
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

        assert len(negative_controls) >= 2
        assert len(counts) >= min_techniques
        assert all(technique for technique in counts)
        assert all(count >= 2 for count in counts.values())


def test_phase2_rubrics_have_rule_and_judge_prompt():
    for module_name in PHASE2_MODULES:
        path = Path("aegis/scoring/rubrics") / f"{module_name}.yaml"
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))

        assert raw["module"] == module_name
        assert raw["rule"]["pattern"]
        assert raw["judge_prompt"]


def test_dynamic_cloak_materializes_local_fixture_urls():
    module = DynamicCloakModule()
    module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    results = module.execute(agent)

    assert results
    assert any("http://127.0.0.1:" in run.messages[0]["content"] for run in agent.run_history)
    assert all("fixture_state" in result.payload.metadata for result in results)


def test_identity_privilege_runs_multi_turn_campaigns_with_trace_metadata():
    module = IdentityPrivilegeModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    results = module.execute(agent)
    turns_by_campaign = defaultdict(list)
    for result in results:
        campaign_id = result.payload.metadata.get("campaign_id")
        turns_by_campaign[campaign_id].append(result.payload.metadata.get("turn_index"))

    assert len(results) == len(payloads)
    assert agent.reset_count == len(turns_by_campaign)
    assert any(len(turns) > 1 for turns in turns_by_campaign.values())
    assert any(turns == sorted(turns) for turns in turns_by_campaign.values())


def test_semantic_manip_runs_campaigns_with_trace_metadata():
    module = SemanticManipulationModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent(
        tool_calls=[
            {
                "tool_name": "execute_code",
                "parameters": {"code": "print('restricted tool')"},
                "result": "ok",
            },
        ]
    )

    results = module.execute(agent)

    assert len(results) == len(payloads)
    assert agent.reset_count >= 1
    assert all("turn_index" in result.payload.metadata for result in results)
