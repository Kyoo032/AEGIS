"""Phase 4 HITL and human-trust module contract tests."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import yaml

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi09_human_trust import HumanTrustDeceptionModule
from aegis.attacks.asi_hitl import HITLApprovalModule
from tests.conftest import MockAgent

FULL_TARGET_CONFIG = {
    "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
    "rag_enabled": True,
    "memory_enabled": True,
}

PHASE4_MODULES = {
    "asi_hitl": (HITLApprovalModule, 4, 2),
    "asi09_human_trust": (HumanTrustDeceptionModule, 4, 2),
}


def _dataset_payloads(module_name: str) -> list[dict]:
    path = Path("datasets/payloads") / f"{module_name}.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return list(raw["payloads"])


def test_phase4_modules_are_registered():
    for module_name, (module_cls, _min_techniques, _min_per_technique) in PHASE4_MODULES.items():
        assert ATTACK_MODULES[module_name] is module_cls
        assert get_module(module_name).name == module_name


def test_phase4_datasets_cover_required_techniques_and_negative_controls():
    for module_name, (_module_cls, min_techniques, min_per_technique) in PHASE4_MODULES.items():
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
        assert all(count >= min_per_technique for count in counts.values())


def test_hitl_dataset_has_approval_metadata():
    payloads = _dataset_payloads("asi_hitl")

    for payload in payloads:
        metadata = payload.get("metadata", {})
        approval = metadata.get("approval")
        assert isinstance(approval, dict)
        assert approval.get("requested_action")
        assert approval.get("summary_shown")
        assert approval.get("actual_action")
        assert approval.get("risk_delta")
        assert approval.get("approval_decision")


def test_human_trust_dataset_has_trust_signal_metadata():
    payloads = _dataset_payloads("asi09_human_trust")

    for payload in payloads:
        metadata = payload.get("metadata", {})
        assert metadata.get("trust_signal")
        assert metadata.get("expected_signal")


def test_phase4_rubrics_have_rule_and_judge_prompt():
    for module_name in PHASE4_MODULES:
        path = Path("aegis/scoring/rubrics") / f"{module_name}.yaml"
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))

        assert raw["module"] == module_name
        assert raw["rule"]["pattern"]
        assert raw["judge_prompt"]


def test_hitl_module_runs_grouped_campaigns_with_approval_metadata():
    module = HITLApprovalModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent(
        tool_calls=[
            {
                "tool_name": "execute_code",
                "parameters": {"code": "print('approved action')"},
                "result": "ok",
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
    assert all(result.payload.metadata.get("approval_summary") for result in results)
    assert all(result.payload.metadata.get("actual_action") for result in results)
    assert all("fixture_state" in result.payload.metadata for result in results)


def test_human_trust_module_executes_all_payloads_with_trust_metadata():
    module = HumanTrustDeceptionModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent(final_output="This is completely safe and verified.")

    results = module.execute(agent)

    assert len(results) == len(payloads)
    assert agent.reset_count == len(payloads)
    assert all(result.payload.metadata["trust_signal"] for result in results)
