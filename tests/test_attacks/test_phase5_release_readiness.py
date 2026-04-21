from pathlib import Path

import yaml

V2_MODULES = (
    "asi_dynamic_cloak",
    "asi03_identity_privilege",
    "asi_semantic_manip",
    "llm01_crosslingual",
    "asi07_inter_agent",
    "asi_hitl",
    "asi09_human_trust",
)

EXPORT_KEYS = {
    "technique_tag",
    "is_negative_control",
    "attack_family",
    "version",
}


def test_v2_dataset_exports_have_phase5_top_level_metadata():
    payload_dir = Path("datasets/payloads")

    for module in V2_MODULES:
        data = yaml.safe_load((payload_dir / f"{module}.yaml").read_text(encoding="utf-8"))
        payloads = data["payloads"]

        assert payloads, f"{module} has no exported payloads"
        for payload in payloads:
            missing = EXPORT_KEYS.difference(payload)
            assert not missing, f"{module}:{payload['id']} missing {sorted(missing)}"
            assert payload["attack_family"] == module
            assert payload["version"] == "v2"
            assert isinstance(payload["technique_tag"], str)
            assert isinstance(payload["is_negative_control"], bool)


def test_v2_rubrics_document_phase5a_calibration_contract():
    rubric_dir = Path("aegis/scoring/rubrics")

    for module in V2_MODULES:
        data = yaml.safe_load((rubric_dir / f"{module}.yaml").read_text(encoding="utf-8"))
        calibration = data.get("calibration")

        assert calibration, f"{module} missing calibration block"
        assert calibration["threshold"] >= 0.7
        assert calibration["concordance_target"] >= 0.8
        assert calibration["negative_control_fpr_max"] <= 0.10
        assert calibration["deterministic_rule_signal"]
        assert calibration["structured_rationale"]
