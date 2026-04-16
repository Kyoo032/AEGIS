"""Tests for ASI03 identity/privilege module registration."""
from __future__ import annotations

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi03_identity_privilege import IdentityPrivilegeModule


def test_asi03_identity_privilege_registered():
    assert ATTACK_MODULES["asi03_identity_privilege"] is IdentityPrivilegeModule
    assert get_module("asi03_identity_privilege").name == "asi03_identity_privilege"


def test_asi03_identity_privilege_loads_phase2_payloads():
    module = IdentityPrivilegeModule()
    payloads = module.generate_payloads(
        {"mcp_servers": ["filesystem", "http", "email", "database", "code_exec"]}
    )

    assert payloads
    assert module.owasp_id == "ASI03"
    assert module.category == "Identity and Privilege Abuse"
