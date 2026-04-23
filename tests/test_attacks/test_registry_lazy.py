"""Tests for lazy attack registry loading."""
from __future__ import annotations

import importlib
import sys


def test_attack_registry_defers_module_imports():
    for module_name in list(sys.modules):
        if module_name == "aegis.attacks" or module_name.startswith("aegis.attacks."):
            sys.modules.pop(module_name, None)

    attacks = importlib.import_module("aegis.attacks")

    assert "aegis.attacks.asi01_goal_hijack" not in sys.modules

    module_cls = attacks.ATTACK_MODULES["asi01_goal_hijack"]

    assert module_cls.__name__ == "GoalHijackModule"
    assert "aegis.attacks.asi01_goal_hijack" in sys.modules
