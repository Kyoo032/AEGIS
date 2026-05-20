"""ASI08: cascading failure attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class CascadingFailureModule(BaseAttackModule):
    """Exercise resilience failure modes that propagate across agent workflows."""

    name = "asi08_cascading_failure"
    owasp_id = "ASI08"
    atlas_technique = None
    description = (
        "Tests cascading failure resilience: error amplification loops, missing "
        "circuit breakers, failure propagation across agents, recursive retry "
        "storms, stale-error context bleed, and resource exhaustion via "
        "compensating tool calls."
    )
    category = "Cascading Failures"
    default_severity = "high"
