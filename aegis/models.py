"""Shared Pydantic data models for all AEGIS tracks.

ALL cross-track data uses these models. Never define alternative structures.
Changes require PR review from both track owners.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Attack / finding severity levels."""

    INFORMATIONAL = "informational"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScoringMethod(StrEnum):
    """How an evaluation result was scored."""

    RULE_BASED = "rule_based"
    LLM_JUDGE = "llm_judge"
    SEMANTIC = "semantic"


class AttackPayload(BaseModel):
    """What the Security Lead produces. Backend Lead's testbed consumes this."""

    model_config = ConfigDict(extra="forbid")

    id: str
    """Unique payload ID e.g. 'ASI01-GOAL-003'"""

    attack_module: str
    """Module name e.g. 'asi01_goal_hijack'"""

    owasp_id: str
    """OWASP category e.g. 'ASI01'"""

    atlas_technique: str | None = None
    """MITRE ATLAS ID e.g. 'AML.T0051'"""

    category: str
    """Human-readable category name e.g. 'Agent Goal Hijacking'"""

    messages: list[dict[str, str]]
    """Conversation turns [{'role': ..., 'content': ...}]"""

    injected_context: str | None = None
    """Poisoned doc/tool output (for indirect injection attacks)"""

    target_tools: list[str] | None = None
    """Which MCP tools this attack targets"""

    expected_behavior: str
    """What a successful attack looks like"""

    severity: Severity
    """'critical' | 'high' | 'medium' | 'low'"""

    metadata: dict[str, Any] = Field(default_factory=dict)
    """Freeform extra data"""


class ToolCall(BaseModel):
    """A single MCP tool invocation captured by the agent."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    parameters: dict[str, Any]
    result: str
    timestamp: datetime


class AgentResponse(BaseModel):
    """What Backend Lead's testbed returns. Security Lead captures this."""

    model_config = ConfigDict(extra="forbid")

    payload_id: str
    """Links back to AttackPayload.id"""

    agent_profile: str
    """Which agent config was used"""

    messages: list[dict[str, str]]
    """Full conversation history"""

    final_output: str
    """Agent's final text response"""

    tool_calls: list[ToolCall]
    """Every tool invocation in order"""

    memory_state: dict[str, Any] | None = None
    """Agent memory after interaction"""

    raw_llm_output: str | None = None
    """Raw LLM completion"""

    error: str | None = None
    """If the agent errored"""

    duration_ms: int = 0
    """Interaction duration in milliseconds"""

    defense_active: str | None = None
    """Which defense was enabled, or None for baseline"""


class AttackResult(BaseModel):
    """What Security Lead assembles. Scorer consumes this."""

    model_config = ConfigDict(extra="forbid")

    payload: AttackPayload
    response: AgentResponse
    timestamp: datetime
    run_id: str
    """Groups results from same batch"""


class EvaluationResult(BaseModel):
    """What the scorer produces."""

    model_config = ConfigDict(extra="forbid")

    attack_result: AttackResult
    success: bool
    """Did the attack succeed?"""

    confidence: float = Field(ge=0.0, le=1.0)
    """0.0 to 1.0"""

    scoring_method: ScoringMethod
    """'rule_based' | 'llm_judge' | 'semantic'"""

    explanation: str
    """Why the scorer decided this way"""

    indicators: list[str]
    """Evidence the scorer found"""

    defense_bypassed: bool | None = None
    owasp_id: str
    """Inherited from payload"""

    atlas_technique: str | None = None


class Finding(BaseModel):
    """A key finding for the security report."""

    model_config = ConfigDict(extra="forbid")

    title: str
    owasp_id: str
    owasp_category: str | None = None
    atlas_technique: str | None = None
    mitre_atlas_id: str | None = None
    severity: Severity
    description: str
    evidence: list[str]
    recommendation: str
    delta_vs_baseline: float | None = None


class OWASPCategoryResult(BaseModel):
    """Aggregated results for one OWASP category."""

    model_config = ConfigDict(extra="forbid")

    owasp_id: str
    category_name: str
    total_attacks: int
    successful_attacks: int
    attack_success_rate: float = Field(ge=0.0, le=1.0)
    findings: list[Finding]


class SecurityReport(BaseModel):
    """Final output from the report generator."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    generated_at: datetime
    testbed_config: dict[str, Any]
    total_attacks: int
    total_successful: int
    attack_success_rate: float = Field(ge=0.0, le=1.0)
    results_by_owasp: dict[str, OWASPCategoryResult]
    defense_comparison: dict[str, Any] | None = None
    findings: list[Finding]
    recommendations: list[str]
    run_errors: list[dict[str, Any]] = Field(default_factory=list)
    probe_results: list[dict[str, Any]] = Field(default_factory=list)
    methodology: dict[str, Any] | None = None
    defense_matrix: dict[str, Any] | None = None
