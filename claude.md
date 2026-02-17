# AEGIS — Agentic Exploit & Guardrail Investigation Suite

## What This Project Is

AEGIS is a security testing framework for auditing agentic AI systems. It targets three OWASP frameworks: LLM Top 10 (2025), Agentic Top 10 (2026), and MCP Top 10 (2025).

Three components: a vulnerable AI agent testbed connected via MCP, modular attack engine, and detection/evaluation/reporting pipeline.

## Team Structure

Two parallel tracks. Each track owns specific directories. **Never edit files outside your track without explicit approval.**

- **Backend Lead:** `aegis/testbed/`, `aegis/defenses/`, `aegis/cli.py`, `aegis/orchestrator.py`
- **Security Lead:** `aegis/attacks/`, `aegis/attacks/payloads/`, `aegis/evaluation/`, `aegis/reporting/`, `promptfoo_configs/`, `docs/`, `datasets/`
- **Shared (both, changes require consensus):** `aegis/models.py`, `aegis/interfaces/`, `aegis/config.yaml`, `tests/test_integration.py`

## Tech Stack

| Component | Tool |
|-----------|------|
| Language | Python 3.11+ |
| Agent Framework | LangChain + LangGraph |
| MCP Implementation | FastMCP (Python SDK) |
| LLM Providers | Ollama (local, primary) + HuggingFace API (fallback) |
| Local Models | Qwen3-4B (primary, Q4_K_M), Qwen3-1.7B (fallback/judge) — 4GB VRAM, 4K context |
| Vector Store | ChromaDB |
| Red Team Framework | Promptfoo |
| MCP Scanner | Proximity |
| LLM Vulnerability Scanner | Garak |
| Evaluation | DeepEval + custom scorers |
| Reporting | Jinja2 templates + JSON schema |
| CLI | Typer |
| Testing | pytest |
| CI/CD | GitHub Actions |

## Repository Structure

```
aegis/
  models.py                   # SHARED — Pydantic data models (both tracks import from here)
  interfaces/
    agent.py                  # SHARED — AgentInterface ABC
    attack.py                 # SHARED — AttackModule ABC
    scorer.py                 # SHARED — Scorer ABC
    defense.py                # SHARED — Defense ABC
  orchestrator.py             # BACKEND LEAD OWNS — Main execution pipeline
  config.yaml                 # SHARED — Global configuration

  testbed/                    # BACKEND LEAD OWNS
    agent.py                  # Configurable victim agent (implements AgentInterface)
    mcp_servers/
      filesystem_server.py    # File access MCP server
      http_server.py          # HTTP request MCP server
      email_server.py         # Mock email MCP server
      database_server.py      # Mock DB MCP server
      code_exec_server.py     # Sandboxed code execution
      evil_server.py          # Intentionally malicious MCP server (for supply chain testing)
    rag_pipeline.py           # RAG with ChromaDB for indirect injection testing
    memory_store.py           # Agent memory for poisoning tests

  attacks/                    # SECURITY LEAD OWNS
    base.py                   # Convenience base implementing AttackModule
    asi01_goal_hijack.py
    asi02_tool_misuse.py
    asi04_supply_chain.py
    asi05_code_exec.py
    asi06_memory_poison.py
    mcp06_cmd_injection.py
    llm01_prompt_inject.py
    payloads/                 # YAML payload templates per module

  defenses/                   # BACKEND LEAD OWNS
    input_validator.py
    output_filter.py
    tool_boundary.py
    mcp_integrity.py
    permission_enforcer.py

  evaluation/                 # SECURITY LEAD OWNS
    scorer.py                 # Attack success scoring engine
    llm_judge.py              # LLM-as-judge evaluator
    rule_detector.py          # Pattern-based detection rules
    metrics.py                # ASR, bypass rate, defense effectiveness

  reporting/                  # SECURITY LEAD OWNS
    report_generator.py       # JSON + HTML + PDF report output
    owasp_mapper.py           # Maps findings to OWASP categories
    atlas_mapper.py           # Maps findings to MITRE ATLAS techniques
    templates/                # Jinja2 report templates

  cli.py                      # BACKEND LEAD OWNS — CLI entry point (Typer)

tests/
  test_models.py              # Validates shared models
  test_integration.py         # SHARED — Full pipeline smoke test
  test_testbed/               # Backend Lead
  test_attacks/               # Security Lead
  test_eval/                  # Security Lead

promptfoo_configs/            # SECURITY LEAD OWNS
docs/
  METHODOLOGY.md
  FINDINGS.md
  DEFENSE_EVALUATION.md
datasets/
  payloads/
  results/
```

## Shared Data Models

These live in `aegis/models.py`. ALL cross-track data uses these models. Never define alternative structures.

```python
from pydantic import BaseModel
from datetime import datetime


class AttackPayload(BaseModel):
    """What Security Lead produces. Backend Lead's testbed consumes this."""
    id: str                            # Unique payload ID e.g. "ASI01-GOAL-003"
    attack_module: str                 # Module name e.g. "asi01_goal_hijack"
    owasp_id: str                      # OWASP category e.g. "ASI01"
    atlas_technique: str | None = None # MITRE ATLAS ID e.g. "AML.T0051"
    category: str                      # Human-readable e.g. "Agent Goal Hijacking"
    messages: list[dict]               # Conversation turns [{"role": ..., "content": ...}]
    injected_context: str | None = None # Poisoned doc/tool output (for indirect injection)
    target_tools: list[str] | None = None # Which MCP tools this attack targets
    expected_behavior: str             # What a successful attack looks like
    severity: str                      # "critical" | "high" | "medium" | "low"
    metadata: dict = {}                # Freeform extra data


class ToolCall(BaseModel):
    """A single MCP tool invocation captured by the agent."""
    tool_name: str
    parameters: dict
    result: str
    timestamp: datetime


class AgentResponse(BaseModel):
    """What Backend Lead's testbed returns. Security Lead captures this."""
    payload_id: str                    # Links back to AttackPayload.id
    agent_profile: str                 # Which agent config was used
    messages: list[dict]               # Full conversation history
    final_output: str                  # Agent's final text response
    tool_calls: list[ToolCall]         # Every tool invocation in order
    memory_state: dict | None = None   # Agent memory after interaction
    raw_llm_output: str | None = None  # Raw LLM completion
    error: str | None = None           # If the agent errored
    duration_ms: int = 0               # Interaction duration
    defense_active: str | None = None  # Which defense was enabled (or None)


class AttackResult(BaseModel):
    """What Security Lead assembles for scoring."""
    payload: AttackPayload
    response: AgentResponse
    timestamp: datetime
    run_id: str                        # Groups results from same batch


class EvaluationResult(BaseModel):
    """What Security Lead's scorer produces."""
    attack_result: AttackResult
    success: bool                      # Did the attack succeed?
    confidence: float                  # 0.0 to 1.0
    scoring_method: str                # "rule_based" | "llm_judge" | "semantic"
    explanation: str                   # Why the scorer decided this way
    indicators: list[str]              # Evidence the scorer found
    defense_bypassed: bool | None = None
    owasp_id: str                      # Inherited from payload
    atlas_technique: str | None = None


class Finding(BaseModel):
    """A key finding for the security report."""
    title: str
    owasp_id: str
    atlas_technique: str | None = None
    severity: str
    description: str
    evidence: list[str]
    recommendation: str


class OWASPCategoryResult(BaseModel):
    """Aggregated results for one OWASP category."""
    owasp_id: str
    category_name: str
    total_attacks: int
    successful_attacks: int
    attack_success_rate: float
    findings: list[Finding]


class SecurityReport(BaseModel):
    """Final output from Security Lead's report generator."""
    report_id: str
    generated_at: datetime
    testbed_config: dict
    total_attacks: int
    total_successful: int
    attack_success_rate: float
    results_by_owasp: dict[str, OWASPCategoryResult]
    defense_comparison: dict | None = None
    findings: list[Finding]
    recommendations: list[str]
```

## Abstract Interfaces

These live in `aegis/interfaces/`. Each track implements behind these. Code against the interface, never against another track's internals.

### AgentInterface — Backend Lead implements. Security Lead calls.

```python
# aegis/interfaces/agent.py
from abc import ABC, abstractmethod
from aegis.models import AttackPayload, AgentResponse


class AgentInterface(ABC):

    @abstractmethod
    def run(self, payload: AttackPayload) -> AgentResponse:
        """Send an attack payload to the agent, return structured response."""
        ...

    @abstractmethod
    def reset(self) -> None:
        """Reset agent state (memory, context) between test runs."""
        ...

    @abstractmethod
    def get_config(self) -> dict:
        """Return current agent configuration (model, tools, profile)."""
        ...

    @abstractmethod
    def enable_defense(self, defense_name: str, config: dict) -> None:
        """Activate a defense module on the agent."""
        ...

    @abstractmethod
    def disable_defense(self, defense_name: str) -> None:
        """Deactivate a defense module."""
        ...

    @abstractmethod
    def inject_context(self, context: str, method: str) -> None:
        """Inject content into RAG store or memory.
        method: 'rag' | 'memory' | 'tool_output'"""
        ...
```

### AttackModule — Security Lead implements. Orchestrator calls.

```python
# aegis/interfaces/attack.py
from abc import ABC, abstractmethod
from aegis.models import AttackPayload, AttackResult
from aegis.interfaces.agent import AgentInterface


class AttackModule(ABC):
    name: str              # e.g. "asi01_goal_hijack"
    owasp_id: str          # e.g. "ASI01"
    atlas_technique: str | None = None
    description: str = ""

    @abstractmethod
    def generate_payloads(self, target_config: dict) -> list[AttackPayload]:
        """Generate attack payloads. target_config from agent.get_config()."""
        ...

    @abstractmethod
    def execute(self, agent: AgentInterface) -> list[AttackResult]:
        """Run all payloads against the agent, return results."""
        ...

    @abstractmethod
    def get_metadata(self) -> dict:
        """Return module metadata for reporting."""
        ...
```

### Scorer — Security Lead implements. Evaluation pipeline calls.

```python
# aegis/interfaces/scorer.py
from abc import ABC, abstractmethod
from aegis.models import AttackResult, EvaluationResult


class Scorer(ABC):
    name: str              # e.g. "rule_based", "llm_judge"

    @abstractmethod
    def evaluate(self, result: AttackResult) -> EvaluationResult:
        """Score a single attack result."""
        ...
```

### Defense — Backend Lead implements. Plugs into AgentInterface.

```python
# aegis/interfaces/defense.py
from abc import ABC, abstractmethod
from aegis.interfaces.agent import AgentInterface


class Defense(ABC):
    name: str
    description: str = ""

    @abstractmethod
    def apply(self, agent: AgentInterface) -> None:
        """Install this defense on the agent."""
        ...

    @abstractmethod
    def remove(self, agent: AgentInterface) -> None:
        """Remove this defense from the agent."""
        ...

    @abstractmethod
    def inspect(self, input_data: str | dict) -> tuple[bool, str]:
        """Check if input should be blocked. Returns (blocked, reason)."""
        ...
```

## Orchestrator Pattern

This is the glue code where both tracks meet. Lives in `aegis/orchestrator.py`. Backend Lead owns.

```python
class AEGISOrchestrator:

    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.agent = self._build_agent()         # Backend Lead's code
        self.attacks = self._load_attacks()       # Security Lead's code
        self.scorers = self._load_scorers()       # Security Lead's code
        self.reporter = ReportGenerator(self.config)

    def run_baseline(self) -> SecurityReport:
        """Run all attacks with no defenses."""
        all_eval_results = []
        for attack_module in self.attacks:
            self.agent.reset()
            results = attack_module.execute(self.agent)
            for result in results:
                for scorer in self.scorers:
                    eval_result = scorer.evaluate(result)
                    all_eval_results.append(eval_result)
        return self.reporter.generate(all_eval_results)

    def run_with_defense(self, defense_name: str) -> SecurityReport:
        """Run all attacks with a specific defense enabled."""
        self.agent.enable_defense(defense_name, self.config)
        report = self.run_baseline()
        self.agent.disable_defense(defense_name)
        return report

    def run_full_matrix(self) -> dict[str, SecurityReport]:
        """Run baseline + every defense. Returns comparison data."""
        reports = {"baseline": self.run_baseline()}
        for defense in self.config["defenses"]["available"]:
            reports[defense] = self.run_with_defense(defense)
        return reports
```

## Configuration Schema

Lives in `aegis/config.yaml`. Both tracks read from this.

```yaml
testbed:
  model: "qwen3:4b"
  fallback_model: "qwen3:1.7b"
  context_length: 4096              # 4GB VRAM budget — do not exceed
  model_provider: "ollama"          # ollama | huggingface | anthropic
  agent_profile: "default"          # default | hardened | minimal
  mcp_servers:
    - filesystem
    - http
    - email
    - code_exec
  rag_enabled: true
  memory_enabled: true

attacks:
  modules:
    - asi01_goal_hijack
    - asi02_tool_misuse
    - asi04_supply_chain
    - asi05_code_exec
    - asi06_memory_poison
    - mcp06_cmd_injection
    - llm01_prompt_inject
  payloads_per_module: 10
  multi_turn: true

evaluation:
  scorers:
    - rule_based
    - llm_judge
  judge_model: "qwen3:1.7b"
  confidence_threshold: 0.7

defenses:
  active: []
  available:
    - input_validator
    - output_filter
    - tool_boundary
    - mcp_integrity
    - permission_enforcer

reporting:
  formats: ["json", "html"]
  output_dir: "./reports"
  include_atlas_mapping: true
```

## OWASP Attack Surface Mapping

Each attack module maps to specific OWASP categories:

| Module | OWASP ID | Risk | MITRE ATLAS |
|--------|----------|------|-------------|
| asi01_goal_hijack | ASI01 | Agent Goal Hijacking | AML.T0051 |
| asi02_tool_misuse | ASI02 | Tool Misuse & Exploitation | AML.T0040 |
| asi04_supply_chain | ASI04 | Supply Chain Vulnerabilities | AML.T0010 |
| asi05_code_exec | ASI05 | Unexpected Code Execution | AML.T0051 |
| asi06_memory_poison | ASI06 | Memory & Context Poisoning | AML.T0020 |
| mcp06_cmd_injection | MCP06 | Command Injection | AML.T0040 |
| llm01_prompt_inject | LLM01 | Prompt Injection | AML.T0051 |

> **Stretch goals:** `mcp01_token_leak` (MCP01), `llm02_data_disclosure` (LLM02), and `asi03_privilege_abuse` (ASI03) are descoped from the 2-person plan. Add if time permits.

## Integration Test

This must pass before any merge to develop:

```python
# tests/test_integration.py

def test_full_pipeline():
    """Verifies the entire Backend -> Security pipeline works end-to-end."""
    agent = DefaultAgent(config="test")
    attack = PromptInjectionModule()
    scorer = RuleBasedScorer()

    payloads = attack.generate_payloads(agent.get_config())
    assert len(payloads) > 0
    assert all(isinstance(p, AttackPayload) for p in payloads)

    results = attack.execute(agent)
    assert len(results) > 0
    assert all(isinstance(r, AttackResult) for r in results)

    for result in results:
        eval_result = scorer.evaluate(result)
        assert isinstance(eval_result, EvaluationResult)
        assert eval_result.owasp_id == result.payload.owasp_id
```

## Code Conventions

- Type hints on all function signatures
- Docstrings on all public methods
- Pydantic models for all data crossing track boundaries
- `pytest` for all tests
- `ruff` for linting
- Logging via Python `logging` module, not print statements
- All MCP servers use FastMCP Python SDK patterns
- YAML for payload templates, not hardcoded strings in Python
