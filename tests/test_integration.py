"""Integration smoke test — verifies the full A -> B -> C pipeline.

This test WILL FAIL on Day 1 because DefaultAgent, PromptInjectionModule,
and RuleBasedScorer are not yet implemented. That is expected.

The test will be green by Day 7 buffer day.
"""
import pytest


@pytest.mark.xfail(
    reason="DefaultAgent, PromptInjectionModule, and RuleBasedScorer not yet implemented. "
    "Expected to pass by Day 7.",
    strict=False,
)
def test_full_pipeline():
    """Verifies the entire A -> B -> C pipeline works end-to-end."""
    from aegis.attacks.llm01_prompt_inject import PromptInjectionModule
    from aegis.evaluation.scorer import RuleBasedScorer
    from aegis.models import AttackPayload, AttackResult, EvaluationResult
    from aegis.testbed.agent import DefaultAgent

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
