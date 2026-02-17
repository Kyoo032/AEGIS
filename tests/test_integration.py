"""Integration smoke test — verifies the full A -> B -> C pipeline."""
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
