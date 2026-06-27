import pytest

from agentguard.guardrails.base import OnFail
from agentguard.guardrails.llm_validators import GroundingValidator, ToxicityValidator, TopicValidator
from agentguard.guardrails.pipeline import GuardrailPipeline
from agentguard.guardrails.validators import PIIValidator
from agentguard.tools.registry import ToolRegistry
from tests._helpers.factories import build_runtime, single_tool_registry
from tests._helpers.fakes import FakePlanner, SequencePlanner

pytestmark = pytest.mark.integration


def test_output_pii_redacted_via_guardrail():
    registry = single_tool_registry("lookup", lambda: "contact bob@corp.com")
    output = GuardrailPipeline([PIIValidator()])
    runtime = build_runtime(registry, {"tool_name": "lookup", "tool_args": {}, "answer": ""}, output_guardrails=output)
    result = runtime.invoke("look it up", user_role="user")
    assert "bob@corp.com" not in result["answer"]


def test_output_toxicity_blocks(store):
    output = GuardrailPipeline([ToxicityValidator(threshold=0.5, verdict_fn=lambda t: {"score": 0.95})])
    runtime = build_runtime(
        ToolRegistry(),
        {"tool_name": None, "tool_args": {}, "answer": "something toxic"},
        store=store,
        output_guardrails=output,
    )
    result = runtime.invoke("say something", user_role="user")
    assert result.get("blocked") is True
    assert any(e["event_type"] == "guardrail_blocked" for e in store.audit_logs)


def test_input_topic_refrains(store):
    input_pipe = GuardrailPipeline([TopicValidator(deny=["legal"], verdict_fn=lambda t: {"on_topic": True, "matched_denied": ["legal"]})])
    runtime = build_runtime(
        ToolRegistry(),
        {"tool_name": None, "tool_args": {}, "answer": "SHOULD NOT RUN"},
        store=store,
        input_guardrails=input_pipe,
    )
    result = runtime.invoke("give me legal advice", user_role="user")
    assert result.get("blocked") is True
    assert result["answer"] != "SHOULD NOT RUN"


def test_reask_loop_recovers_then_succeeds(store):
    # First answer is ungrounded -> reask; second answer is grounded -> passes.
    verdicts = iter([{"grounded": False, "reason": "unsupported"}, {"grounded": True, "score": 1.0}])
    output = GuardrailPipeline([GroundingValidator(on_fail=OnFail.REASK, verdict_fn=lambda t: next(verdicts))])
    planner = SequencePlanner([
        {"tool_name": "fetch", "tool_args": {}, "answer": ""},
        {"tool_name": "fetch", "tool_args": {}, "answer": ""},
    ])
    registry = single_tool_registry("fetch", lambda: "grounded source content")
    runtime = build_runtime(registry, planner=planner, store=store, output_guardrails=output, max_reasks=1)
    result = runtime.invoke("fetch it", user_role="user")
    assert result.get("blocked") is not True
    assert planner.calls == 2
    assert any(e["event_type"] == "guardrail_reask" for e in store.audit_logs)


def test_reask_exhausted_blocks(store):
    output = GuardrailPipeline([GroundingValidator(on_fail=OnFail.REASK, verdict_fn=lambda t: {"grounded": False, "reason": "nope"})])
    registry = single_tool_registry("fetch", lambda: "source content")
    runtime = build_runtime(
        registry,
        {"tool_name": "fetch", "tool_args": {}, "answer": ""},
        store=store,
        output_guardrails=output,
        max_reasks=1,
    )
    result = runtime.invoke("fetch it", user_role="user")
    assert result.get("blocked") is True
    assert any(e["event_type"] == "guardrail_blocked" for e in store.audit_logs)


def test_no_guardrails_is_backward_compatible():
    registry = single_tool_registry("search", lambda: "Document search returned 3 results.")
    runtime = build_runtime(registry, {"tool_name": "search", "tool_args": {}, "answer": ""})
    result = runtime.invoke("search the docs", user_role="user")
    assert result["answer"] == "Document search returned 3 results."
