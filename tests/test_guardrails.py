import json

from agentguard.core.runtime import AgentGuardRuntime
from agentguard.guardrails.base import GuardrailResult, OnFail, more_severe
from agentguard.guardrails.config import GuardrailsConfig, load_guardrails_config
from agentguard.guardrails.factory import build_guardrails
from agentguard.guardrails.llm_validators import GroundingValidator, ToxicityValidator, TopicValidator
from agentguard.guardrails.pipeline import GuardrailPipeline
from agentguard.guardrails.validators import PIIValidator, SchemaValidator
from agentguard.policies.risk import RiskLevel
from agentguard.providers.storage.memory import MemoryStore
from agentguard.tools.registry import ToolRegistry


class FakePlanner:
    def __init__(self, decision):
        self.decision = decision

    def plan(self, system_prompt, user_message):
        return self.decision


class SequencePlanner:
    """Returns a different decision on each call; used to test the reask loop."""

    def __init__(self, decisions):
        self.decisions = decisions
        self.calls = 0

    def plan(self, system_prompt, user_message):
        decision = self.decisions[min(self.calls, len(self.decisions) - 1)]
        self.calls += 1
        return decision


# --- core ------------------------------------------------------------------------

def test_more_severe_ordering():
    assert more_severe(OnFail.REDACT, OnFail.BLOCK) == OnFail.BLOCK
    assert more_severe(OnFail.REASK, OnFail.REDACT) == OnFail.REASK
    assert more_severe(None, OnFail.LOG) == OnFail.LOG


# --- deterministic validators ----------------------------------------------------

def test_pii_redacts_email_and_ssn():
    result = PIIValidator().validate("reach me at a@b.com or 123-45-6789", {})
    assert result.passed is False
    assert result.action == OnFail.REDACT
    assert "a@b.com" not in result.fixed_value
    assert "123-45-6789" not in result.fixed_value


def test_pii_passes_clean_text():
    assert PIIValidator().validate("no personal data here", {}).passed is True


def test_schema_flags_invalid_json():
    result = SchemaValidator(required=["name"]).validate("not json", {})
    assert result.passed is False
    assert result.action == OnFail.REASK


def test_schema_flags_missing_field_and_wrong_type():
    result = SchemaValidator(required=["name"], types={"age": "number"}).validate(json.dumps({"age": "old"}), {})
    assert result.passed is False
    assert any("name" in r for r in result.reasons)
    assert any("age" in r for r in result.reasons)


def test_schema_passes_valid_object():
    assert SchemaValidator(required=["name"], types={"name": "string"}).validate(json.dumps({"name": "x"}), {}).passed is True


# --- llm validators (with injected verdicts) -------------------------------------

def test_toxicity_blocks_above_threshold():
    v = ToxicityValidator(threshold=0.7, verdict_fn=lambda t: {"score": 0.9})
    result = v.validate("nasty content", {})
    assert result.passed is False and result.action == OnFail.REFRAIN


def test_toxicity_fails_open_on_error():
    def boom(t):
        raise RuntimeError("down")

    assert ToxicityValidator(verdict_fn=boom).validate("x", {}).passed is True


def test_topic_blocks_denied():
    v = TopicValidator(deny=["legal advice"], verdict_fn=lambda t: {"on_topic": True, "matched_denied": ["legal advice"]})
    assert v.validate("should I sue?", {}).passed is False


def test_topic_skipped_when_no_lists():
    assert TopicValidator(verdict_fn=lambda t: {"on_topic": False}).validate("anything", {}).passed is True


def test_grounding_skipped_without_sources():
    assert GroundingValidator(verdict_fn=lambda t: {"grounded": False}).validate("claim", {}).passed is True


def test_grounding_flags_ungrounded_with_sources():
    v = GroundingValidator(verdict_fn=lambda t: {"grounded": False, "score": 0.1, "reason": "unsupported"})
    result = v.validate("the moon is cheese", {"sources": ["the moon is rock"]})
    assert result.passed is False


# --- pipeline --------------------------------------------------------------------

def test_pipeline_chains_redactions_and_picks_dominant_action():
    pipe = GuardrailPipeline([
        PIIValidator(),
        ToxicityValidator(threshold=0.5, verdict_fn=lambda t: {"score": 0.9}),
    ])
    result = pipe.run("email a@b.com, and toxic stuff")
    assert "a@b.com" not in result.text          # redaction applied
    assert result.blocked is True                # toxicity (refrain) dominates


def test_pipeline_redact_only_marks_changed():
    result = GuardrailPipeline([PIIValidator()]).run("contact a@b.com")
    assert result.changed is True
    assert result.action == OnFail.REDACT
    assert result.blocked is False


# --- config / factory ------------------------------------------------------------

def test_load_guardrails_config(tmp_path):
    path = tmp_path / "g.json"
    path.write_text(json.dumps({"output": [{"type": "pii"}], "max_reasks": 3}))
    config = load_guardrails_config(str(path))
    assert config.max_reasks == 3 and config.output[0]["type"] == "pii"


def test_build_guardrails_assembles_pipelines():
    config = GuardrailsConfig(
        input=[{"type": "topic", "deny": ["x"]}],
        output=[{"type": "pii"}, {"type": "toxicity"}, {"type": "grounding"}],
        max_reasks=2,
    )
    input_pipe, output_pipe, max_reasks = build_guardrails(config)
    assert max_reasks == 2
    assert [g.name for g in input_pipe.guardrails] == ["topic"]
    assert [g.name for g in output_pipe.guardrails] == ["pii", "toxicity", "grounding"]


def test_build_guardrail_unknown_type_raises():
    import pytest

    with pytest.raises(ValueError):
        build_guardrails(GuardrailsConfig(output=[{"type": "nope"}]))


# --- end-to-end runtime ----------------------------------------------------------

def _registry_with(name, handler):
    registry = ToolRegistry()
    registry.register(name, handler, "desc", RiskLevel.LOW, False, ["user"])
    return registry


def test_output_pii_redacted_via_guardrail():
    registry = _registry_with("lookup", lambda: "contact bob@corp.com")
    output = GuardrailPipeline([PIIValidator()])
    runtime = AgentGuardRuntime(
        registry=registry,
        planner=FakePlanner({"tool_name": "lookup", "tool_args": {}, "answer": ""}),
        store=MemoryStore(),
        output_guardrails=output,
    )
    result = runtime.invoke("look it up", user_role="user")
    assert "bob@corp.com" not in result["answer"]


def test_output_toxicity_blocks():
    store = MemoryStore()
    output = GuardrailPipeline([ToxicityValidator(threshold=0.5, verdict_fn=lambda t: {"score": 0.95})])
    runtime = AgentGuardRuntime(
        registry=ToolRegistry(),
        planner=FakePlanner({"tool_name": None, "tool_args": {}, "answer": "something toxic"}),
        store=store,
        output_guardrails=output,
    )
    result = runtime.invoke("say something", user_role="user")
    assert result.get("blocked") is True
    assert any(e["event_type"] == "guardrail_blocked" for e in store.audit_logs)


def test_input_topic_refrains():
    store = MemoryStore()
    input_pipe = GuardrailPipeline([TopicValidator(deny=["legal"], verdict_fn=lambda t: {"on_topic": True, "matched_denied": ["legal"]})])
    runtime = AgentGuardRuntime(
        registry=ToolRegistry(),
        planner=FakePlanner({"tool_name": None, "tool_args": {}, "answer": "SHOULD NOT RUN"}),
        store=store,
        input_guardrails=input_pipe,
    )
    result = runtime.invoke("give me legal advice", user_role="user")
    assert result.get("blocked") is True
    assert result["answer"] != "SHOULD NOT RUN"


def test_reask_loop_recovers_then_succeeds():
    # First answer is ungrounded -> reask; second answer is grounded -> passes.
    verdicts = iter([{"grounded": False, "reason": "unsupported"}, {"grounded": True, "score": 1.0}])
    output = GuardrailPipeline([GroundingValidator(on_fail=OnFail.REASK, verdict_fn=lambda t: next(verdicts))])
    store = MemoryStore()
    planner = SequencePlanner([
        {"tool_name": "fetch", "tool_args": {}, "answer": ""},
        {"tool_name": "fetch", "tool_args": {}, "answer": ""},
    ])
    registry = _registry_with("fetch", lambda: "grounded source content")
    runtime = AgentGuardRuntime(registry=registry, planner=planner, store=store, output_guardrails=output, max_reasks=1)
    result = runtime.invoke("fetch it", user_role="user")
    assert result.get("blocked") is not True
    assert planner.calls == 2
    assert any(e["event_type"] == "guardrail_reask" for e in store.audit_logs)


def test_reask_exhausted_blocks():
    output = GuardrailPipeline([GroundingValidator(on_fail=OnFail.REASK, verdict_fn=lambda t: {"grounded": False, "reason": "nope"})])
    store = MemoryStore()
    registry = _registry_with("fetch", lambda: "source content")
    runtime = AgentGuardRuntime(
        registry=registry,
        planner=FakePlanner({"tool_name": "fetch", "tool_args": {}, "answer": ""}),
        store=store,
        output_guardrails=output,
        max_reasks=1,
    )
    result = runtime.invoke("fetch it", user_role="user")
    assert result.get("blocked") is True
    assert any(e["event_type"] == "guardrail_blocked" for e in store.audit_logs)


def test_no_guardrails_is_backward_compatible():
    registry = _registry_with("search", lambda: "Document search returned 3 results.")
    runtime = AgentGuardRuntime(
        registry=registry,
        planner=FakePlanner({"tool_name": "search", "tool_args": {}, "answer": ""}),
        store=MemoryStore(),
    )
    result = runtime.invoke("search the docs", user_role="user")
    assert result["answer"] == "Document search returned 3 results."
