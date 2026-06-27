import json

import pytest

from agentguard.guardrails.base import OnFail
from agentguard.guardrails.llm_validators import GroundingValidator, ToxicityValidator, TopicValidator
from agentguard.guardrails.validators import PIIValidator, SchemaValidator

pytestmark = pytest.mark.unit


# --- deterministic: PII ----------------------------------------------------------

def test_pii_redacts_email_and_ssn():
    result = PIIValidator().validate("reach me at a@b.com or 123-45-6789", {})
    assert result.passed is False
    assert result.action == OnFail.REDACT
    assert "a@b.com" not in result.fixed_value
    assert "123-45-6789" not in result.fixed_value


def test_pii_passes_clean_text():
    assert PIIValidator().validate("no personal data here", {}).passed is True


# --- deterministic: schema -------------------------------------------------------

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


# --- llm validators (injected verdicts) ------------------------------------------

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
