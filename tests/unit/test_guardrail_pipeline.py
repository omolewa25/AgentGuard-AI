import pytest

from agentguard.guardrails.base import OnFail
from agentguard.guardrails.llm_validators import ToxicityValidator
from agentguard.guardrails.pipeline import GuardrailPipeline
from agentguard.guardrails.validators import PIIValidator

pytestmark = pytest.mark.unit


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
