from __future__ import annotations

from agentguard.guardrails.base import Guardrail, OnFail
from agentguard.guardrails.config import GuardrailsConfig, load_guardrails_config
from agentguard.guardrails.llm_validators import GroundingValidator, ToxicityValidator, TopicValidator
from agentguard.guardrails.pipeline import GuardrailPipeline
from agentguard.guardrails.validators import PIIValidator, SchemaValidator
from agentguard.providers.llm.factory import is_litellm

_DEFAULT_ON_FAIL = {
    "pii": OnFail.REDACT,
    "schema": OnFail.REASK,
    "toxicity": OnFail.REFRAIN,
    "topic": OnFail.REFRAIN,
    "grounding": OnFail.BLOCK,
}


def build_guardrail(spec: dict, *, provider: str, model: str | None) -> Guardrail:
    gtype = spec["type"]
    if gtype not in _DEFAULT_ON_FAIL:
        raise ValueError(f"Unknown guardrail type: {gtype}")
    on_fail = OnFail(spec["on_fail"]) if "on_fail" in spec else _DEFAULT_ON_FAIL[gtype]
    llm_kwargs = {"model": spec.get("model", model), "provider": provider}

    if gtype == "pii":
        return PIIValidator(on_fail=on_fail, types=spec.get("types"))
    if gtype == "schema":
        return SchemaValidator(required=spec.get("required"), types=spec.get("types"), on_fail=on_fail)
    if gtype == "toxicity":
        return ToxicityValidator(threshold=spec.get("threshold", 0.7), on_fail=on_fail, **llm_kwargs)
    if gtype == "topic":
        return TopicValidator(allow=spec.get("allow"), deny=spec.get("deny"), on_fail=on_fail, **llm_kwargs)
    if gtype == "grounding":
        return GroundingValidator(on_fail=on_fail, **llm_kwargs)
    raise ValueError(f"Unknown guardrail type: {gtype}")


def build_guardrails(
    config: GuardrailsConfig | None = None,
    *,
    model: str | None = None,
) -> tuple[GuardrailPipeline, GuardrailPipeline, int]:
    """Build (input_pipeline, output_pipeline, max_reasks) from config. LLM
    validators inherit the configured provider (openai or litellm)."""
    config = config or load_guardrails_config()
    provider = "litellm" if is_litellm() else "openai"

    input_pipe = GuardrailPipeline([build_guardrail(s, provider=provider, model=model) for s in config.input])
    output_pipe = GuardrailPipeline([build_guardrail(s, provider=provider, model=model) for s in config.output])
    return input_pipe, output_pipe, config.max_reasks
