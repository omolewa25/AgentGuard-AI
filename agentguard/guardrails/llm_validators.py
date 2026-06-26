from __future__ import annotations

import json
from typing import Any, Callable

from agentguard.guardrails.base import GuardrailResult, OnFail
from agentguard.providers.llm.litellm import litellm_complete, resolve_model


def run_verdict(
    system_prompt: str,
    user_content: str,
    *,
    model: str | None,
    provider: str,
    completion_fn: Callable[..., Any] | None,
    verdict_fn: Callable[[str], dict] | None,
) -> dict:
    """Get a JSON verdict from the configured LLM backend. `verdict_fn` short-circuits
    the real call (used for tests)."""
    if verdict_fn is not None:
        return verdict_fn(user_content)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
    if provider in ("litellm", "lite_llm"):
        content = litellm_complete(resolve_model(model), messages, completion_fn=completion_fn, temperature=0)
        return json.loads(content)

    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, SystemMessage

    llm = ChatOpenAI(model=resolve_model(model), temperature=0)
    response = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=user_content)])
    return json.loads(str(response.content))


_TOXICITY_PROMPT = """You score text for toxic, harmful, hateful, or unsafe content.
Return ONLY JSON: {"score": <float 0..1>, "reason": "<short reason>"}.
1.0 = clearly toxic/unsafe; 0.0 = benign."""


class ToxicityValidator:
    name = "toxicity"

    def __init__(self, threshold: float = 0.7, on_fail: OnFail = OnFail.REFRAIN, *, model=None, provider="openai", completion_fn=None, verdict_fn=None) -> None:
        self.threshold = threshold
        self.on_fail = on_fail
        self.model = model
        self.provider = provider
        self.completion_fn = completion_fn
        self.verdict_fn = verdict_fn

    def validate(self, text: str, context: dict[str, Any]) -> GuardrailResult:
        if not text.strip():
            return GuardrailResult(self.name, passed=True)
        try:
            verdict = run_verdict(_TOXICITY_PROMPT, text, model=self.model, provider=self.provider, completion_fn=self.completion_fn, verdict_fn=self.verdict_fn)
            score = float(verdict.get("score", 0.0))
        except Exception:
            return GuardrailResult(self.name, passed=True, reasons=["toxicity.unavailable"])  # fail open
        if score >= self.threshold:
            return GuardrailResult(self.name, passed=False, action=self.on_fail, score=score, reasons=[f"toxicity score {round(score, 2)} >= {self.threshold}"])
        return GuardrailResult(self.name, passed=True, score=score)


class TopicValidator:
    name = "topic"

    def __init__(self, allow: list[str] | None = None, deny: list[str] | None = None, on_fail: OnFail = OnFail.REFRAIN, *, model=None, provider="openai", completion_fn=None, verdict_fn=None) -> None:
        self.allow = allow or []
        self.deny = deny or []
        self.on_fail = on_fail
        self.model = model
        self.provider = provider
        self.completion_fn = completion_fn
        self.verdict_fn = verdict_fn

    def _prompt(self) -> str:
        return (
            "You classify whether text stays within allowed topics.\n"
            f"Allowed topics (empty = any): {self.allow}\n"
            f"Denied topics: {self.deny}\n"
            'Return ONLY JSON: {"on_topic": <bool>, "matched_denied": [<denied topics present>], "reason": "<short>"}.'
        )

    def validate(self, text: str, context: dict[str, Any]) -> GuardrailResult:
        if not text.strip() or (not self.allow and not self.deny):
            return GuardrailResult(self.name, passed=True)
        try:
            verdict = run_verdict(self._prompt(), text, model=self.model, provider=self.provider, completion_fn=self.completion_fn, verdict_fn=self.verdict_fn)
        except Exception:
            return GuardrailResult(self.name, passed=True, reasons=["topic.unavailable"])  # fail open
        denied = verdict.get("matched_denied") or []
        on_topic = verdict.get("on_topic", True)
        if denied or (self.allow and not on_topic):
            reason = "; ".join(denied) if denied else "off-topic"
            return GuardrailResult(self.name, passed=False, action=self.on_fail, reasons=[reason])
        return GuardrailResult(self.name, passed=True)


_GROUNDING_PROMPT = """You check whether an ANSWER is supported by the provided SOURCES.
Return ONLY JSON: {"grounded": <bool>, "score": <float 0..1>, "reason": "<short reason>"}.
grounded=false if the answer makes claims not supported by the sources."""


class GroundingValidator:
    """Checks the answer against sources in context['sources']. Skipped (passes)
    when there are no sources to ground against."""

    name = "grounding"

    def __init__(self, on_fail: OnFail = OnFail.BLOCK, *, model=None, provider="openai", completion_fn=None, verdict_fn=None) -> None:
        self.on_fail = on_fail
        self.model = model
        self.provider = provider
        self.completion_fn = completion_fn
        self.verdict_fn = verdict_fn

    def validate(self, text: str, context: dict[str, Any]) -> GuardrailResult:
        sources = context.get("sources") or []
        if not text.strip() or not sources:
            return GuardrailResult(self.name, passed=True)
        user_content = "SOURCES:\n" + "\n---\n".join(str(s) for s in sources) + f"\n\nANSWER:\n{text}"
        try:
            verdict = run_verdict(_GROUNDING_PROMPT, user_content, model=self.model, provider=self.provider, completion_fn=self.completion_fn, verdict_fn=self.verdict_fn)
        except Exception:
            return GuardrailResult(self.name, passed=True, reasons=["grounding.unavailable"])  # fail open
        if not verdict.get("grounded", True):
            return GuardrailResult(self.name, passed=False, action=self.on_fail, score=float(verdict.get("score", 0.0)), reasons=[str(verdict.get("reason", "not grounded in sources"))])
        return GuardrailResult(self.name, passed=True, score=float(verdict.get("score", 1.0)))
