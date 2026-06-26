from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentguard.guardrails.base import Guardrail, GuardrailResult, OnFail, more_severe


@dataclass
class PipelineResult:
    text: str
    action: OnFail | None = None
    changed: bool = False
    failures: list[GuardrailResult] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action in (OnFail.BLOCK, OnFail.REFRAIN)

    def feedback(self) -> str:
        parts: list[str] = []
        for failure in self.failures:
            parts.extend(failure.reasons or [failure.guardrail])
        return "; ".join(parts)


class GuardrailPipeline:
    """Runs guardrails in order. REDACT fixes are applied sequentially (chained);
    the dominant remaining action determines how the runtime should respond."""

    def __init__(self, guardrails: list[Guardrail] | None = None) -> None:
        self.guardrails = guardrails or []

    def __bool__(self) -> bool:
        return bool(self.guardrails)

    def run(self, text: str, context: dict[str, Any] | None = None) -> PipelineResult:
        context = context or {}
        current = text
        action: OnFail | None = None
        failures: list[GuardrailResult] = []

        for guardrail in self.guardrails:
            result = guardrail.validate(current, context)
            if result.passed:
                continue
            failures.append(result)
            if result.action == OnFail.REDACT and result.fixed_value is not None:
                current = result.fixed_value
            else:
                action = more_severe(action, result.action)

        changed = current != text
        if action is None and changed:
            action = OnFail.REDACT
        return PipelineResult(text=current, action=action, changed=changed, failures=failures)
