from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class OnFail(str, Enum):
    """What to do when a guardrail fails, in ascending order of severity."""

    LOG = "log"                       # record only; allow through
    REDACT = "redact"                 # replace offending content, allow through
    REQUIRE_APPROVAL = "require_approval"  # escalate to human approval
    REASK = "reask"                   # re-prompt the model with feedback (output only)
    REFRAIN = "refrain"               # refuse with a safe message
    BLOCK = "block"                   # hard stop


_SEVERITY = {
    OnFail.LOG: 0,
    OnFail.REDACT: 1,
    OnFail.REQUIRE_APPROVAL: 2,
    OnFail.REASK: 3,
    OnFail.REFRAIN: 4,
    OnFail.BLOCK: 5,
}


def more_severe(a: OnFail | None, b: OnFail | None) -> OnFail | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if _SEVERITY[a] >= _SEVERITY[b] else b


@dataclass
class GuardrailResult:
    guardrail: str
    passed: bool
    action: OnFail = OnFail.LOG
    score: float = 0.0
    fixed_value: str | None = None
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Guardrail(Protocol):
    name: str
    on_fail: OnFail

    def validate(self, text: str, context: dict[str, Any]) -> GuardrailResult: ...
