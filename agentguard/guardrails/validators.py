from __future__ import annotations

import json
import re
from typing import Any

from agentguard.guardrails.base import GuardrailResult, OnFail

PII_PATTERNS: dict[str, str] = {
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "ssn": r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
    "phone": r"(?<!\d)(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)",
    "credit_card": r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)",
}


class PIIValidator:
    name = "pii"

    def __init__(self, on_fail: OnFail = OnFail.REDACT, types: list[str] | None = None) -> None:
        self.on_fail = on_fail
        self.patterns = {k: v for k, v in PII_PATTERNS.items() if not types or k in types}

    def validate(self, text: str, context: dict[str, Any]) -> GuardrailResult:
        found: list[str] = []
        redacted = text
        for name, pattern in self.patterns.items():
            redacted, count = re.subn(pattern, f"[REDACTED_{name.upper()}]", redacted)
            if count:
                found.append(name)
        if not found:
            return GuardrailResult(self.name, passed=True)
        return GuardrailResult(self.name, passed=False, action=self.on_fail, fixed_value=redacted, reasons=[f"contains {t}" for t in found])


def _type_ok(value: Any, expected: str) -> bool:
    mapping = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "object": dict,
        "array": list,
    }
    python_type = mapping.get(expected)
    if python_type is None:
        return True
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, python_type)


class SchemaValidator:
    """Lightweight structured-output check (no external dependency): verifies the
    output parses as a JSON object with required fields and basic types."""

    name = "schema"

    def __init__(self, required: list[str] | None = None, types: dict[str, str] | None = None, on_fail: OnFail = OnFail.REASK) -> None:
        self.required = required or []
        self.types = types or {}
        self.on_fail = on_fail

    def validate(self, text: str, context: dict[str, Any]) -> GuardrailResult:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return GuardrailResult(self.name, passed=False, action=self.on_fail, reasons=["output is not valid JSON"])

        errors: list[str] = []
        if not isinstance(data, dict):
            errors.append("output must be a JSON object")
        else:
            for key in self.required:
                if key not in data:
                    errors.append(f"missing required field '{key}'")
            for key, expected in self.types.items():
                if key in data and not _type_ok(data[key], expected):
                    errors.append(f"field '{key}' must be of type {expected}")

        if errors:
            return GuardrailResult(self.name, passed=False, action=self.on_fail, reasons=errors)
        return GuardrailResult(self.name, passed=True)
