from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

GUARDRAILS_ENV_VAR = "AGENTGUARD_GUARDRAILS_CONFIG"


@dataclass
class GuardrailsConfig:
    input: list[dict] = field(default_factory=list)
    output: list[dict] = field(default_factory=list)
    max_reasks: int = 1


def _parse(path: str, raw: str) -> dict:
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to load YAML guardrails config.") from exc
        return yaml.safe_load(raw) or {}
    return json.loads(raw)


def load_guardrails_config(path: str | None = None) -> GuardrailsConfig:
    path = path or os.getenv(GUARDRAILS_ENV_VAR)
    if not path or not os.path.exists(path):
        return GuardrailsConfig()

    with open(path, encoding="utf-8") as handle:
        data = _parse(path, handle.read()) or {}

    return GuardrailsConfig(
        input=list(data.get("input", [])),
        output=list(data.get("output", [])),
        max_reasks=int(data.get("max_reasks", 1)),
    )
