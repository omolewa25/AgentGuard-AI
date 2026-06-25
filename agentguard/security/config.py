from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

CONFIG_ENV_VAR = "AGENTGUARD_SECURITY_CONFIG"


@dataclass
class SecurityConfig:
    injection_patterns: list[str] = field(default_factory=list)
    injection_regex: list[str] = field(default_factory=list)
    enable_llm_judge: bool = False
    enable_transformers: bool = False
    transformers_model: str | None = None
    block_threshold: float | None = None
    approval_threshold: float | None = None


def _parse(path: str, raw: str) -> dict:
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to load YAML security config.") from exc
        return yaml.safe_load(raw) or {}
    return json.loads(raw)


def load_security_config(path: str | None = None) -> SecurityConfig:
    """Load security config from an explicit path or the AGENTGUARD_SECURITY_CONFIG
    env var. Missing/empty config yields framework defaults."""
    path = path or os.getenv(CONFIG_ENV_VAR)
    if not path or not os.path.exists(path):
        return SecurityConfig()

    with open(path, encoding="utf-8") as handle:
        data = _parse(path, handle.read()) or {}

    return SecurityConfig(
        injection_patterns=list(data.get("injection_patterns", [])),
        injection_regex=list(data.get("injection_regex", [])),
        enable_llm_judge=bool(data.get("enable_llm_judge", False)),
        enable_transformers=bool(data.get("enable_transformers", False)),
        transformers_model=data.get("transformers_model"),
        block_threshold=data.get("block_threshold"),
        approval_threshold=data.get("approval_threshold"),
    )
