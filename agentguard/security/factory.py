from __future__ import annotations

import os

from agentguard.providers.llm.factory import is_litellm
from agentguard.security.config import SecurityConfig, load_security_config
from agentguard.security.scanner import (
    CompositeScanner,
    HeuristicScanner,
    LLMJudgeScanner,
    SecurityScanner,
    TransformersInjectionScanner,
)

DEFAULT_TRANSFORMERS_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


def build_scanner(
    config: SecurityConfig | None = None,
    extra_patterns: list[str] | None = None,
    *,
    llm_model: str | None = None,
) -> SecurityScanner:
    """Assemble the detection cascade from config + env flags.

    Order is cheapest-first so expensive layers only run when earlier ones are
    not confident (CompositeScanner short-circuits at the block threshold):
    heuristic -> local transformers classifier (free) -> LLM judge (paid).
    """
    config = config or load_security_config()
    patterns = list(extra_patterns or []) + config.injection_patterns

    scanners: list[SecurityScanner] = [
        HeuristicScanner(
            injection_patterns=patterns or None,
            injection_regex_patterns=config.injection_regex or None,
        )
    ]

    if config.enable_transformers or os.getenv("AGENTGUARD_TRANSFORMERS") == "1":
        scanners.append(
            TransformersInjectionScanner(
                model_name=config.transformers_model or DEFAULT_TRANSFORMERS_MODEL
            )
        )

    if config.enable_llm_judge or os.getenv("AGENTGUARD_LLM_JUDGE") == "1":
        provider = "litellm" if is_litellm() else "openai"
        scanners.append(LLMJudgeScanner(model=llm_model or os.getenv("OPENAI_MODEL"), provider=provider))

    if len(scanners) == 1:
        return scanners[0]
    return CompositeScanner(scanners)
