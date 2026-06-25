from __future__ import annotations

import os

LLM_PROVIDER_ENV_VAR = "AGENTGUARD_LLM_PROVIDER"


def is_litellm(provider: str | None = None) -> bool:
    provider = provider or os.getenv(LLM_PROVIDER_ENV_VAR, "openai")
    return provider.lower() in ("litellm", "lite_llm")


def build_planner():
    """Select the LLM planner via AGENTGUARD_LLM_PROVIDER (openai|litellm).
    Imports are lazy so only the chosen backend's dependency is required."""
    if is_litellm():
        from agentguard.providers.llm.litellm import LiteLLMToolPlanner

        return LiteLLMToolPlanner()

    from agentguard.providers.llm.openai import OpenAIToolPlanner

    return OpenAIToolPlanner()
