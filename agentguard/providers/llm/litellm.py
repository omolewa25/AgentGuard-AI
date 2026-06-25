from __future__ import annotations

import json
import os
from typing import Any, Callable

DEFAULT_MODEL = "gpt-4.1-mini"


def resolve_model(model: str | None) -> str:
    return model or os.getenv("LITELLM_MODEL") or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)


def extract_content(response: Any) -> str:
    """Pull the message content out of an OpenAI-style response (object or dict),
    which is the shape LiteLLM returns for every provider."""
    try:
        return response.choices[0].message.content
    except AttributeError:
        return response["choices"][0]["message"]["content"]


def litellm_complete(
    model: str,
    messages: list[dict[str, str]],
    completion_fn: Callable[..., Any] | None = None,
    **kwargs: Any,
) -> str:
    if completion_fn is not None:
        response = completion_fn(model=model, messages=messages, **kwargs)
    else:
        from litellm import completion

        response = completion(model=model, messages=messages, **kwargs)
    return extract_content(response)


class LiteLLMToolPlanner:
    """Provider-agnostic planner via LiteLLM. Works with any LiteLLM-supported
    model (OpenAI, Anthropic, Gemini, Bedrock, Azure, Ollama, ...) using one
    interface. Set the model via `model=` or the LITELLM_MODEL env var, e.g.
    "gpt-4.1-mini", "claude-3-5-sonnet-20240620", "gemini/gemini-1.5-pro",
    "ollama/llama3".
    """

    def __init__(self, model: str | None = None, completion_fn: Callable[..., Any] | None = None, **completion_kwargs: Any) -> None:
        self.model = resolve_model(model)
        self._completion_fn = completion_fn
        self.completion_kwargs = {"temperature": 0, **completion_kwargs}

    def plan(self, system_prompt: str, user_message: str) -> dict:
        content = litellm_complete(
            self.model,
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            completion_fn=self._completion_fn,
            **self.completion_kwargs,
        )
        try:
            return json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return {"tool_name": None, "tool_args": {}, "answer": content if isinstance(content, str) else str(content)}
