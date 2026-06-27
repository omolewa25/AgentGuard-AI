"""Reusable test doubles shared across the suite."""

from __future__ import annotations

from typing import Any


class FakePlanner:
    """Planner that always returns the same canned decision."""

    def __init__(self, decision: dict) -> None:
        self.decision = decision

    def plan(self, system_prompt: str, user_message: str) -> dict:
        return self.decision


class SequencePlanner:
    """Returns a different decision on each call; used to drive the reask loop."""

    def __init__(self, decisions: list[dict]) -> None:
        self.decisions = decisions
        self.calls = 0

    def plan(self, system_prompt: str, user_message: str) -> dict:
        decision = self.decisions[min(self.calls, len(self.decisions) - 1)]
        self.calls += 1
        return decision


# --- Jenkins HTTP doubles --------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: dict | None = None, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}

    def json(self) -> dict:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Minimal stand-in for a requests.Session that records calls."""

    def __init__(self, get_responses: dict | None = None, post_response: FakeResponse | None = None) -> None:
        self.get_responses = get_responses or {}
        self.post_response = post_response or FakeResponse(201, headers={"Location": "http://j/queue/item/42/"})
        self.calls: list[tuple[str, str, dict]] = []

    def get(self, url, timeout=None, **kwargs):
        self.calls.append(("GET", url, kwargs))
        for key, resp in self.get_responses.items():
            if key in url:
                return resp
        return FakeResponse(404)

    def post(self, url, timeout=None, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.post_response


# --- LiteLLM response double -----------------------------------------------------

class _Msg:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = _Msg(content)


class LiteLLMResponse:
    """OpenAI-style response object that LiteLLM returns."""

    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


def litellm_completion_fn(content: str):
    """Builds a `completion_fn` that always returns `content`."""

    def completion(model, messages, **kwargs) -> LiteLLMResponse:
        return LiteLLMResponse(content)

    return completion
