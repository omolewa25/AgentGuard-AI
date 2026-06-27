import json

import pytest

from agentguard.policies.risk import RiskLevel
from agentguard.providers.llm.litellm import LiteLLMToolPlanner
from tests._helpers.factories import build_runtime, single_tool_registry
from tests._helpers.fakes import litellm_completion_fn

pytestmark = pytest.mark.integration


def test_planner_drives_runtime_end_to_end():
    registry = single_tool_registry("search", lambda **k: "3 results", roles=("user",))
    planner = LiteLLMToolPlanner(completion_fn=litellm_completion_fn(json.dumps({"tool_name": "search", "tool_args": {}, "answer": ""})))
    runtime = build_runtime(registry, planner=planner)
    assert runtime.invoke("search docs", user_role="user")["answer"] == "3 results"
