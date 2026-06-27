"""Builders for registries and runtimes used across integration tests."""

from __future__ import annotations

from agentguard.core.runtime import AgentGuardRuntime
from agentguard.policies.risk import RiskLevel
from agentguard.providers.storage.memory import MemoryStore
from agentguard.tools.registry import ToolRegistry
from tests._helpers.fakes import FakePlanner


def single_tool_registry(name, handler, *, risk=RiskLevel.LOW, requires_approval=False, roles=("user",), description="desc"):
    registry = ToolRegistry()
    registry.register(name, handler, description, risk, requires_approval, list(roles))
    return registry


def build_runtime(
    registry,
    decision=None,
    *,
    planner=None,
    store=None,
    scanner=None,
    policy=None,
    input_guardrails=None,
    output_guardrails=None,
    max_reasks=1,
):
    return AgentGuardRuntime(
        registry=registry,
        planner=planner or FakePlanner(decision or {"tool_name": None, "tool_args": {}, "answer": ""}),
        store=store or MemoryStore(),
        scanner=scanner,
        policy=policy,
        input_guardrails=input_guardrails,
        output_guardrails=output_guardrails,
        max_reasks=max_reasks,
    )
