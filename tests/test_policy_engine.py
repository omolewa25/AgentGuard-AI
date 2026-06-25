from agentguard.policies.engine import PolicyEngine
from agentguard.policies.risk import RiskLevel
from agentguard.tools.registry import ToolRegistry


def noop():
    return "ok"


def test_high_risk_requires_approval():
    registry = ToolRegistry()
    registry.register("dangerous", noop, "Dangerous action", RiskLevel.HIGH, True, ["admin"])
    decision = PolicyEngine(registry).evaluate("dangerous", "admin")
    assert decision["requires_approval"] is True


def test_role_blocked():
    registry = ToolRegistry()
    registry.register("safe", noop, "Safe action", RiskLevel.LOW, False, ["admin"])
    decision = PolicyEngine(registry).evaluate("safe", "user")
    assert decision["allowed"] is False
