import json

import pytest

from agentguard.policies.conditions import PolicyConditionError, evaluate_condition
from agentguard.policies.config import PolicyDocument, ToolPolicy, PolicyCondition, load_policy
from agentguard.policies.engine import PolicyEngine
from agentguard.policies.risk import RiskLevel
from agentguard.tools.registry import ToolRegistry


def noop(**kwargs):
    return "ok"


def _registry():
    registry = ToolRegistry()
    registry.register("deploy_service", noop, "deploy", RiskLevel.HIGH, True, ["platform_engineer", "admin"])
    registry.register("search", noop, "search", RiskLevel.LOW, False, ["user", "admin"])
    return registry


# --- safe condition evaluator ----------------------------------------------------

def test_condition_basic_equality():
    assert evaluate_condition("env == 'production'", {"env": "production"}) is True
    assert evaluate_condition("env == 'production'", {"env": "staging"}) is False


def test_condition_boolean_and_membership():
    assert evaluate_condition("env == 'prod' and user_role != 'admin'", {"env": "prod", "user_role": "dev"}) is True
    assert evaluate_condition("region in ['us', 'eu']", {"region": "eu"}) is True


def test_condition_missing_name_is_none():
    assert evaluate_condition("external == true", {}) is False


def test_condition_rejects_function_calls():
    with pytest.raises(PolicyConditionError):
        evaluate_condition("__import__('os').system('echo hi')", {})


def test_condition_rejects_attribute_access():
    with pytest.raises(PolicyConditionError):
        evaluate_condition("env.upper() == 'PROD'", {"env": "prod"})


def test_condition_rejects_arithmetic():
    with pytest.raises(PolicyConditionError):
        evaluate_condition("1 + 1 == 2", {})


# --- config overrides ------------------------------------------------------------

def test_backward_compatible_without_policy():
    engine = PolicyEngine(_registry())
    assert engine.evaluate("deploy_service", "platform_engineer")["requires_approval"] is True
    assert engine.evaluate("search", "user")["allowed"] is True
    assert engine.evaluate("search", "stranger")["allowed"] is False


def test_policy_overrides_allowed_roles():
    policy = PolicyDocument(tools={"search": ToolPolicy(allowed_roles=["admin"])})
    engine = PolicyEngine(_registry(), policy)
    assert engine.evaluate("search", "user")["allowed"] is False
    assert engine.evaluate("search", "admin")["allowed"] is True


def test_policy_can_lower_approval_requirement():
    policy = PolicyDocument(tools={"deploy_service": ToolPolicy(risk_level=RiskLevel.MEDIUM, requires_approval=False)})
    engine = PolicyEngine(_registry(), policy)
    assert engine.evaluate("deploy_service", "admin")["allowed"] is True


# --- conditions ------------------------------------------------------------------

def test_condition_requires_approval():
    policy = PolicyDocument(tools={"search": ToolPolicy(
        conditions=[PolicyCondition(expr="env == 'production'", require_approval=True, reason="prod needs sign-off")]
    )})
    engine = PolicyEngine(_registry(), policy)
    allowed = engine.evaluate("search", "user", {"env": "staging"})
    escalated = engine.evaluate("search", "user", {"env": "production"})
    assert allowed["allowed"] is True
    assert escalated["requires_approval"] is True
    assert escalated["reason"] == "prod needs sign-off"


def test_condition_denies():
    policy = PolicyDocument(tools={"search": ToolPolicy(
        conditions=[PolicyCondition(expr="user_role != 'admin'", deny=True, reason="admins only")]
    )})
    engine = PolicyEngine(_registry(), policy)
    assert engine.evaluate("search", "user")["allowed"] is False
    assert engine.evaluate("search", "admin")["allowed"] is True


def test_malformed_condition_fails_closed():
    policy = PolicyDocument(tools={"search": ToolPolicy(
        conditions=[PolicyCondition(expr="this is not valid !!", require_approval=True)]
    )})
    engine = PolicyEngine(_registry(), policy)
    # Bad condition must not crash and must not match (no spurious approval).
    assert engine.evaluate("search", "user")["allowed"] is True


# --- loader ----------------------------------------------------------------------

def test_load_policy_from_file(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "tools": {
            "deploy_service": {
                "allowed_roles": ["admin"],
                "conditions": [
                    {"if": "env == 'production' and user_role != 'admin'", "then": "deny", "reason": "no"},
                    {"if": "env == 'production'", "then": "require_approval", "reason": "prod"}
                ]
            }
        }
    }))
    policy = load_policy(str(path))
    engine = PolicyEngine(_registry(), policy)

    assert engine.evaluate("deploy_service", "platform_engineer")["allowed"] is False  # role override
    assert engine.evaluate("deploy_service", "admin", {"env": "production"})["requires_approval"] is True


def test_load_policy_missing_file_is_empty():
    assert load_policy("/no/such/policy.json").tools == {}
