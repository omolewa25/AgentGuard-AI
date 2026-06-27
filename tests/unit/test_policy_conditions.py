import pytest

from agentguard.policies.conditions import PolicyConditionError, evaluate_condition

pytestmark = pytest.mark.unit


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
