import pytest

from agentguard.providers.storage.memory import MemoryStore
from apps.devops_agent import tools as devops_tools
from apps.devops_agent.registry import build_registry
from tests._helpers.factories import build_runtime

pytestmark = pytest.mark.integration


def _devops_runtime(decision, store=None):
    return build_runtime(build_registry(), decision, store=store or MemoryStore())


def test_trigger_requires_approval_and_does_not_execute(store):
    runtime = _devops_runtime({"tool_name": "trigger_jenkins_build", "tool_args": {"job": "deploy-api", "parameters": {"ENV": "staging"}}, "answer": ""}, store)
    result = runtime.invoke("trigger the deploy job", user_role="platform_engineer")
    assert result["requires_approval"] is True
    assert result["approval_id"] is not None
    assert not any(e["event_type"] == "tool_executed" for e in store.audit_logs)


def test_secret_in_build_parameters_blocked_by_egress(store, secret):
    runtime = _devops_runtime({"tool_name": "trigger_jenkins_build", "tool_args": {"job": "deploy-api", "parameters": {"TOKEN": secret}}, "answer": ""}, store)
    result = runtime.invoke("trigger with my token", user_role="platform_engineer")
    assert result["answer"].startswith("Tool call blocked")
    assert any(e["event_type"] == "egress_blocked" for e in store.audit_logs)


def test_low_risk_status_tool_executes(monkeypatch):
    class FakeClient:
        def get_build_status(self, job, build_number):
            return {"job": job, "build_number": build_number, "building": False, "result": "SUCCESS", "url": "http://j/x"}

    monkeypatch.setattr(devops_tools, "build_jenkins_client", lambda: FakeClient())
    runtime = _devops_runtime({"tool_name": "get_jenkins_build_status", "tool_args": {"job": "api", "build_number": 7}, "answer": ""})
    result = runtime.invoke("what's the build status", user_role="developer")
    assert result["requires_approval"] is not True
    assert "SUCCESS" in result["answer"]


def test_approval_then_trigger_executes(monkeypatch, store):
    triggered = {}

    class FakeClient:
        def trigger_build(self, job, parameters=None):
            triggered["job"] = job
            triggered["parameters"] = parameters
            return {"job": job, "status": "queued", "queue_url": "http://j/queue/item/9/"}

    monkeypatch.setattr(devops_tools, "build_jenkins_client", lambda: FakeClient())
    runtime = _devops_runtime({"tool_name": "trigger_jenkins_build", "tool_args": {"job": "deploy-api", "parameters": {"ENV": "prod"}}, "answer": ""}, store)
    result = runtime.invoke("trigger it", user_role="admin")
    approved = runtime.approve(result["approval_id"])
    assert approved["status"] == "approved"
    assert triggered["job"] == "deploy-api"
    assert "queued" in approved["result"]
