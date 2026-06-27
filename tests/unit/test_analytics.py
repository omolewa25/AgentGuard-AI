import pytest

from agentguard.analytics import compliance_csv, compliance_rows, compute_stats
from agentguard.providers.storage.memory import MemoryStore

pytestmark = pytest.mark.unit


def _seed(store):
    store.log_event("prompt_injection_blocked", {"matches": ["jailbreak"]})
    store.log_event("egress_blocked", {"tool_name": "send_email"})
    store.log_event("output_secrets_redacted", {"matches": ["openai_api_key"]})
    store.log_event("policy_decision", {"tool_name": "x", "decision": {"allowed": False, "requires_approval": False}})
    store.log_event("tool_executed", {"tool_name": "search"})
    a1 = store.create_approval("deploy_service", {"env": "production"}, "platform_engineer")
    a2 = store.create_approval("send_email", {"to": "x@y.com"}, "operator")
    store.update_approval_status(a1, "approved")
    store.update_approval_status(a2, "rejected")


def test_compute_stats():
    store = MemoryStore()
    _seed(store)
    stats = compute_stats(store)
    assert stats["totals"]["blocked_injections"] == 1
    assert stats["totals"]["egress_blocked"] == 1
    assert stats["totals"]["secrets_redacted"] == 1
    assert stats["totals"]["policy_denied"] == 1
    assert stats["totals"]["tool_executions"] == 1
    assert stats["approvals"] == {"pending": 0, "approved": 1, "rejected": 1, "total": 2}


def test_compliance_rows_and_csv():
    store = MemoryStore()
    _seed(store)
    rows = compliance_rows(store)
    assert {r["status"] for r in rows} == {"approved", "rejected"}
    csv_text = compliance_csv(store)
    assert "approval_id,tool,requested_by_role,status" in csv_text
    assert "deploy_service" in csv_text
