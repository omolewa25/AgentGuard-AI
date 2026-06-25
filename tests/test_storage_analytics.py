import pytest

from agentguard.analytics import compliance_csv, compliance_rows, compute_stats
from agentguard.providers.storage.base import Store
from agentguard.providers.storage.memory import MemoryStore
from agentguard.providers.storage.sqlite import SQLiteStore


def _stores(tmp_path):
    return [MemoryStore(), SQLiteStore(str(tmp_path / "t.db"))]


def test_both_stores_satisfy_protocol(tmp_path):
    for store in _stores(tmp_path):
        assert isinstance(store, Store)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_approval_lifecycle(kind, tmp_path):
    store = MemoryStore() if kind == "memory" else SQLiteStore(str(tmp_path / "a.db"))
    aid = store.create_approval("deploy_service", {"env": "production"}, "platform_engineer")

    fetched = store.get_approval(aid)
    assert fetched["status"] == "pending"
    assert fetched["tool_args"] == {"env": "production"}

    store.update_approval_status(aid, "approved")
    assert store.get_approval(aid)["status"] == "approved"
    assert store.get_approval(aid)["updated_at"]

    assert store.update_approval_status("missing", "approved") is None
    assert len(store.list_approvals(status="approved")) == 1
    assert store.list_approvals(status="pending") == []


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_audit_log_ordering_and_limit(kind, tmp_path):
    store = MemoryStore() if kind == "memory" else SQLiteStore(str(tmp_path / "b.db"))
    for i in range(5):
        store.log_event("policy_decision", {"n": i})
    logs = store.list_audit_logs(limit=3)
    assert len(logs) == 3
    assert logs[0]["payload"]["n"] == 4  # newest first
    assert len(store.list_audit_logs(limit=None)) == 5


def test_sqlite_persists_across_reconnect(tmp_path):
    db = str(tmp_path / "persist.db")
    store = SQLiteStore(db)
    aid = store.create_approval("send_email", {"to": "a@b.com"}, "operator")
    store.log_event("tool_executed", {"tool_name": "send_email"})

    reopened = SQLiteStore(db)
    assert reopened.get_approval(aid)["tool_name"] == "send_email"
    assert len(reopened.list_audit_logs(limit=None)) == 1


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
