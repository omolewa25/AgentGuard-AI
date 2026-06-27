import pytest

from agentguard.providers.storage.base import Store
from agentguard.providers.storage.memory import MemoryStore
from agentguard.providers.storage.sqlite import SQLiteStore

pytestmark = pytest.mark.unit


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
