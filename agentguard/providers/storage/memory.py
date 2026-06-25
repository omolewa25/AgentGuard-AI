import uuid
from datetime import datetime, UTC


class MemoryStore:
    def __init__(self) -> None:
        self.approvals: dict[str, dict] = {}
        self.audit_logs: list[dict] = []

    def create_approval(self, tool_name: str, tool_args: dict, user_role: str) -> str:
        approval_id = str(uuid.uuid4())
        self.approvals[approval_id] = {
            "id": approval_id,
            "tool_name": tool_name,
            "tool_args": tool_args,
            "user_role": user_role,
            "status": "pending",
            "created_at": datetime.now(UTC).isoformat(),
        }
        return approval_id

    def get_approval(self, approval_id: str) -> dict | None:
        return self.approvals.get(approval_id)

    def update_approval_status(self, approval_id: str, status: str) -> dict | None:
        approval = self.get_approval(approval_id)
        if not approval:
            return None
        approval["status"] = status
        approval["updated_at"] = datetime.now(UTC).isoformat()
        return approval

    def list_approvals(self, status: str | None = None, limit: int | None = 100) -> list[dict]:
        items = sorted(self.approvals.values(), key=lambda a: a["created_at"], reverse=True)
        if status:
            items = [a for a in items if a["status"] == status]
        return items if limit is None else items[:limit]

    def log_event(self, event_type: str, payload: dict) -> None:
        self.audit_logs.append({
            "id": str(uuid.uuid4()),
            "event_type": event_type,
            "payload": payload,
            "created_at": datetime.now(UTC).isoformat(),
        })

    def list_audit_logs(self, limit: int | None = 50) -> list[dict]:
        ordered = list(reversed(self.audit_logs))
        return ordered if limit is None else ordered[:limit]
