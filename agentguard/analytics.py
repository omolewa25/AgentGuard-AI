from __future__ import annotations

import csv
import io
from collections import Counter
from typing import Any

from agentguard.providers.storage.base import Store

# Audit event types that represent a security control firing.
_SECURITY_EVENTS = {
    "prompt_injection_blocked": "blocked_injections",
    "prompt_injection_suspected": "suspected_injections",
    "egress_blocked": "egress_blocked",
    "output_secrets_redacted": "secrets_redacted",
    "tool_output_flagged": "tool_outputs_flagged",
}


def compute_stats(store: Store) -> dict[str, Any]:
    logs = store.list_audit_logs(limit=None)
    approvals = store.list_approvals(limit=None)

    by_type: Counter[str] = Counter(log["event_type"] for log in logs)

    security = {label: by_type.get(event, 0) for event, label in _SECURITY_EVENTS.items()}

    policy_denied = sum(
        1
        for log in logs
        if log["event_type"] == "policy_decision"
        and not log["payload"].get("decision", {}).get("allowed", True)
        and not log["payload"].get("decision", {}).get("requires_approval", False)
    )

    approval_counts = Counter(a["status"] for a in approvals)

    return {
        "totals": {
            "events": len(logs),
            "tool_executions": by_type.get("tool_executed", 0),
            "policy_decisions": by_type.get("policy_decision", 0),
            "policy_denied": policy_denied,
            **security,
        },
        "approvals": {
            "pending": approval_counts.get("pending", 0),
            "approved": approval_counts.get("approved", 0),
            "rejected": approval_counts.get("rejected", 0),
            "total": len(approvals),
        },
        "events_by_type": dict(by_type),
        "recent_events": logs[:20],
    }


def compliance_rows(store: Store) -> list[dict[str, Any]]:
    """One row per human-in-the-loop approval: the core audit evidence that
    high-risk actions were reviewed, with outcome and reviewer role."""
    rows: list[dict[str, Any]] = []
    for approval in store.list_approvals(limit=None):
        rows.append(
            {
                "approval_id": approval["id"],
                "tool": approval["tool_name"],
                "requested_by_role": approval["user_role"],
                "status": approval["status"],
                "requested_at": approval.get("created_at", ""),
                "decided_at": approval.get("updated_at", ""),
                "arguments": approval.get("tool_args", {}),
            }
        )
    return rows


def compliance_csv(store: Store) -> str:
    rows = compliance_rows(store)
    fieldnames = ["approval_id", "tool", "requested_by_role", "status", "requested_at", "decided_at", "arguments"]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        serialized = dict(row)
        serialized["arguments"] = str(row["arguments"])
        writer.writerow(serialized)
    return buffer.getvalue()
