from typing import Any, TypedDict


class AgentState(TypedDict, total=False):
    message: str
    user_role: str
    answer: str
    tool_name: str | None
    tool_args: dict[str, Any]
    requires_approval: bool
    approval_id: str | None
    blocked: bool
    force_approval: bool
    reason: str | None
