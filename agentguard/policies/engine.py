from __future__ import annotations

from typing import Any

from agentguard.policies.conditions import PolicyConditionError, evaluate_condition
from agentguard.policies.config import PolicyDocument, ToolPolicy
from agentguard.policies.risk import RiskLevel
from agentguard.tools.registry import ToolRegistry


class PolicyEngine:
    def __init__(self, registry: ToolRegistry, policy: PolicyDocument | None = None) -> None:
        self.registry = registry
        self.policy = policy or PolicyDocument()

    def evaluate(self, tool_name: str, user_role: str, context: dict[str, Any] | None = None) -> dict:
        tool = self.registry.get(tool_name)
        if not tool:
            return {"allowed": False, "requires_approval": False, "reason": "Tool is not registered."}

        tool_policy = self.policy.for_tool(tool_name)
        risk_level = self._resolve_risk(tool, tool_policy)
        allowed_roles = self._resolve_roles(tool, tool_policy)
        requires_approval = self._resolve_requires_approval(tool, tool_policy)

        if risk_level == RiskLevel.BLOCKED:
            return {"allowed": False, "requires_approval": False, "reason": "Tool is blocked."}
        if user_role not in allowed_roles:
            return {"allowed": False, "requires_approval": False, "reason": f"Role '{user_role}' cannot use '{tool_name}'."}

        approval_reason = "Human approval required."
        if tool_policy:
            eval_context = self._build_context(tool_name, user_role, risk_level, context)
            for condition in tool_policy.conditions:
                if not self._matches(condition.expr, eval_context):
                    continue
                if condition.deny:
                    return {"allowed": False, "requires_approval": False, "reason": condition.reason or f"Denied by policy for '{tool_name}'."}
                if condition.require_approval:
                    requires_approval = True
                    if condition.reason:
                        approval_reason = condition.reason

        if requires_approval or risk_level == RiskLevel.HIGH:
            return {"allowed": False, "requires_approval": True, "reason": approval_reason}
        return {"allowed": True, "requires_approval": False, "reason": "Tool call approved."}

    @staticmethod
    def _resolve_risk(tool, tool_policy: ToolPolicy | None) -> RiskLevel:
        if tool_policy and tool_policy.risk_level is not None:
            return tool_policy.risk_level
        return tool.risk_level

    @staticmethod
    def _resolve_roles(tool, tool_policy: ToolPolicy | None) -> list[str]:
        if tool_policy and tool_policy.allowed_roles is not None:
            return tool_policy.allowed_roles
        return tool.allowed_roles

    @staticmethod
    def _resolve_requires_approval(tool, tool_policy: ToolPolicy | None) -> bool:
        if tool_policy and tool_policy.requires_approval is not None:
            return tool_policy.requires_approval
        return tool.requires_approval

    @staticmethod
    def _build_context(tool_name: str, user_role: str, risk_level: RiskLevel, context: dict[str, Any] | None) -> dict[str, Any]:
        merged: dict[str, Any] = dict(context or {})
        # Reserved keys always reflect the request, overriding any tool args.
        merged["tool"] = tool_name
        merged["user_role"] = user_role
        merged["risk"] = risk_level.value
        return merged

    @staticmethod
    def _matches(expr: str, context: dict[str, Any]) -> bool:
        try:
            return evaluate_condition(expr, context)
        except PolicyConditionError:
            # A malformed condition should fail closed (treated as not matching)
            # rather than crash the request or silently allow it.
            return False
