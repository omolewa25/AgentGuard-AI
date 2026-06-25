from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from agentguard.policies.risk import RiskLevel

POLICY_ENV_VAR = "AGENTGUARD_POLICY_CONFIG"


@dataclass
class PolicyCondition:
    expr: str
    require_approval: bool = False
    deny: bool = False
    reason: str | None = None


@dataclass
class ToolPolicy:
    risk_level: RiskLevel | None = None
    requires_approval: bool | None = None
    allowed_roles: list[str] | None = None
    conditions: list[PolicyCondition] = field(default_factory=list)


@dataclass
class PolicyDocument:
    tools: dict[str, ToolPolicy] = field(default_factory=dict)

    def for_tool(self, tool_name: str) -> ToolPolicy | None:
        return self.tools.get(tool_name)


def _parse(path: str, raw: str) -> dict:
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to load YAML policy config.") from exc
        return yaml.safe_load(raw) or {}
    return json.loads(raw)


def _build_condition(data: dict) -> PolicyCondition:
    then = str(data.get("then", "")).lower()
    return PolicyCondition(
        expr=data["if"],
        require_approval=bool(data.get("require_approval", then in {"require_approval", "approve"})),
        deny=bool(data.get("deny", then == "deny")),
        reason=data.get("reason"),
    )


def _build_tool_policy(data: dict) -> ToolPolicy:
    risk = data.get("risk") or data.get("risk_level")
    return ToolPolicy(
        risk_level=RiskLevel(risk) if risk else None,
        requires_approval=data.get("requires_approval"),
        allowed_roles=data.get("allowed_roles"),
        conditions=[_build_condition(c) for c in data.get("conditions", [])],
    )


def load_policy(path: str | None = None) -> PolicyDocument:
    """Load a policy document from an explicit path or AGENTGUARD_POLICY_CONFIG.
    Missing/empty config yields an empty document (engine then falls back to the
    risk/role metadata declared on each tool in the registry)."""
    path = path or os.getenv(POLICY_ENV_VAR)
    if not path or not os.path.exists(path):
        return PolicyDocument()

    with open(path, encoding="utf-8") as handle:
        data = _parse(path, handle.read()) or {}

    tools = {name: _build_tool_policy(spec) for name, spec in data.get("tools", {}).items()}
    return PolicyDocument(tools=tools)
