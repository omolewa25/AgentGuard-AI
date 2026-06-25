from __future__ import annotations

from agentguard.tools.base import ToolSpec
from agentguard.policies.risk import RiskLevel


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(
        self,
        name: str,
        handler,
        description: str,
        risk_level: RiskLevel | str = RiskLevel.LOW,
        requires_approval: bool = False,
        allowed_roles: list[str] | None = None,
    ) -> None:
        risk = risk_level if isinstance(risk_level, RiskLevel) else RiskLevel(risk_level)
        self._tools[name] = ToolSpec(
            name=name,
            description=description,
            handler=handler,
            risk_level=risk,
            requires_approval=requires_approval,
            allowed_roles=allowed_roles or ["admin"],
        )

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools.keys())
