from collections.abc import Callable
from pydantic import BaseModel, Field
from agentguard.policies.risk import RiskLevel


class ToolSpec(BaseModel):
    name: str
    description: str
    handler: Callable
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    allowed_roles: list[str] = Field(default_factory=lambda: ["admin"])

    class Config:
        arbitrary_types_allowed = True
