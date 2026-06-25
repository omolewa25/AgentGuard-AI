from agentguard.policies.risk import RiskLevel
from agentguard.tools.registry import ToolRegistry
from apps.email_agent.tools import search_docs, draft_email, send_email


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register("search_docs", search_docs, "Read-only document search.", RiskLevel.LOW, False, ["user", "operator", "admin"])
    registry.register("draft_email", draft_email, "Create an email draft without sending.", RiskLevel.MEDIUM, False, ["operator", "admin"])
    registry.register("send_email", send_email, "Send an email through SMTP.", RiskLevel.HIGH, True, ["operator", "admin"])
    return registry
