from agentguard.policies.risk import RiskLevel
from agentguard.tools.registry import ToolRegistry
from apps.devops_agent.tools import explain_terraform_plan, create_deploy_plan, deploy_service


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register("explain_terraform_plan", explain_terraform_plan, "Explain a Terraform plan. Read-only.", RiskLevel.LOW, False, ["developer", "platform_engineer", "admin"])
    registry.register("create_deploy_plan", create_deploy_plan, "Create a deployment plan without executing it.", RiskLevel.MEDIUM, False, ["platform_engineer", "admin"])
    registry.register("deploy_service", deploy_service, "Deploy a service to an environment.", RiskLevel.HIGH, True, ["platform_engineer", "admin"])
    return registry
