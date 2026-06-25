import os
from dotenv import load_dotenv
from agentguard.core.runtime import AgentGuardRuntime
from agentguard.policies.config import load_policy
from agentguard.providers.llm.openai import OpenAIToolPlanner
from agentguard.providers.storage.factory import build_store
from agentguard.security.factory import build_scanner
from agentguard.security.scanner import SecurityScanner
from apps.email_agent.registry import build_registry as build_email_registry
from apps.devops_agent.registry import build_registry as build_devops_registry

load_dotenv()

store = build_store()

# Built-in app-specific phrases, layered on top of framework defaults and any
# external config file (AGENTGUARD_SECURITY_CONFIG).
DEMO_INJECTION_PATTERNS = {
    "email": ["forward all emails", "add bcc", "change reply-to"],
    "devops": ["disable approvals", "skip review", "delete production"],
}


def build_demo_scanner(demo: str) -> SecurityScanner:
    return build_scanner(
        extra_patterns=DEMO_INJECTION_PATTERNS.get(demo, []),
        llm_model=os.getenv("OPENAI_MODEL"),
    )


def build_runtime() -> AgentGuardRuntime:
    demo = os.getenv("AGENTGUARD_DEMO", "email")
    registry = build_devops_registry() if demo == "devops" else build_email_registry()
    planner = OpenAIToolPlanner()
    scanner = build_demo_scanner(demo)
    policy = load_policy()
    return AgentGuardRuntime(registry=registry, planner=planner, store=store, scanner=scanner, policy=policy)

runtime = build_runtime()
