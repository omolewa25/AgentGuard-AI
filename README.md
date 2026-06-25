# AgentGuard AI

Reusable secure AI agent governance framework for production-grade LLM applications.

AgentGuard AI gives you a generic runtime for building governed AI agents with:

- Tool registry
- Risk-based policy engine
- Human-in-the-loop approvals
- Prompt injection detection
- Audit logging
- Pluggable LLM planners
- Pluggable storage providers
- Pluggable notification/action providers
- Demo apps for email automation and DevOps workflows

## Architecture

```text
agentguard/
  core/              # Runtime, graph, state, prompts
  tools/             # Generic tool registry
  policies/          # Risk levels and policy engine
  security/          # Prompt injection detection
  providers/         # LLM, storage, notification providers
apps/
  email_agent/       # Email workflow demo
  devops_agent/      # DevOps workflow demo
backend/
  app/               # FastAPI wrapper around the generic runtime
```

## Quick start

```bash
cp .env.example .env
pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Choose a demo

In `.env`:

```env
AGENTGUARD_DEMO=email
```

or:

```env
AGENTGUARD_DEMO=devops
```

## Example: email agent

Request:

```json
{
  "message": "Send an email to test@example.com saying hello from AgentGuard AI",
  "user_role": "operator"
}
```

Expected behavior:

```text
The agent requests send_email.
Policy engine marks it high risk.
Runtime creates an approval request.
Email is not sent until approval.
```

Approve:

```text
POST /api/approvals/{approval_id}/approve
```

## Example: DevOps agent

Set:

```env
AGENTGUARD_DEMO=devops
```

Request:

```json
{
  "message": "Deploy billing-api to staging",
  "user_role": "platform_engineer"
}
```

Expected behavior:

```text
The agent requests deploy_service.
Policy engine marks it high risk.
Runtime pauses for approval.
```

## Register your own tools

```python
from agentguard.policies.risk import RiskLevel
from agentguard.tools.registry import ToolRegistry

registry = ToolRegistry()

registry.register(
    name="create_ticket",
    handler=create_ticket,
    description="Create a Jira ticket.",
    risk_level=RiskLevel.MEDIUM,
    requires_approval=False,
    allowed_roles=["support_agent", "admin"],
)

registry.register(
    name="refund_customer",
    handler=refund_customer,
    description="Issue a customer refund.",
    risk_level=RiskLevel.HIGH,
    requires_approval=True,
    allowed_roles=["manager", "admin"],
)
```

## LinkedIn description

Built AgentGuard AI, a reusable secure AI agent governance framework for production-grade LLM applications. The platform supports configurable tool governance, human-in-the-loop approvals, audit logging, role-based access control, prompt-injection detection, and pluggable providers for LLMs, storage, and external actions.
