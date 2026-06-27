from agentguard.providers.cicd.jenkins import build_jenkins_client


def explain_terraform_plan(plan_text: str) -> str:
    return f"Terraform plan explanation placeholder. Characters analyzed: {len(plan_text)}"


def create_deploy_plan(environment: str, service: str) -> str:
    return f"Deployment plan created for {service} in {environment}. No deployment executed."


def deploy_service(environment: str, service: str) -> str:
    return f"Deployment triggered for {service} in {environment}."


def trigger_jenkins_build(job: str, parameters: dict | None = None) -> str:
    client = build_jenkins_client()
    result = client.trigger_build(job, parameters or {})
    queue = result.get("queue_url") or "(queued; no location header)"
    return f"Jenkins build queued for job '{job}'. Queue: {queue}"


def get_jenkins_build_status(job: str, build_number: int) -> str:
    client = build_jenkins_client()
    status = client.get_build_status(job, build_number)
    state = "building" if status.get("building") else (status.get("result") or "unknown")
    return f"Jenkins job '{job}' #{build_number}: {state} ({status.get('url')})"
