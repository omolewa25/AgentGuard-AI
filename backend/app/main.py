from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response

from agentguard.analytics import compliance_csv, compliance_rows, compute_stats
from backend.app.schemas import AgentRequest, AgentResponse
from backend.app.runtime_factory import runtime, store

app = FastAPI(title="AgentGuard AI", version="1.0.0")

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/")
def health_check():
    return {"status": "ok", "service": "agentguard-ai"}


@app.post("/api/agent", response_model=AgentResponse)
def run_agent(request: AgentRequest):
    result = runtime.invoke(message=request.message, user_role=request.user_role)
    return AgentResponse(
        answer=result.get("answer", ""),
        requires_approval=result.get("requires_approval", False),
        approval_id=result.get("approval_id"),
    )


@app.post("/api/approvals/{approval_id}/approve")
def approve_action(approval_id: str):
    try:
        return runtime.approve(approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/approvals/{approval_id}/reject")
def reject_action(approval_id: str):
    try:
        return runtime.reject(approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/approvals")
def list_approvals(status: str | None = None, limit: int = 100):
    return store.list_approvals(status=status, limit=limit)


@app.get("/api/audit-logs")
def list_audit_logs(limit: int = 50):
    return store.list_audit_logs(limit=limit)


@app.get("/api/tools")
def list_tools():
    return [tool.model_dump(exclude={"handler"}) for tool in runtime.registry.list()]


@app.get("/api/stats")
def stats():
    return compute_stats(store)


@app.get("/api/compliance/export")
def export_compliance(format: str = "json"):
    if format == "csv":
        return Response(
            content=compliance_csv(store),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=agentguard-compliance.csv"},
        )
    return compliance_rows(store)


@app.get("/dashboard")
def dashboard():
    return FileResponse(STATIC_DIR / "dashboard.html")
