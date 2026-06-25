from typing import Literal
from pydantic import BaseModel


class AgentRequest(BaseModel):
    message: str
    user_role: str = "user"


class AgentResponse(BaseModel):
    answer: str
    requires_approval: bool = False
    approval_id: str | None = None
