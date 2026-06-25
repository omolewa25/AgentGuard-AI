import json
import os
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage


class OpenAIToolPlanner:
    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    def plan(self, system_prompt: str, user_message: str) -> dict:
        llm = ChatOpenAI(model=self.model, temperature=0)
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_message),
        ])
        try:
            return json.loads(str(response.content))
        except json.JSONDecodeError:
            return {"tool_name": None, "tool_args": {}, "answer": str(response.content)}
