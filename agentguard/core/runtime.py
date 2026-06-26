from typing import Literal
from langgraph.graph import StateGraph, START, END

from agentguard.core.state import AgentState
from agentguard.core.prompts import build_system_prompt, spotlight_untrusted
from agentguard.guardrails.base import OnFail
from agentguard.guardrails.pipeline import GuardrailPipeline
from agentguard.policies.config import PolicyDocument
from agentguard.policies.engine import PolicyEngine
from agentguard.security.scanner import (
    APPROVAL_THRESHOLD,
    BLOCK_THRESHOLD,
    HeuristicScanner,
    SecurityScanner,
)
from agentguard.tools.registry import ToolRegistry


class AgentGuardRuntime:
    def __init__(
        self,
        registry: ToolRegistry,
        planner,
        store,
        scanner: SecurityScanner | None = None,
        policy: PolicyDocument | None = None,
        input_guardrails: GuardrailPipeline | None = None,
        output_guardrails: GuardrailPipeline | None = None,
        max_reasks: int = 1,
    ) -> None:
        self.registry = registry
        self.planner = planner
        self.store = store
        self.scanner = scanner or HeuristicScanner()
        self.policy_engine = PolicyEngine(registry, policy)
        self.input_guardrails = input_guardrails or GuardrailPipeline()
        self.output_guardrails = output_guardrails or GuardrailPipeline()
        self.max_reasks = max_reasks
        self.graph = self._build_graph()

    def _scan_input(self, state: AgentState) -> AgentState:
        result = self.scanner.scan_input(state["message"])
        if result.severity >= BLOCK_THRESHOLD:
            self.store.log_event("prompt_injection_blocked", {"message": state["message"], "severity": result.severity, "matches": result.matches, "reasons": result.reasons})
            return {**state, "blocked": True, "force_approval": False, "answer": "Suspicious instruction detected. I can help safely, but I will not follow hidden or unsafe instructions.", "requires_approval": False, "approval_id": None, "reason": "prompt_injection_blocked"}
        if result.severity >= APPROVAL_THRESHOLD:
            self.store.log_event("prompt_injection_suspected", {"message": state["message"], "severity": result.severity, "matches": result.matches, "reasons": result.reasons})
            return {**state, "blocked": False, "force_approval": True}
        return {**state, "blocked": False, "force_approval": False}

    def _guardrail_input(self, state: AgentState) -> AgentState:
        if not self.input_guardrails:
            return state
        result = self.input_guardrails.run(state["message"], {"user_role": state.get("user_role")})
        if not result.failures:
            return state
        self.store.log_event("guardrail_input", {"failures": [f.guardrail for f in result.failures], "action": result.action.value if result.action else None})
        if result.action in (OnFail.BLOCK, OnFail.REFRAIN, OnFail.REASK):
            self.store.log_event("guardrail_blocked", {"stage": "input", "failures": [f.guardrail for f in result.failures]})
            return {**state, "blocked": True, "answer": "I can't help with that request."}
        if result.action == OnFail.REQUIRE_APPROVAL:
            return {**state, "message": result.text, "force_approval": True}
        return {**state, "message": result.text}

    def _agent_decision(self, state: AgentState) -> AgentState:
        system_prompt = build_system_prompt(self.registry.list())
        user_message = state["message"]
        feedback = state.get("guardrail_feedback")
        updates: dict = {}
        if feedback:
            user_message = (
                f"{user_message}\n\n[Revision required] Your previous response was rejected by a "
                f"guardrail: {feedback}. Produce a corrected response."
            )
            updates["reask_count"] = state.get("reask_count", 0) + 1
            updates["guardrail_feedback"] = None
        decision = self.planner.plan(system_prompt=system_prompt, user_message=user_message)
        return {**state, **updates, "tool_name": decision.get("tool_name"), "tool_args": decision.get("tool_args", {}), "answer": decision.get("answer", "")}

    def _policy_guard(self, state: AgentState) -> AgentState:
        tool_name = state.get("tool_name")
        if not tool_name:
            return {**state, "requires_approval": False, "approval_id": None}

        egress = self.scanner.scan_tool_input(state.get("tool_args", {}))
        if egress.detected:
            self.store.log_event("egress_blocked", {"tool_name": tool_name, "matches": egress.matches, "reasons": egress.reasons})
            return {**state, "requires_approval": False, "approval_id": None, "answer": "Tool call blocked: outbound secret or credential detected in tool arguments."}

        decision = self.policy_engine.evaluate(tool_name=tool_name, user_role=state["user_role"], context=state.get("tool_args", {}))
        self.store.log_event("policy_decision", {"tool_name": tool_name, "tool_args": state.get("tool_args", {}), "decision": decision, "force_approval": state.get("force_approval", False)})

        needs_approval = decision["requires_approval"] or (state.get("force_approval") and decision["allowed"])
        if needs_approval:
            approval_id = self.store.create_approval(tool_name=tool_name, tool_args=state.get("tool_args", {}), user_role=state["user_role"])
            reason = decision["reason"] if decision["requires_approval"] else "Input looked suspicious, so human approval is required."
            return {**state, "requires_approval": True, "approval_id": approval_id, "answer": f"The agent wants to use `{tool_name}`. {reason}"}
        if not decision["allowed"]:
            return {**state, "requires_approval": False, "approval_id": None, "answer": f"Tool call blocked: {decision['reason']}"}
        return {**state, "requires_approval": False, "approval_id": None}

    def _execute_tool(self, state: AgentState) -> AgentState:
        tool_name = state.get("tool_name")
        if not tool_name:
            return state
        tool = self.registry.get(tool_name)
        if not tool:
            return {**state, "answer": f"Unknown tool: {tool_name}"}
        result = tool.handler(**state.get("tool_args", {}))
        output = str(result)
        scan = self.scanner.scan_tool_output(output)
        if scan.detected:
            self.store.log_event("tool_output_flagged", {"tool_name": tool_name, "severity": scan.severity, "matches": scan.matches, "reasons": scan.reasons})
            sanitized = scan.sanitized_text if scan.sanitized_text is not None else output
            if any("injection" in reason for reason in scan.reasons):
                output = "[Quarantined: the tool output contained instructions, which were ignored]\n" + spotlight_untrusted(sanitized)
            else:
                output = sanitized
        self.store.log_event("tool_executed", {"tool_name": tool_name, "tool_args": state.get("tool_args", {}), "result": output})
        return {**state, "answer": output, "sources": [output]}

    def _guardrail_output(self, state: AgentState) -> AgentState:
        if not self.output_guardrails:
            return state
        answer = state.get("answer", "")
        context = {"sources": state.get("sources", []), "user_role": state.get("user_role")}
        result = self.output_guardrails.run(answer, context)
        if not result.failures:
            return state

        self.store.log_event("guardrail_output", {"failures": [f.guardrail for f in result.failures], "action": result.action.value if result.action else "redact"})

        if result.action == OnFail.REASK:
            if state.get("reask_count", 0) < self.max_reasks:
                self.store.log_event("guardrail_reask", {"failures": [f.guardrail for f in result.failures]})
                return {**state, "guardrail_feedback": result.feedback(), "answer": result.text}
            self.store.log_event("guardrail_blocked", {"stage": "output", "reason": "reask_exhausted", "failures": [f.guardrail for f in result.failures]})
            return {**state, "answer": "I couldn't produce a response that satisfies the guardrails.", "blocked": True, "guardrail_feedback": None}

        if result.blocked:
            self.store.log_event("guardrail_blocked", {"stage": "output", "failures": [f.guardrail for f in result.failures]})
            message = "Response withheld by content policy." if result.action == OnFail.BLOCK else "I can't help with that request."
            return {**state, "answer": message, "blocked": True}

        return {**state, "answer": result.text}

    def _scan_output(self, state: AgentState) -> AgentState:
        answer = state.get("answer", "")
        scan = self.scanner.scan_output(answer)
        if scan.detected:
            self.store.log_event("output_secrets_redacted", {"matches": scan.matches})
            if scan.sanitized_text is not None:
                return {**state, "answer": scan.sanitized_text}
        return state

    @staticmethod
    def _route_after_scan(state: AgentState) -> Literal["scan_output", "guardrail_input"]:
        return "scan_output" if state.get("blocked") else "guardrail_input"

    @staticmethod
    def _route_after_input_guard(state: AgentState) -> Literal["scan_output", "agent_decision"]:
        return "scan_output" if state.get("blocked") else "agent_decision"

    @staticmethod
    def _route_after_policy(state: AgentState) -> Literal["scan_output", "execute_tool", "guardrail_output"]:
        if state.get("requires_approval"):
            return "scan_output"
        if state.get("answer", "").startswith("Tool call blocked"):
            return "scan_output"
        if not state.get("tool_name"):
            return "guardrail_output"
        return "execute_tool"

    @staticmethod
    def _route_after_output_guard(state: AgentState) -> Literal["scan_output", "agent_decision"]:
        return "agent_decision" if state.get("guardrail_feedback") else "scan_output"

    def _build_graph(self):
        graph = StateGraph(AgentState)
        graph.add_node("scan_input", self._scan_input)
        graph.add_node("guardrail_input", self._guardrail_input)
        graph.add_node("agent_decision", self._agent_decision)
        graph.add_node("policy_guard", self._policy_guard)
        graph.add_node("execute_tool", self._execute_tool)
        graph.add_node("guardrail_output", self._guardrail_output)
        graph.add_node("scan_output", self._scan_output)
        graph.add_edge(START, "scan_input")
        graph.add_conditional_edges("scan_input", self._route_after_scan, {"guardrail_input": "guardrail_input", "scan_output": "scan_output"})
        graph.add_conditional_edges("guardrail_input", self._route_after_input_guard, {"agent_decision": "agent_decision", "scan_output": "scan_output"})
        graph.add_edge("agent_decision", "policy_guard")
        graph.add_conditional_edges("policy_guard", self._route_after_policy, {"execute_tool": "execute_tool", "guardrail_output": "guardrail_output", "scan_output": "scan_output"})
        graph.add_edge("execute_tool", "guardrail_output")
        graph.add_conditional_edges("guardrail_output", self._route_after_output_guard, {"agent_decision": "agent_decision", "scan_output": "scan_output"})
        graph.add_edge("scan_output", END)
        return graph.compile()

    def invoke(self, message: str, user_role: str = "user") -> dict:
        return self.graph.invoke({"message": message, "user_role": user_role})

    def approve(self, approval_id: str) -> dict:
        approval = self.store.get_approval(approval_id)
        if not approval:
            raise ValueError("Approval not found.")
        if approval["status"] != "pending":
            raise ValueError("Approval already processed.")
        tool = self.registry.get(approval["tool_name"])
        if not tool:
            raise ValueError("Tool not registered.")

        egress = self.scanner.scan_tool_input(approval["tool_args"])
        if egress.detected:
            self.store.log_event("egress_blocked", {"approval_id": approval_id, "tool_name": approval["tool_name"], "matches": egress.matches})
            raise ValueError("Outbound secret or credential detected in tool arguments; execution blocked.")

        result = tool.handler(**approval["tool_args"])
        output = str(result)
        scan = self.scanner.scan_output(output)
        if scan.detected:
            self.store.log_event("output_secrets_redacted", {"approval_id": approval_id, "matches": scan.matches})
            if scan.sanitized_text is not None:
                output = scan.sanitized_text
        self.store.update_approval_status(approval_id, "approved")
        self.store.log_event("approval_approved", {"approval_id": approval_id, "tool_name": approval["tool_name"], "result": output})
        return {"status": "approved", "result": output}

    def reject(self, approval_id: str) -> dict:
        approval = self.store.get_approval(approval_id)
        if not approval:
            raise ValueError("Approval not found.")
        if approval["status"] != "pending":
            raise ValueError("Approval already processed.")
        self.store.update_approval_status(approval_id, "rejected")
        self.store.log_event("approval_rejected", {"approval_id": approval_id, "tool_name": approval["tool_name"]})
        return {"status": "rejected"}
