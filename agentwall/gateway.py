"""
The Gateway Interception Layer.

Every action the AI assistant attempts passes through this gateway.
In UNPROTECTED mode, actions pass through directly to the environment
(allowing attacks to succeed for comparison and vulnerability demonstration).
In PROTECTED mode, actions are evaluated against security policies, taint tracking,
and human-in-the-loop approvals.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from agentwall.environment import Environment
from agentwall.tools import execute_tool, get_tool_category, get_tool_metadata


@dataclass
class GatewayDecision:
    allowed: bool
    decision: str  # "allow", "block", "require_approval"
    reason: str
    tool_name: str
    arguments: Dict[str, Any]
    output: Any = None
    scam_report: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None


class Gateway:
    """Interception gateway between agent and environment tools."""

    def __init__(
        self,
        env: Environment,
        mode: str = "unprotected",  # "unprotected" or "protected"
        policy_engine: Optional[Any] = None,
        taint_tracker: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
    ):
        self.env = env
        self.mode = mode.lower()
        self.policy_engine = policy_engine
        self.taint_tracker = taint_tracker
        self.audit_logger = audit_logger

        self.event_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self.call_history: List[GatewayDecision] = []

    def add_event_listener(self, listener: Callable[[Dict[str, Any]], None]) -> None:
        """Register an event listener (for SSE server, UI, or audit logs)."""
        self.event_listeners.append(listener)

    def emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast an event to all registered listeners."""
        payload = {
            "type": event_type,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **data,
        }
        for listener in self.event_listeners:
            try:
                listener(payload)
            except Exception:
                pass

        if self.audit_logger and hasattr(self.audit_logger, "log_event"):
            try:
                self.audit_logger.log_event(event_type, payload)
            except Exception:
                pass

    def execute(self, tool_name: str, arguments: Dict[str, Any]) -> GatewayDecision:
        """Intercept and process a tool invocation."""
        category = get_tool_category(tool_name)

        # Notify tool call initiated
        self.emit_event(
            "tool_call",
            {
                "tool_name": tool_name,
                "arguments": arguments,
                "category": category,
                "mode": self.mode,
            },
        )

        # UNPROTECTED MODE: Pass-through execution
        if self.mode == "unprotected":
            tool_output = execute_tool(self.env, tool_name, arguments)
            decision = GatewayDecision(
                allowed=True,
                decision="allow",
                reason="Pass-through (unprotected mode active)",
                tool_name=tool_name,
                arguments=arguments,
                output=tool_output,
            )
            self.call_history.append(decision)
            self.emit_event(
                "decision",
                {
                    "decision": decision.decision,
                    "reason": decision.reason,
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "allowed": True,
                    "output": tool_output,
                },
            )
            return decision

        # PROTECTED MODE: Security evaluation (Phase 2 & 3 extensions)
        if self.policy_engine:
            policy_result = self.policy_engine.evaluate(
                tool_name=tool_name,
                arguments=arguments,
                category=category,
                env=self.env,
                taint_tracker=self.taint_tracker,
            )
            decision_action = policy_result.decision
            decision_reason = policy_result.reason
        else:
            decision_action = "allow"
            decision_reason = "Default allow (no policy configured)"

        if decision_action == "block":
            tool_output = {
                "error": f"BLOCKED BY SECURITY POLICY: {decision_reason}",
                "status": "blocked",
            }
            decision = GatewayDecision(
                allowed=False,
                decision="block",
                reason=decision_reason,
                tool_name=tool_name,
                arguments=arguments,
                output=tool_output,
            )
            self.call_history.append(decision)
            self.emit_event(
                "decision",
                {
                    "decision": "block",
                    "reason": decision_reason,
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "allowed": False,
                    "output": tool_output,
                },
            )
            return decision

        # If allowed, execute tool
        tool_output = execute_tool(self.env, tool_name, arguments)
        decision = GatewayDecision(
            allowed=True,
            decision="allow",
            reason=decision_reason,
            tool_name=tool_name,
            arguments=arguments,
            output=tool_output,
        )
        self.call_history.append(decision)
        self.emit_event(
            "decision",
            {
                "decision": "allow",
                "reason": decision_reason,
                "tool_name": tool_name,
                "arguments": arguments,
                "allowed": True,
                "output": tool_output,
            },
        )
        return decision
