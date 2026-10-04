"""
The Gateway Interception Layer.

Every action the AI assistant attempts passes through this gateway.
In UNPROTECTED mode, actions pass through directly to the environment
(allowing attacks to succeed for comparison and vulnerability demonstration).
In PROTECTED mode, actions are evaluated against security policies, taint tracking,
impersonation heuristics, isolated prompt injection judge, and human-in-the-loop approvals.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from agentwall.approvals import ApprovalItem, ApprovalQueue
from agentwall.audit import AuditLogger
from agentwall.environment import Environment
from agentwall.impersonation import ImpersonationSignal, analyze_email_signals
from agentwall.judge import InjectionJudge, JudgeVerdict
from agentwall.policy import PolicyDecision, PolicyEngine
from agentwall.scam_report import ScamReport, generate_scam_report
from agentwall.taint import TaintTracker
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
        policy_engine: Optional[PolicyEngine] = None,
        taint_tracker: Optional[TaintTracker] = None,
        audit_logger: Optional[AuditLogger] = None,
        approval_queue: Optional[ApprovalQueue] = None,
        judge: Optional[InjectionJudge] = None,
    ):
        self.env = env
        self.mode = mode.lower()
        self.policy_engine = policy_engine or PolicyEngine()
        self.taint_tracker = taint_tracker or TaintTracker(env=self.env)
        self.audit_logger = audit_logger
        self.approval_queue = approval_queue
        self.judge = judge or InjectionJudge()

        self.impersonation_signals: List[ImpersonationSignal] = []
        self.last_judge_verdict: Optional[JudgeVerdict] = None
        self.event_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self.call_history: List[GatewayDecision] = []

    def add_event_listener(self, listener: Callable[[Dict[str, Any]], None]) -> None:
        """Register an event listener (for SSE server, UI, or audit logs)."""
        self.event_listeners.append(listener)

    def emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast an event to all registered listeners and audit logger."""
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

        if self.audit_logger:
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

        # PROTECTED MODE: Zero-trust policy and taint evaluation
        policy_result: PolicyDecision = self.policy_engine.evaluate(
            tool_name=tool_name,
            arguments=arguments,
            category=category,
            env=self.env,
            taint_tracker=self.taint_tracker,
            impersonation_signals=self.impersonation_signals,
        )

        decision_action = policy_result.decision
        decision_reason = policy_result.reason

        # Handle human-in-the-loop approval requirement
        if decision_action == "require_approval":
            if self.approval_queue:
                appr_item = self.approval_queue.create_request(
                    tool_name=tool_name,
                    arguments=arguments,
                    reason=decision_reason,
                )
                self.emit_event(
                    "approval_needed",
                    {
                        "approval_id": appr_item.id,
                        "tool_name": tool_name,
                        "arguments": arguments,
                        "reason": decision_reason,
                        "amount": appr_item.amount,
                        "target": appr_item.target,
                    },
                )
                # Block waiting for human administrator decision
                approved = self.approval_queue.wait_for_resolution(appr_item, timeout=20.0)
                if approved:
                    tool_output = execute_tool(self.env, tool_name, arguments)
                    decision = GatewayDecision(
                        allowed=True,
                        decision="allow",
                        reason=f"Approved by human administrator: {decision_reason}",
                        tool_name=tool_name,
                        arguments=arguments,
                        output=tool_output,
                        approval_id=appr_item.id,
                    )
                    self.call_history.append(decision)
                    self.emit_event(
                        "decision",
                        {
                            "decision": "allow",
                            "reason": decision.reason,
                            "tool_name": tool_name,
                            "arguments": arguments,
                            "allowed": True,
                            "output": tool_output,
                        },
                    )
                    return decision
                else:
                    decision_action = "block"
                    decision_reason = f"Denied by human verification: {appr_item.reviewer_note or decision_reason}"
            else:
                # If no approval queue attached, hold action
                decision = GatewayDecision(
                    allowed=False,
                    decision="require_approval",
                    reason=decision_reason,
                    tool_name=tool_name,
                    arguments=arguments,
                    output={"status": "held_for_verification", "reason": decision_reason},
                )
                self.call_history.append(decision)
                self.emit_event(
                    "decision",
                    {
                        "decision": "require_approval",
                        "reason": decision_reason,
                        "tool_name": tool_name,
                        "arguments": arguments,
                        "allowed": False,
                        "output": decision.output,
                    },
                )
                return decision

        if decision_action == "block":
            tool_output = {
                "error": f"BLOCKED BY SECURITY POLICY: {decision_reason}",
                "status": "blocked",
            }
            # Generate plain-language scam report
            report = generate_scam_report(
                env=self.env,
                impersonation_signals=self.impersonation_signals,
                judge_verdict=self.last_judge_verdict,
                blocked_decisions=[
                    GatewayDecision(
                        allowed=False,
                        decision="block",
                        reason=decision_reason,
                        tool_name=tool_name,
                        arguments=arguments,
                    )
                ],
            )
            decision = GatewayDecision(
                allowed=False,
                decision="block",
                reason=decision_reason,
                tool_name=tool_name,
                arguments=arguments,
                output=tool_output,
                scam_report=report.to_dict(),
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
                    "scam_report": report.to_dict(),
                },
            )
            return decision

        # If allowed, execute the tool against the environment
        tool_output = execute_tool(self.env, tool_name, arguments)

        # Track taint and provenance on the result
        self.taint_tracker.track_tool_result(
            tool_name=tool_name,
            arguments=arguments,
            output=tool_output,
            env=self.env,
        )

        # If an email was read, inspect for prompt injection and impersonation signals
        if tool_name == "read_email" and isinstance(tool_output, dict):
            email_id = str(arguments.get("id", ""))
            body = tool_output.get("body", "")
            subject = tool_output.get("subject", "")

            # 1. Run Injection Judge on the untrusted message content
            judge_verdict = self.judge.judge(f"{subject}\n{body}")
            self.last_judge_verdict = judge_verdict
            if judge_verdict.injection:
                self.emit_event(
                    "judge_verdict",
                    {
                        "injection": True,
                        "confidence": judge_verdict.confidence,
                        "explanation": judge_verdict.explanation,
                        "source": email_id,
                    },
                )

            # 2. Run Impersonation checks
            for email in self.env.inbox:
                if email.id == email_id:
                    signals = analyze_email_signals(email, self.env)
                    for sig in signals:
                        if sig not in self.impersonation_signals:
                            self.impersonation_signals.append(sig)
                            self.emit_event(
                                "impersonation_signal",
                                {
                                    "signal_type": sig.signal_type,
                                    "severity": sig.severity,
                                    "evidence": sig.evidence,
                                    "source": email_id,
                                },
                            )
                    break

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
