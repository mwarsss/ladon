"""
Zero-Trust Policy Engine for AgentWall.

Evaluates every tool call against YAML security rules in order (first match wins)
with default-deny backstops for external communication and financial transfers.
Unit-testable without requiring any LLM.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from agentwall.environment import Environment
from agentwall.impersonation import ImpersonationSignal, check_lookalike_domain, extract_domain
from agentwall.taint import TaintTracker


@dataclass
class PolicyDecision:
    decision: str  # "allow", "block", "require_approval"
    reason: str
    rule_id: str


class PolicyEngine:
    """Evaluates proposed actions against security rules."""

    DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"

    def __init__(self, policy_path: Optional[str | Path] = None):
        self.policy_path = Path(policy_path or self.DEFAULT_POLICY_PATH)
        self.rules: List[Dict[str, Any]] = []
        self.default_decisions: Dict[str, Dict[str, str]] = {}
        self._load_policy()

    def _load_policy(self) -> None:
        """Load and parse the policy YAML file."""
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")

        with open(self.policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        self.rules = data.get("rules", [])
        self.default_decisions = data.get("default_decisions", {})

    def evaluate(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        category: str,
        env: Environment,
        taint_tracker: Optional[TaintTracker] = None,
        impersonation_signals: Optional[List[ImpersonationSignal]] = None,
    ) -> PolicyDecision:
        """Evaluate a proposed tool call and return a security decision."""
        tracker = taint_tracker or TaintTracker(env=env)
        signals = impersonation_signals or []

        # Context for condition evaluation
        confidential_flow = tracker.has_confidential_flow(arguments)
        to_arg = str(arguments.get("to", ""))
        amount_arg = arguments.get("amount", 0.0)

        # Iterate through rules in order
        for rule in self.rules:
            rule_id = rule.get("id", "rule")
            rule_category = rule.get("category")
            rule_categories = rule.get("categories", [rule_category] if rule_category else [])

            if rule_categories and category not in rule_categories:
                continue

            condition = rule.get("condition")
            matched = True

            if condition:
                matched = self._eval_condition(
                    condition=condition,
                    arguments=arguments,
                    category=category,
                    env=env,
                    tracker=tracker,
                    signals=signals,
                    confidential_flow=confidential_flow,
                )

            if matched:
                reason_tpl = rule.get("reason", "Action evaluated by policy")
                confidential_src = confidential_flow.label.source if confidential_flow else "confidential file"
                formatted_reason = reason_tpl.format(
                    to=to_arg,
                    amount=f"{amount_arg:,.2f}" if isinstance(amount_arg, (int, float)) else str(amount_arg),
                    confidential_source=confidential_src,
                    tool=tool_name,
                )
                return PolicyDecision(
                    decision=rule.get("decision", "allow"),
                    reason=formatted_reason,
                    rule_id=rule_id,
                )

        # Default fallback decision per category
        fallback = self.default_decisions.get(
            category,
            {"decision": "block", "reason": f"Default Deny for category {category}."},
        )
        return PolicyDecision(
            decision=fallback.get("decision", "block"),
            reason=fallback.get("reason", "Default policy decision."),
            rule_id="default_fallback",
        )

    def _eval_condition(
        self,
        condition: str,
        arguments: Dict[str, Any],
        category: str,
        env: Environment,
        tracker: TaintTracker,
        signals: List[ImpersonationSignal],
        confidential_flow: Optional[Any],
    ) -> bool:
        """Evaluate boolean policy condition expressions."""
        cond = condition.strip()

        # Handle 'and' compounds
        if " and " in cond:
            sub_conds = [sc.strip() for sc in cond.split(" and ")]
            return all(
                self._eval_condition(
                    sc, arguments, category, env, tracker, signals, confidential_flow
                )
                for sc in sub_conds
            )

        if cond == "has_confidential_flow":
            return confidential_flow is not None

        elif cond == "target_is_untrusted_entity_or_lookalike":
            to_addr = str(arguments.get("to", "")).lower()
            if not to_addr:
                return False
            # Check if domain is a lookalike of company domain
            domain = extract_domain(to_addr)
            if check_lookalike_domain(domain, [env.company_domain]):
                return True
            # Check if address first appeared only inside untrusted content
            if to_addr in tracker.untrusted_entities:
                return True
            return False

        elif cond == "target_not_in_payee_registry":
            target = str(arguments.get("to", ""))
            return env.get_payee(target) is None

        elif cond == "target_in_payee_registry":
            target = str(arguments.get("to", ""))
            return env.get_payee(target) is not None

        elif cond == "has_untrusted_instruction_provenance":
            return tracker.has_untrusted_instruction_provenance()

        elif cond == "has_lookalike_signal":
            return any(s.signal_type == "lookalike_domain" for s in signals)

        elif cond == "target_in_trusted_contacts":
            to_addr = str(arguments.get("to", ""))
            return env.is_trusted_contact(to_addr)

        return False
