"""
Zero-Trust Policy Engine for AgentWall.

Evaluates every tool call against YAML security rules in order (first match wins)
with default-deny backstops for external communication and financial transfers.
Unit-testable without requiring any LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from email.utils import parseaddr
from urllib.parse import unquote_plus, urlsplit

import yaml

from agentwall.environment import Environment
from agentwall.impersonation import (
    ImpersonationSignal,
    analyze_email_signals,
    check_lookalike_domain,
    extract_domain,
)
from agentwall.taint import TaintTracker


@dataclass
class PolicyDecision:
    decision: str  # "allow", "block", "require_approval"
    reason: str
    rule_id: str


KNOWN_CONDITIONS = {
    "has_confidential_flow",
    "target_is_untrusted_entity_or_lookalike",
    "target_not_in_payee_registry",
    "target_in_payee_registry",
    "has_untrusted_instruction_provenance",
    "payee_introduced_by_unverified_sender",
    "has_lookalike_signal",
    "target_in_trusted_contacts",
    "url_sends_payload_to_unknown_domain",
    "amount_exceeds_auto_limit",
    "is_duplicate_reference",
}


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
        self.limits: Dict[str, float] = data.get("limits", {})
        # A misspelled condition must not silently disable a security rule.
        for rule in self.rules:
            condition = rule.get("condition")
            if not condition:
                continue
            for atom in condition.split(" and "):
                if atom.strip() not in KNOWN_CONDITIONS:
                    raise ValueError(
                        f"Policy rule '{rule.get('id')}' uses unknown condition '{atom.strip()}'"
                    )

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

        # Context for condition evaluation. URLs are decoded first so
        # percent-encoding can't hide data being smuggled out in a request.
        flow_args = arguments
        if tool_name == "fetch_url":
            flow_args = {"url": unquote_plus(str(arguments.get("url", "")))}
        confidential_flow = tracker.has_confidential_flow(flow_args)
        to_arg = str(arguments.get("to", ""))
        amount_arg = arguments.get("amount", 0.0)

        # Iterate through rules in order
        for rule in self.rules:
            rule_id = rule.get("id", "rule")
            rule_category = rule.get("category")
            rule_categories = rule.get("categories", [rule_category] if rule_category else [])

            if rule_categories and category not in rule_categories:
                continue
            rule_tools = rule.get("tools")
            if rule_tools and tool_name not in rule_tools:
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
                    url=str(arguments.get("url", "")),
                    reference=str(arguments.get("reference", "")),
                    limit=f"{self._auto_limit(env, to_arg):,.2f}",
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

        elif cond == "payee_introduced_by_unverified_sender":
            return self._payee_from_unverified_sender(arguments, env, tracker)

        elif cond == "url_sends_payload_to_unknown_domain":
            parts = urlsplit(str(arguments.get("url", "")))
            host = (parts.hostname or "").lower()
            if not (parts.query or parts.fragment):
                return False
            return host not in self._known_domains(env)

        elif cond == "amount_exceeds_auto_limit":
            try:
                amount = float(arguments.get("amount", 0))
            except (TypeError, ValueError):
                return True
            return amount > self._auto_limit(env, str(arguments.get("to", "")))

        elif cond == "is_duplicate_reference":
            return env.is_duplicate_payment(str(arguments.get("reference", "")))

        raise ValueError(f"Unknown policy condition: {cond}")

    @staticmethod
    def _payee_from_unverified_sender(
        arguments: Dict[str, Any], env: Environment, tracker: TaintTracker
    ) -> bool:
        """True unless the new account was introduced by a known contact showing no spoofing.

        A genuine supplier changing bank details should be held for a human to verify;
        an account supplied by an unknown or spoofed sender should be blocked outright.
        """
        flow = tracker.has_untrusted_entity_flow(arguments)
        if flow is None:
            return False  # not introduced by any message; the hold rule still applies
        if not flow.label.source.startswith("email:"):
            return True  # e.g. an account taken from an untrusted web page
        email_id = flow.label.source.split(":", 1)[1]
        email = next((e for e in env.inbox if e.id == email_id), None)
        if email is None:
            return True
        _, sender = parseaddr(email.from_addr)
        if not env.is_trusted_contact(sender):
            return True
        spoofing = {"lookalike_domain", "display_name_spoof", "reply_to_mismatch"}
        return any(sig.signal_type in spoofing for sig in analyze_email_signals(email, env))

    def _auto_limit(self, env: Environment, target: str) -> float:
        payee = env.get_payee(target) if target else None
        if payee and payee.max_auto_amount is not None:
            return float(payee.max_auto_amount)
        return float(self.limits.get("auto_payment_limit", 5000))

    @staticmethod
    def _known_domains(env: Environment) -> set:
        domains = {env.company_domain}
        domains.update(c.email.split("@")[-1].lower() for c in env.trusted_contacts if "@" in c.email)
        domains.update((urlsplit(u).hostname or "").lower() for u in env.web_pages)
        domains.discard("")
        return domains
