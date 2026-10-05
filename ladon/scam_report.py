"""
Scam Report Generator for Ladon.

Generates structured, plain-language incident response reports for business users
and security administrators when fraudulent actions are blocked or held.
Template-based to guarantee factual accuracy and zero hallucination.
"""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ladon.environment import Contact, Environment
from ladon.impersonation import ImpersonationSignal
from ladon.judge import JudgeVerdict


@dataclass
class RedFlagItem:
    title: str
    severity: str  # "high", "medium", "low"
    evidence: str


@dataclass
class PreventedImpact:
    prevented_payment_total: float
    blocked_payee_accounts: List[str]
    protected_files: List[str]
    suspicious_recipients: List[str]


@dataclass
class ScamReport:
    timestamp: str
    summary: str
    red_flags: List[RedFlagItem]
    prevented_impact: PreventedImpact
    recommended_next_steps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        """Render human-readable Markdown incident summary."""
        lines = [
            "# 🛡️ Ladon Incident Scam Report",
            f"**Generated at:** {self.timestamp}",
            "",
            "## 1. What the Scammer Tried",
            f"> {self.summary}",
            "",
            "## 2. Red Flags Detected",
        ]
        for idx, rf in enumerate(self.red_flags, start=1):
            badge = "[HIGH RISK]" if rf.severity == "high" else "[WARNING]"
            lines.append(f"### {idx}. {rf.title} {badge}")
            lines.append(f"- **Evidence:** {rf.evidence}")

        lines.extend([
            "",
            "## 3. What Ladon Prevented",
            f"- **Financial Loss Prevented:** ${self.prevented_impact.prevented_payment_total:,.2f}",
        ])
        if self.prevented_impact.blocked_payee_accounts:
            lines.append(f"- **Blocked Accounts:** {', '.join(self.prevented_impact.blocked_payee_accounts)}")
        if self.prevented_impact.protected_files:
            lines.append(f"- **Confidential Files Protected from Exfiltration:** {', '.join(self.prevented_impact.protected_files)}")
        if self.prevented_impact.suspicious_recipients:
            lines.append(f"- **Blocked External Recipients:** {', '.join(self.prevented_impact.suspicious_recipients)}")

        lines.extend([
            "",
            "## 4. Recommended Next Steps",
        ])
        for step in self.recommended_next_steps:
            lines.append(f"- [ ] {step}")

        return "\n".join(lines)


def generate_scam_report(
    env: Environment,
    impersonation_signals: List[ImpersonationSignal],
    judge_verdict: Optional[JudgeVerdict] = None,
    blocked_decisions: Optional[List[Any]] = None,
) -> ScamReport:
    """Compile a structured incident report based on detected signals and blocked actions."""
    blocked = blocked_decisions or []
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Analyze Prevented Impact
    prevented_cash = 0.0
    blocked_accounts: List[str] = []
    protected_files: List[str] = []
    suspicious_recipients: List[str] = []

    for d in blocked:
        if d.tool_name == "make_payment":
            try:
                amt = float(d.arguments.get("amount", 0.0))
            except (TypeError, ValueError):
                amt = 0.0  # the model sent something that isn't an amount
            to_acc = str(d.arguments.get("to", ""))
            prevented_cash += amt
            if to_acc and to_acc not in blocked_accounts:
                blocked_accounts.append(to_acc)
        elif d.tool_name == "send_email":
            to_addr = str(d.arguments.get("to", ""))
            if to_addr and to_addr not in suspicious_recipients:
                suspicious_recipients.append(to_addr)
            # Find which file was protected
            for path in env.files.keys():
                if path in d.reason:
                    protected_files.append(path)

    # 2. Extract Red Flags
    red_flags: List[RedFlagItem] = []
    for sig in impersonation_signals:
        title = sig.signal_type.replace("_", " ").title()
        red_flags.append(
            RedFlagItem(title=title, severity=sig.severity, evidence=sig.evidence)
        )

    if judge_verdict and judge_verdict.injection:
        red_flags.append(
            RedFlagItem(
                title="Hidden Prompt Injection",
                severity="high",
                evidence=judge_verdict.explanation,
            )
        )

    # 3. Formulate Summary
    if suspicious_recipients and blocked_accounts:
        summary = (
            f"An external attacker attempted business email compromise (BEC) and prompt injection "
            f"to divert ${prevented_cash:,.2f} to an unverified bank account and exfiltrate confidential files."
        )
    elif blocked_accounts:
        summary = (
            f"An attacker attempted fraudulent invoice payment redirection of ${prevented_cash:,.2f} "
            f"to an unverified bank account."
        )
    elif suspicious_recipients:
        summary = "An external attacker attempted unauthorized exfiltration of confidential internal documents."
    else:
        summary = "Suspicious impersonation signals and policy violations were intercepted."

    # Without spoofing or injection evidence this may be a genuine request; say so.
    spoofing = {"lookalike_domain", "display_name_spoof", "reply_to_mismatch"}
    has_attack_evidence = any(sig.signal_type in spoofing for sig in impersonation_signals) or bool(
        judge_verdict and judge_verdict.injection
    )
    if not has_attack_evidence:
        summary = (
            f"A payment or data transfer was stopped because it could not be verified "
            f"(${prevented_cash:,.2f} held back). There are no signs of impersonation, so this may be "
            f"a genuine request; confirm it through a trusted channel before retrying."
            if prevented_cash
            else "An action was stopped because it could not be verified against policy."
        )

    # 4. Actionable Next Steps: call the person being impersonated or whose request this was.
    primary_contact = _relevant_contact(env, impersonation_signals, blocked)

    steps: List[str] = []
    if primary_contact:
        steps.append(
            f"Verbal Confirmation: Call {primary_contact.name} at {primary_contact.phone} "
            f"(the verified number in company records) to verbally verify the request. Do NOT use any contact details from the email."
        )
    steps.append("Do not reply to the suspicious email or forward it to external parties.")
    steps.append("Alert Internal IT/Security to blacklist the sender domain on corporate mail servers.")
    steps.append("If bank account changes were requested, confirm payment terms directly with the supplier using previously verified contracts.")

    return ScamReport(
        timestamp=timestamp,
        summary=summary,
        red_flags=red_flags,
        prevented_impact=PreventedImpact(
            prevented_payment_total=prevented_cash,
            blocked_payee_accounts=blocked_accounts,
            protected_files=protected_files,
            suspicious_recipients=suspicious_recipients,
        ),
        recommended_next_steps=steps,
    )


def _relevant_contact(
    env: Environment, signals: List[ImpersonationSignal], blocked: List[Any]
) -> Optional[Contact]:
    """Pick the trusted contact named or addressed in the evidence, else the first contact."""
    text = " ".join(
        [f"{sig.evidence} {sig.source_entity}" for sig in signals]
        + [f"{getattr(d, 'reason', '')} {getattr(d, 'arguments', '')}" for d in blocked]
        + [f"{e.from_addr}" for e in env.inbox]
    ).lower()
    best, best_score = None, 0
    for contact in env.trusted_contacts:
        score = 0
        if contact.name.lower() in text:
            score += 2
        if contact.email.lower() in text:
            score += 1
        if score > best_score:
            best, best_score = contact, score
    return best or (env.trusted_contacts[0] if env.trusted_contacts else None)
