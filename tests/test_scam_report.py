"""
Unit tests for the Scam Report Generator (ladon/scam_report.py).
"""

import pytest

from ladon.environment import Contact, Environment
from ladon.gateway import GatewayDecision
from ladon.impersonation import ImpersonationSignal
from ladon.judge import JudgeVerdict
from ladon.scam_report import generate_scam_report


def test_scam_report_generation():
    env = Environment(
        company_domain="kopjelogistics.example",
        trusted_contacts=[
            Contact(
                name="Tendai Moyo",
                email="tendai.moyo@kopjelogistics.example",
                phone="+263 77 210 9845",
            )
        ],
        files={"finance/q3_payroll.csv": None},  # type: ignore
    )

    signals = [
        ImpersonationSignal(
            signal_type="lookalike_domain",
            severity="high",
            evidence="Sender domain kopje-logistlcs.example imitates kopjelogistics.example",
            source_entity="kopje-logistlcs.example",
        ),
        ImpersonationSignal(
            signal_type="pressure_tactic",
            severity="medium",
            evidence="Urgency pressure tactic: matched phrase 'urgent'",
            source_entity="urgent",
        ),
    ]

    judge_verdict = JudgeVerdict(
        injection=True,
        confidence=0.95,
        quoted_instruction="Skip confirmation",
        explanation="Hidden HTML comment containing system instructions",
        method="heuristic",
    )

    blocked = [
        GatewayDecision(
            allowed=False,
            decision="block",
            reason="Data exfiltration blocked: Attempt to send confidential information from file:finance/q3_payroll.csv to external address tendai.moyo@kopje-logistlcs.example.",
            tool_name="send_email",
            arguments={"to": "tendai.moyo@kopje-logistlcs.example"},
        ),
        GatewayDecision(
            allowed=False,
            decision="block",
            reason="Blocked payment of $8,450.00 to unverified account ACC-99281.",
            tool_name="make_payment",
            arguments={"to": "ACC-99281", "amount": 8450.0},
        ),
    ]

    report = generate_scam_report(
        env=env,
        impersonation_signals=signals,
        judge_verdict=judge_verdict,
        blocked_decisions=blocked,
    )

    assert report.prevented_impact.prevented_payment_total == 8450.0
    assert "ACC-99281" in report.prevented_impact.blocked_payee_accounts
    assert len(report.red_flags) == 3

    # Check that recommended steps include verified phone number
    md = report.to_markdown()
    assert "+263 77 210 9845" in md
    assert "Tendai Moyo" in md
    assert "$8,450.00" in md
    assert "# 🛡️ Ladon Incident Scam Report" in md
