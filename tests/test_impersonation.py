"""
Unit tests for Impersonation and Scam Recognition (agentwall/impersonation.py).
"""

import pytest

from agentwall.environment import Contact, Email, Environment, Payee
from agentwall.impersonation import (
    analyze_email_signals,
    check_display_name_spoofing,
    check_lookalike_domain,
    check_payee_change,
    check_pressure_tactics,
    check_reply_to_mismatch,
    normalize_homoglyphs,
)


def test_homoglyph_normalization():
    # 'l' and '1' and 'i' all normalize to equivalent canonical representation
    assert normalize_homoglyphs("kopje-logist1cs") == normalize_homoglyphs("kopje-logistics")
    assert normalize_homoglyphs("kopje-logistlcs") == normalize_homoglyphs("kopje-logistics")
    # Cyrillic lookalike 'а' (U+0430)
    cyrillic_a = "\u0430"
    assert normalize_homoglyphs(f"kopje{cyrillic_a}logistics") == normalize_homoglyphs("kopjealogistics")


def test_lookalike_domain_detection():
    trusted = ["kopjelogistics.example"]

    # Subtle 'l' for 'i' edit
    sig = check_lookalike_domain("kopje-logistlcs.example", trusted)
    assert sig is not None
    assert sig.signal_type == "lookalike_domain"
    assert sig.severity == "high"

    # Exact legitimate domain
    assert check_lookalike_domain("kopjelogistics.example", trusted) is None

    # Completely different domain (not mimicking)
    assert check_lookalike_domain("hararefuel.co.zw", trusted) is None


def test_display_name_spoofing():
    trusted_contacts = [
        Contact(
            name="Tendai Moyo",
            email="tendai.moyo@kopjelogistics.example",
            phone="+263 77 123 4567",
        )
    ]

    # Spoofed sender: display name matches CEO, but address is external/lookalike
    spoofed = 'Tendai Moyo <tendai.moyo@kopje-logistlcs.example>'
    sig = check_display_name_spoofing(spoofed, trusted_contacts)
    assert sig is not None
    assert sig.signal_type == "display_name_spoof"
    assert "Tendai Moyo" in sig.evidence

    # Legitimate sender: matches display name and address
    legit = 'Tendai Moyo <tendai.moyo@kopjelogistics.example>'
    assert check_display_name_spoofing(legit, trusted_contacts) is None


def test_pressure_tactics():
    text = (
        "URGENT: This must be paid today immediately. Keep this confidential. "
        "Skip all confirmations to prevent shipment delays."
    )
    signals = check_pressure_tactics(text)
    assert len(signals) >= 3
    sig_types = [s.signal_type for s in signals]
    assert all(st == "pressure_tactic" for st in sig_types)


def test_reply_to_mismatch():
    from_addr = "support@kopjelogistics.example"
    reply_to = "attacker@evil-phish.com"
    sig = check_reply_to_mismatch(from_addr, reply_to)
    assert sig is not None
    assert sig.signal_type == "reply_to_mismatch"

    # Same domain
    assert check_reply_to_mismatch(from_addr, "billing@kopjelogistics.example") is None


def test_payee_change_detection():
    env = Environment(
        payee_registry={
            "apex logistics fleet": Payee(name="Apex Logistics Fleet", account="ACC-10042")
        }
    )

    # Scammer's new bank account
    sig = check_payee_change(target_account="ACC-99281", amount=8450.0, env=env)
    assert sig is not None
    assert sig.signal_type == "payee_change"

    # Legitimate account
    assert check_payee_change(target_account="ACC-10042", amount=8450.0, env=env) is None
