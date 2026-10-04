"""
Unit tests for Tamper-Evident Signed Audit Log (agentwall/audit.py).
"""

import json
from pathlib import Path

import pytest

from agentwall.audit import AuditLogger


@pytest.fixture
def audit_setup(tmp_path):
    log_file = tmp_path / "logs" / "audit.jsonl"
    keys_dir = tmp_path / "keys"
    logger = AuditLogger(log_file=log_file, keys_dir=keys_dir)
    pub_key_path = keys_dir / "ed25519_public.pem"
    return logger, log_file, pub_key_path


def test_audit_logging_and_verification(audit_setup):
    logger, log_file, pub_key_path = audit_setup

    logger.log_event("tool_call", {"tool": "read_inbox"})
    logger.log_event("decision", {"decision": "allow", "reason": "safe read"})
    logger.log_event(
        "decision", {"decision": "block", "reason": "exfiltration attempt"}
    )

    is_valid, msg, broken_idx = AuditLogger.verify_log_file(
        log_path=log_file, public_key_path=pub_key_path
    )
    assert is_valid is True
    assert broken_idx is None
    assert "3 entries checked" in msg


def test_audit_tamper_content_detection(audit_setup):
    logger, log_file, pub_key_path = audit_setup

    logger.log_event("decision", {"decision": "block", "amount": 1000})
    logger.log_event("decision", {"decision": "allow", "amount": 2000})

    # Tamper with the first line: change "block" to "allow"
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    tampered_entry = json.loads(lines[0])
    tampered_entry["details"]["decision"] = "allow"  # Malicious attacker modification
    lines[0] = json.dumps(tampered_entry) + "\n"

    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    is_valid, msg, broken_idx = AuditLogger.verify_log_file(
        log_path=log_file, public_key_path=pub_key_path
    )
    assert is_valid is False
    assert broken_idx == 0
    assert "tampering detected" in msg.lower()


def test_audit_tamper_chain_break(audit_setup):
    logger, log_file, pub_key_path = audit_setup

    logger.log_event("event_1", {"data": 1})
    logger.log_event("event_2", {"data": 2})

    # Corrupt prev_hash of second line
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entry = json.loads(lines[1])
    entry["prev_hash"] = "f" * 64
    lines[1] = json.dumps(entry) + "\n"

    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    is_valid, msg, broken_idx = AuditLogger.verify_log_file(
        log_path=log_file, public_key_path=pub_key_path
    )
    assert is_valid is False
    assert broken_idx == 1
    assert "chain broken" in msg.lower()
