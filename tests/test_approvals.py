"""
Unit tests for the Human-in-the-Loop Approval Queue (ladon/approvals.py).
"""

import threading
import time

import pytest

from ladon.approvals import ApprovalQueue


def test_approval_creation_and_resolution():
    queue = ApprovalQueue()
    item = queue.create_request(
        tool_name="make_payment",
        arguments={"to": "ACC-88301", "amount": 4500.0},
        reason="Bank details change",
    )

    assert item.status == "pending"
    assert item.amount == 4500.0
    assert len(queue.get_pending()) == 1

    # Resolve approval
    success = queue.resolve(item.id, approved=True, note="Confirmed via phone")
    assert success is True
    assert item.status == "approved"
    assert len(queue.get_pending()) == 0


def test_approval_denial():
    queue = ApprovalQueue()
    item = queue.create_request(
        tool_name="make_payment",
        arguments={"to": "ACC-99999", "amount": 10000.0},
        reason="Suspicious transfer",
    )

    success = queue.resolve(item.id, approved=False, note="Fraud suspected")
    assert success is True
    assert item.status == "denied"


def test_approval_wait_thread_resolution():
    queue = ApprovalQueue()
    item = queue.create_request(
        tool_name="make_payment",
        arguments={"to": "ACC-12345", "amount": 500.0},
        reason="New supplier verification",
    )

    def resolver():
        time.sleep(0.1)
        queue.resolve(item.id, approved=True)

    t = threading.Thread(target=resolver)
    t.start()

    approved = queue.wait_for_resolution(item, timeout=2.0)
    t.join()

    assert approved is True
    assert item.status == "approved"


def test_approval_timeout_default_deny():
    queue = ApprovalQueue()
    item = queue.create_request(
        tool_name="make_payment",
        arguments={"to": "ACC-12345", "amount": 500.0},
        reason="Verification test",
    )

    # Short timeout to test default deny
    approved = queue.wait_for_resolution(item, timeout=0.05)
    assert approved is False
    assert item.status == "timed_out"


def test_hold_sends_code_to_the_contact_on_file_and_approval_needs_it(tmp_path):
    import json
    import threading

    from ladon.approvals import ApprovalQueue, CodeRejected
    from ladon.audit import AuditLogger
    from ladon.environment import Environment
    from ladon.gateway import Gateway

    data = json.loads(open("scenarios/d_verify_bank_change.json").read())
    env = Environment.from_scenario(data)
    queue = ApprovalQueue()
    audit = AuditLogger(log_file=tmp_path / "audit.jsonl", keys_dir=tmp_path / "keys")
    gw = Gateway(env, mode="protected", approval_queue=queue, audit_logger=audit)
    events = []
    gw.add_event_listener(events.append)
    gw.execute("read_inbox", {})
    gw.execute("read_email", {"id": "msg-401"})

    result = {}
    t = threading.Thread(target=lambda: result.update(d=gw.execute(
        "make_payment", {"to": "ACC-88301", "amount": 4500.0, "reference": "INV-7721"})))
    t.start()
    while not any(e["type"] == "approval_needed" for e in events):
        pass
    sms = next(e for e in events if e["type"] == "verification_sent")
    # The number comes from company records, not from the email.
    assert sms["to_name"] == "Apex Supplier Desk" and sms["to_phone"] == "+263 77 555 0199"
    code = next(w.rstrip(".") for w in sms["message"].split() if w.rstrip(".").isdigit() and len(w.rstrip(".")) == 6)
    approval_id = sms["approval_id"]

    with pytest.raises(CodeRejected):
        queue.resolve(approval_id, approved=True, code="000000" if code != "000000" else "111111")
    assert queue.resolve(approval_id, approved=True, code=code)
    t.join(timeout=5)
    assert result["d"].decision == "allow"
    assert code not in (tmp_path / "audit.jsonl").read_text()  # the audit log never holds the code


def test_three_wrong_codes_deny_the_payment():
    from ladon.approvals import ApprovalQueue, CodeRejected
    from ladon.verification import code_hash

    queue = ApprovalQueue()
    item = queue.create_request("make_payment", {"to": "ACC-1", "amount": 10}, "hold")
    queue.require_code(item, "Supplier", "+263 77 000 0000", code_hash("123456"))
    for _ in range(3):
        with pytest.raises(CodeRejected):
            queue.resolve(item.id, approved=True, code="999999")
    assert item.status == "denied"
