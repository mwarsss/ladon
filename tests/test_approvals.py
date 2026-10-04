"""
Unit tests for the Human-in-the-Loop Approval Queue (agentwall/approvals.py).
"""

import threading
import time

import pytest

from agentwall.approvals import ApprovalQueue


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
