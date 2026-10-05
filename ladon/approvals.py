"""
Human-in-the-Loop Approval Queue for Ladon.

Holds risky actions (e.g. bank details changes, high-value transfers) in suspense
until a human administrator explicitly reviews and approves or denies them in the dashboard.
"""

from __future__ import annotations

import copy
import datetime
import threading
import uuid
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional


@dataclass
class ApprovalItem:
    id: str
    tool_name: str
    arguments: Dict[str, Any]
    reason: str
    status: str = "pending"  # "pending", "approved", "denied", "timed_out"
    amount: Optional[float] = None
    target: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    resolved_at: Optional[str] = None
    reviewer_note: Optional[str] = None
    # Out-of-band verification: who was sent a one-time code, from company records
    verify_contact: Optional[str] = None
    verify_phone: Optional[str] = None
    code_attempts: int = 0
    _code_hash: Optional[str] = field(default=None, repr=False)

    # Internal synchronization primitive
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            f.name: copy.deepcopy(getattr(self, f.name))
            for f in fields(self)
            if not f.name.startswith("_")
        }


class CodeRejected(Exception):
    """The verification code was wrong (or too many wrong tries)."""


class ApprovalQueue:
    """Thread-safe queue managing human approval requests."""

    def __init__(self, default_timeout_seconds: float = 60.0):
        self.default_timeout_seconds = default_timeout_seconds
        self._items: Dict[str, ApprovalItem] = {}
        self._lock = threading.Lock()

    def create_request(
        self, tool_name: str, arguments: Dict[str, Any], reason: str
    ) -> ApprovalItem:
        """Create a new pending approval item and queue it."""
        appr_id = f"appr_{uuid.uuid4().hex[:8]}"
        amount = None
        if "amount" in arguments:
            try:
                amount = float(arguments["amount"])
            except (ValueError, TypeError):
                pass
        target = str(arguments.get("to", ""))

        item = ApprovalItem(
            id=appr_id,
            tool_name=tool_name,
            arguments=arguments,
            reason=reason,
            amount=amount,
            target=target,
        )

        with self._lock:
            self._items[appr_id] = item

        return item

    def get_pending(self) -> List[Dict[str, Any]]:
        """List all currently pending approvals."""
        with self._lock:
            return [
                item.to_dict()
                for item in self._items.values()
                if item.status == "pending"
            ]

    def get_all(self) -> List[Dict[str, Any]]:
        """List all approvals (pending, approved, denied)."""
        with self._lock:
            return [item.to_dict() for item in self._items.values()]

    def require_code(self, item: ApprovalItem, contact_name: str, phone: str, code_hash: str) -> None:
        """Approval of this item now needs the code sent to the contact on file."""
        with self._lock:
            item.verify_contact, item.verify_phone, item._code_hash = contact_name, phone, code_hash

    def resolve(
        self, approval_id: str, approved: bool, note: Optional[str] = None, code: Optional[str] = None
    ) -> bool:
        """Resolve a pending approval request (Approve or Deny).

        Approving an item that has a verification code needs that code. Three wrong
        codes deny the payment, since someone is guessing.
        """
        from ladon.verification import MAX_ATTEMPTS, code_matches

        with self._lock:
            item = self._items.get(approval_id)
            if not item or item.status != "pending":
                return False
            if approved and item._code_hash and not code_matches(code or "", item._code_hash):
                item.code_attempts += 1
                if item.code_attempts >= MAX_ATTEMPTS:
                    item.status = "denied"
                    item.resolved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    item.reviewer_note = "Denied: three wrong verification codes."
                    item._event.set()
                    raise CodeRejected("Three wrong codes. The payment has been denied.")
                left = MAX_ATTEMPTS - item.code_attempts
                raise CodeRejected(f"That code doesn't match. {left} tr{'y' if left == 1 else 'ies'} left.")
            if approved and item._code_hash:
                note = note or f"Approved after {item.verify_contact} confirmed the code sent to {item.verify_phone}"

            item.status = "approved" if approved else "denied"
            item.resolved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            item.reviewer_note = note or ("Approved by administrator" if approved else "Denied by administrator")
            item._event.set()
            return True

    def wait_for_resolution(
        self, item: ApprovalItem, timeout: Optional[float] = None
    ) -> bool:
        """
        Block current thread until human resolves or timeout expires.
        Returns True if approved, False if denied or timed out (default deny).
        """
        wait_time = timeout if timeout is not None else self.default_timeout_seconds
        signaled = item._event.wait(timeout=wait_time)

        with self._lock:
            if not signaled:
                item.status = "timed_out"
                item.resolved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                item.reviewer_note = "Timed out waiting for human verification (default deny policy applied)."
                return False
            return item.status == "approved"
