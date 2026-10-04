"""
Human-in-the-Loop Approval Queue for AgentWall.

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

    # Internal synchronization primitive
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            f.name: copy.deepcopy(getattr(self, f.name))
            for f in fields(self)
            if f.name != "_event"
        }


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

    def resolve(
        self, approval_id: str, approved: bool, note: Optional[str] = None
    ) -> bool:
        """Resolve a pending approval request (Approve or Deny)."""
        with self._lock:
            item = self._items.get(approval_id)
            if not item or item.status != "pending":
                return False

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
