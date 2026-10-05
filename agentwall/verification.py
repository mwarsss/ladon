"""Out-of-band verification: confirm a held payment through a contact already on file.

Experts give the same advice for invoice fraud and cloned-voice calls alike: verify the
request, not the voice. When AgentWall holds a payment, it looks up the supplier's phone
number in the company's own records (never a number or address from the email), sends a
one-time code there, and only accepts the approval when the person approving types that
code. Getting the code means the approver really reached the supplier on a known number.

The demo shows the text message on screen as the supplier's phone; a deployment would
send it through an SMS gateway.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from email.utils import parseaddr
from typing import Any, Dict, Optional

from agentwall.environment import Contact, Environment
from agentwall.taint import TaintTracker

MAX_ATTEMPTS = 3


def _words(text: str) -> set:
    return set(re.findall(r"[a-z]{4,}", text.lower())) - {"logistics", "accounts", "billing", "desk", "fleet"}


def verified_contact(env: Environment, tracker: TaintTracker, arguments: Dict[str, Any]) -> Optional[Contact]:
    """The supplier's contact from company records, for confirming this payment."""
    target = str(arguments.get("to", ""))
    payee = env.get_payee(target)
    if payee is not None:
        match = next((c for c in env.trusted_contacts if _words(c.name) & _words(payee.name)), None)
        if match and match.phone:
            return match
    # A new account: confirm with whoever it claims to come from, on the number we hold for them.
    flow = tracker.has_untrusted_entity_flow(arguments)
    if flow is not None and flow.label.source.startswith("email:"):
        email = next((e for e in env.inbox if e.id == flow.label.source.split(":", 1)[1]), None)
        if email is not None:
            name, sender = parseaddr(email.from_addr)
            contact = env.get_contact_by_email(sender)
            if contact is None:
                contact = next((c for c in env.trusted_contacts if c.phone and _words(c.name) & _words(name)), None)
            if contact and contact.phone:
                return contact
    return None


def new_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def code_hash(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()


def code_matches(code: str, expected_hash: str) -> bool:
    return hmac.compare_digest(code_hash(code), expected_hash)


def sms_text(company: str, contact: Contact, arguments: Dict[str, Any], code: str) -> str:
    amount = arguments.get("amount", 0)
    try:
        amount_txt = f"${float(amount):,.2f}"
    except (TypeError, ValueError):
        amount_txt = str(amount)
    return (f"AgentWall for {company}: a payment of {amount_txt} to account {arguments.get('to', '?')} "
            f"was requested in the name of {contact.name}. If you asked for this, read code {code} to the "
            f"person who calls you from {company}. If you didn't, tell them it is fraud.")
