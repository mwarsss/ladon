"""
Impersonation and Scam Recognition Module for AgentWall.

Pure-deterministic security checks (zero LLM dependencies):
1. Lookalike domain detection (homoglyph normalisation + edit distance via rapidfuzz)
2. Display-name spoofing (matching executive names with external sender addresses)
3. Payee / bank account changes (unregistered payees or altered bank accounts)
4. Pressure tactics (urgency, secrecy, and verification-bypass phrases)
5. Reply-To header mismatch
"""

from __future__ import annotations

import email.utils
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from rapidfuzz import distance

from agentwall.environment import Contact, Email, Environment

# Common homoglyph mappings (visual look-alikes across Latin, numbers, and Cyrillic)
HOMOGLYPH_MAP = {
    # Latin / digits
    "1": "i",
    "l": "i",
    "0": "o",
    "8": "b",
    "5": "s",
    # Cyrillic homoglyphs mapping to Latin equivalents
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es
    "\u0435": "e",  # Cyrillic small letter ie
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er
    "\u0455": "s",  # Cyrillic small letter dze
    "\u0443": "y",  # Cyrillic small letter u
    "\u0445": "x",  # Cyrillic small letter ha
}

PRESSURE_PATTERNS = [
    (r"\b(?:urgent|urgently|immediate|immediately|asap|today|right away)\b", "Urgency pressure tactic"),
    (r"\b(?:keep this confidential|strictly confidential|do not discuss|top secret|private audit)\b", "Secrecy pressure tactic"),
    (r"\b(?:skip(?:ping)? (?:all )?confirmations?|skip verification|do not delay|do not call|no need to verify)\b", "Verification bypass instruction"),
    (r"\b(?:prevent shipment delays?|critical deadline|penalt(?:y|ies))\b", "Coercion / consequence threat"),
    (r"\b(?:via|through|by|on|to (?:our|my)) (?:ecocash|onemoney|one money|innbucks|mobile money)\b|\b(?:ecocash|onemoney|innbucks) merchant\b",
     "Payment moved to mobile money, a common way to dodge bank checks"),
    (r"\b(?:sent|paid|transferred) (?:you )?(?:\$|usd ?)?[\d,.]+ (?:\w+ )?by mistake\b|\brefund the (?:extra|difference|balance|overpayment)\b",
     "Overpayment refund request, the classic fake-payment-confirmation scam"),
]


@dataclass
class ImpersonationSignal:
    signal_type: str  # "lookalike_domain", "display_name_spoof", "payee_change", "pressure_tactic", "reply_to_mismatch"
    severity: str  # "high", "medium", "low"
    evidence: str
    source_entity: str


def normalize_homoglyphs(text: str) -> str:
    """Normalize common homoglyphs and remove hyphens/dots for fuzzy comparison."""
    normalized = []
    for char in text.lower():
        normalized.append(HOMOGLYPH_MAP.get(char, char))
    s = "".join(normalized)
    # Also standardize common multi-char homoglyphs like 'rn' -> 'm'
    s = s.replace("rn", "m").replace("vv", "w")
    return s


def extract_domain(email_address: str) -> str:
    """Extract domain portion from an email address or string."""
    clean = email_address.strip().lower()
    if "@" in clean:
        return clean.split("@", 1)[1].strip(">").strip()
    return clean


def check_lookalike_domain(
    domain: str, trusted_domains: List[str]
) -> Optional[ImpersonationSignal]:
    """Check if a domain is deceptively similar to any trusted company domain."""
    candidate = domain.strip().lower()

    for trusted in trusted_domains:
        trusted_clean = trusted.strip().lower()
        if candidate == trusted_clean:
            # Exact match is legitimate
            continue

        # Check raw Levenshtein distance
        raw_dist = distance.Levenshtein.distance(candidate, trusted_clean)
        # Check normalized homoglyph distance
        norm_candidate = normalize_homoglyphs(candidate)
        norm_trusted = normalize_homoglyphs(trusted_clean)
        norm_dist = distance.Levenshtein.distance(norm_candidate, norm_trusted)

        min_dist = min(raw_dist, norm_dist)

        # Flag domains that are within 1 to 3 edits or visually identical
        if min_dist <= 2 or (min_dist == 3 and abs(len(candidate) - len(trusted_clean)) <= 2):
            return ImpersonationSignal(
                signal_type="lookalike_domain",
                severity="high",
                evidence=(
                    f"Sender domain '{candidate}' imitates trusted domain '{trusted_clean}' "
                    f"(edit distance: {raw_dist}, homoglyph distance: {norm_dist})"
                ),
                source_entity=candidate,
            )

    return None


def check_display_name_spoofing(
    from_header: str, trusted_contacts: List[Contact]
) -> Optional[ImpersonationSignal]:
    """Detect if the sender display name impersonates a trusted contact with a different address."""
    name, address = email.utils.parseaddr(from_header)
    clean_name = name.strip()
    clean_addr = address.strip().lower()

    if not clean_name:
        return None

    for contact in trusted_contacts:
        trusted_name = contact.name.strip()
        trusted_addr = contact.email.strip().lower()

        # Check if the display name is identical or closely matches an executive/contact
        name_match = (
            clean_name.lower() == trusted_name.lower()
            or trusted_name.lower() in clean_name.lower()
        )

        if name_match and clean_addr != trusted_addr:
            return ImpersonationSignal(
                signal_type="display_name_spoof",
                severity="high",
                evidence=(
                    f"Display name '{clean_name}' impersonates trusted contact '{trusted_name}', "
                    f"but actual address is '{clean_addr}' (trusted address is '{trusted_addr}')"
                ),
                source_entity=clean_addr,
            )

    return None


def check_pressure_tactics(text: str) -> List[ImpersonationSignal]:
    """Identify psychological manipulation phrases: urgency, secrecy, and verification avoidance."""
    signals: List[ImpersonationSignal] = []
    lower_text = text.lower()

    for pattern, description in PRESSURE_PATTERNS:
        match = re.search(pattern, lower_text)
        if match:
            signals.append(
                ImpersonationSignal(
                    signal_type="pressure_tactic",
                    severity="medium",
                    evidence=f"{description}: matched phrase '{match.group(0)}'",
                    source_entity=match.group(0),
                )
            )

    return signals


def check_reply_to_mismatch(
    from_addr: str, reply_to: Optional[str]
) -> Optional[ImpersonationSignal]:
    """Detect when Reply-To redirects responses to a different domain/address."""
    if not reply_to or not reply_to.strip():
        return None

    from_domain = extract_domain(from_addr)
    reply_domain = extract_domain(reply_to)

    if from_domain != reply_domain:
        return ImpersonationSignal(
            signal_type="reply_to_mismatch",
            severity="medium",
            evidence=(
                f"Reply-To address '{reply_to}' directs to domain '{reply_domain}' "
                f"which differs from sender domain '{from_domain}'"
            ),
            source_entity=reply_to,
        )

    return None


def check_payee_change(
    target_account: str, amount: float, env: Environment
) -> Optional[ImpersonationSignal]:
    """Detect payments to bank accounts not registered in the verified payee list."""
    clean_target = target_account.strip().lower()

    registered_payee = env.get_payee(clean_target)
    if not registered_payee:
        return ImpersonationSignal(
            signal_type="payee_change",
            severity="high",
            evidence=(
                f"Payment destination '{target_account}' is not in the verified supplier "
                f"payee registry. Unverified bank account details."
            ),
            source_entity=target_account,
        )

    return None


def analyze_email_signals(email: Email, env: Environment) -> List[ImpersonationSignal]:
    """Comprehensive impersonation check for an incoming email."""
    signals: List[ImpersonationSignal] = []

    # 1. Lookalike domain check
    sender_domain = extract_domain(email.from_addr)
    trusted_domains = [env.company_domain]
    lookalike_sig = check_lookalike_domain(sender_domain, trusted_domains)
    if lookalike_sig:
        signals.append(lookalike_sig)

    # 2. Display name spoofing
    spoof_sig = check_display_name_spoofing(email.from_addr, env.trusted_contacts)
    if spoof_sig:
        signals.append(spoof_sig)

    # 3. Reply-To mismatch
    reply_sig = check_reply_to_mismatch(email.from_addr, email.reply_to)
    if reply_sig:
        signals.append(reply_sig)

    # 4. Pressure tactics in subject and body
    pressure_sigs = check_pressure_tactics(f"{email.subject} {email.body}")
    signals.extend(pressure_sigs)

    return signals
