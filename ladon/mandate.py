"""Signed payment mandates: the business owner's own signature on who may be paid.

The payee registry is just data, and data can be changed: a hacked supplier database,
a careless edit, or an insider can slip a scammer's account into it. A mandate is the
owner's Ed25519 signature over the approved suppliers and limits (the same idea as the
signed "intent mandates" in Google's AP2 and Mastercard Agent Pay). Ladon only lets
the assistant pay an account that appears in a mandate whose signature checks out.

In the demo, Rudo's key lives in keys/ and the scenario's supplier list is signed when it
loads; in a real deployment she would sign it once, on her own device.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEYS_DIR = Path(os.environ.get("LADON_KEYS_DIR") or Path(__file__).resolve().parent.parent / "keys")
ISSUER = "Rudo, Accounts, Kopje Logistics"
_key: Optional[ed25519.Ed25519PrivateKey] = None


def owner_key() -> ed25519.Ed25519PrivateKey:
    """Load (or create once) the business owner's signing key."""
    global _key
    if _key is None:
        path = KEYS_DIR / "mandate_ed25519_private.pem"
        if path.exists():
            _key = serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[assignment]
        else:
            _key = ed25519.Ed25519PrivateKey.generate()
            try:
                KEYS_DIR.mkdir(parents=True, exist_ok=True)
                path.write_bytes(_key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            except OSError:
                pass  # read-only disk: keep the key in memory for this process
    return _key  # type: ignore[return-value]


@dataclass
class Mandate:
    issuer: str
    issued_at: str
    valid_until: str
    payees: List[Dict[str, Any]]
    auto_payment_limit: Optional[float] = None
    public_key: str = ""
    signature: str = ""
    id: str = field(default="")

    def body(self) -> bytes:
        data = {k: v for k, v in asdict(self).items() if k not in ("signature", "id")}
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self, now: Optional[datetime.datetime] = None) -> Tuple[bool, str]:
        """(valid, reason). Checks the signature, the id and the expiry date."""
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key))
            key.verify(bytes.fromhex(self.signature), self.body())
        except (InvalidSignature, ValueError):
            return False, f"the signature on mandate {self.id or '(unknown)'} does not match its contents"
        if self.id != mandate_id(self.body()):
            return False, f"mandate id {self.id} does not match its contents"
        now = now or datetime.datetime.now(datetime.timezone.utc)
        if now.isoformat() > self.valid_until:
            return False, f"mandate {self.id} expired on {self.valid_until[:10]}"
        return True, f"mandate {self.id} signed by {self.issuer}"

    def payee_for(self, account: str) -> Optional[Dict[str, Any]]:
        clean = account.strip().lower()
        return next((p for p in self.payees
                     if p["account"].lower() == clean or p["name"].lower() == clean), None)

    def public(self) -> Dict[str, Any]:
        ok, reason = self.verify()
        return {**asdict(self), "verified": ok, "status": reason}


_signed: Dict[str, Mandate] = {}


def owner_mandate(payees: List[Dict[str, Any]], auto_payment_limit: Optional[float] = None) -> Mandate:
    """The owner's mandate for this supplier list, signed once and reused (same id everywhere)."""
    key = json.dumps([sorted(payees, key=lambda p: p["account"]), auto_payment_limit], sort_keys=True)
    if key not in _signed or not _signed[key].verify()[0]:
        _signed[key] = sign_mandate(payees, auto_payment_limit=auto_payment_limit)
    return copy.deepcopy(_signed[key])


def mandate_id(body: bytes) -> str:
    return "m-" + hashlib.sha256(body).hexdigest()[:8]


def sign_mandate(payees: List[Dict[str, Any]], auto_payment_limit: Optional[float] = None,
                 issuer: str = ISSUER, valid_days: int = 90,
                 key: Optional[ed25519.Ed25519PrivateKey] = None) -> Mandate:
    key = key or owner_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    mandate = Mandate(
        issuer=issuer,
        issued_at=now.isoformat(timespec="seconds"),
        valid_until=(now + datetime.timedelta(days=valid_days)).isoformat(timespec="seconds"),
        payees=sorted(payees, key=lambda p: p["account"]),
        auto_payment_limit=auto_payment_limit,
        public_key=key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
    )
    mandate.signature = key.sign(mandate.body()).hex()
    mandate.id = mandate_id(mandate.body())
    return mandate
