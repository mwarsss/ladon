"""
Tamper-Evident Hash-Chained and Ed25519-Signed Audit Log for Ladon.

Provides cryptographic non-repudiation for all AI assistant actions and firewall decisions.
Each entry contains:
- index & ISO timestamp
- event name and structured payload
- prev_hash (SHA-256 chaining to preceding entry)
- entry_hash (SHA-256 over canonical JSON representation)
- signature (Ed25519 digital signature over entry_hash)
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_HASH = "0" * 64


class AuditLogger:
    """Manages appending and verifying hash-chained, signed audit records."""

    DEFAULT_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
    DEFAULT_KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"

    def __init__(
        self,
        log_file: Optional[str | Path] = None,
        keys_dir: Optional[str | Path] = None,
    ):
        self.log_file = Path(log_file or (self.DEFAULT_LOG_DIR / "audit.jsonl"))
        self.keys_dir = Path(keys_dir or self.DEFAULT_KEYS_DIR)

        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        self.private_key, self.public_key = self._load_or_generate_keys()
        self.last_hash = self._get_last_hash()
        self.current_index = self._get_last_index() + 1

    def _load_or_generate_keys(
        self,
    ) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Load existing Ed25519 keypair or generate a new one."""
        priv_path = self.keys_dir / "ed25519_private.pem"
        pub_path = self.keys_dir / "ed25519_public.pem"

        if priv_path.exists() and pub_path.exists():
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            with open(pub_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            return private_key, public_key  # type: ignore

        # Generate fresh Ed25519 keypair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Save private key
        with open(priv_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key
        with open(pub_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        return private_key, public_key

    def _get_last_hash(self) -> str:
        """Find the hash of the last entry in the log, or return genesis hash."""
        if not self.log_file.exists():
            return GENESIS_HASH
        last_entry = None
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        last_entry = json.loads(line)
                    except Exception:
                        pass
        if last_entry and "entry_hash" in last_entry:
            return last_entry["entry_hash"]
        return GENESIS_HASH

    def _get_last_index(self) -> int:
        """Get the highest index in the log, or -1 if empty."""
        if not self.log_file.exists():
            return -1
        last_idx = -1
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        last_idx = max(last_idx, entry.get("index", -1))
                    except Exception:
                        pass
        return last_idx

    @staticmethod
    def canonical_json(data: Dict[str, Any]) -> bytes:
        """Produce canonical, deterministic JSON bytes for cryptographic hashing."""
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def log_event(self, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Record an event with hash-chaining and digital signature."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        index = self.current_index
        prev_hash = self.last_hash

        canonical_payload = {
            "index": index,
            "timestamp": timestamp,
            "event": event_type,
            "details": details,
            "prev_hash": prev_hash,
        }

        canonical_bytes = self.canonical_json(canonical_payload)
        entry_hash = hashlib.sha256(canonical_bytes).hexdigest()

        # Sign the entry hash with the Ed25519 private key
        signature = self.private_key.sign(entry_hash.encode("utf-8")).hex()

        full_entry = {
            **canonical_payload,
            "entry_hash": entry_hash,
            "signature": signature,
        }

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(full_entry) + "\n")

        self.last_hash = entry_hash
        self.current_index += 1
        return full_entry

    @classmethod
    def verify_log_file(
        cls,
        log_path: str | Path,
        public_key_path: Optional[str | Path] = None,
    ) -> Tuple[bool, str, Optional[int]]:
        """
        Verify the complete integrity of an audit log file:
        1. Hash chaining continuity (prev_hash == prior entry_hash)
        2. Canonical content SHA-256 hash match
        3. Ed25519 digital signature validity
        Returns (is_valid, message, first_corrupted_index).
        """
        log_file = Path(log_path)
        if not log_file.exists():
            return False, f"Audit log file not found: {log_file}", None

        # Load public key
        if public_key_path:
            pub_file = Path(public_key_path)
        else:
            pub_file = log_file.parent.parent / "keys" / "ed25519_public.pem"

        if not pub_file.exists():
            return False, f"Public key file not found: {pub_file}", None

        with open(pub_file, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        expected_prev_hash = GENESIS_HASH
        entry_count = 0

        with open(log_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                entry_count += 1
                try:
                    entry = json.loads(line)
                except Exception as e:
                    return False, f"Malformed JSON on line {line_no}: {str(e)}", line_no - 1

                index = entry.get("index", line_no - 1)
                prev_hash = entry.get("prev_hash")
                entry_hash = entry.get("entry_hash")
                sig_hex = entry.get("signature")

                # Check hash chain continuity
                if prev_hash != expected_prev_hash:
                    return (
                        False,
                        f"Chain broken at entry index {index} (line {line_no}): "
                        f"prev_hash '{prev_hash}' does not match expected '{expected_prev_hash}'.",
                        index,
                    )

                # Recompute canonical hash
                canonical_payload = {
                    "index": index,
                    "timestamp": entry.get("timestamp"),
                    "event": entry.get("event"),
                    "details": entry.get("details"),
                    "prev_hash": prev_hash,
                }
                computed_hash = hashlib.sha256(
                    cls.canonical_json(canonical_payload)
                ).hexdigest()

                if computed_hash != entry_hash:
                    return (
                        False,
                        f"Content tampering detected at entry index {index} (line {line_no}): "
                        f"recomputed hash '{computed_hash}' does not match recorded '{entry_hash}'.",
                        index,
                    )

                # Verify Ed25519 digital signature
                try:
                    sig_bytes = bytes.fromhex(sig_hex)
                    public_key.verify(sig_bytes, entry_hash.encode("utf-8"))  # type: ignore
                except Exception as e:
                    return (
                        False,
                        f"Cryptographic signature verification failed at entry index {index} (line {line_no}): {str(e)}",
                        index,
                    )

                expected_prev_hash = entry_hash

        if entry_count == 0:
            return True, "Audit log is empty (0 entries)", None

        return (
            True,
            f"Audit log verified: {entry_count} entries checked, hash chain intact, all Ed25519 signatures valid.",
            None,
        )
