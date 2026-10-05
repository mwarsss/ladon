#!/usr/bin/env python3
"""
CLI Tool: Verify the integrity of the Ladon tamper-evident audit log.

Checks:
1. Hash chain continuity across all records
2. SHA-256 canonical hash verification per record
3. Ed25519 public key digital signature verification
"""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ladon.audit import AuditLogger


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify Ladon audit log cryptographic integrity."
    )
    parser.add_argument(
        "--log",
        type=str,
        default=str(PROJECT_ROOT / "logs" / "audit.jsonl"),
        help="Path to the audit log file",
    )
    parser.add_argument(
        "--pubkey",
        type=str,
        default=str(PROJECT_ROOT / "keys" / "ed25519_public.pem"),
        help="Path to the Ed25519 public key PEM file",
    )
    args = parser.parse_args()

    log_path = Path(args.log)
    pub_path = Path(args.pubkey)

    print(f"\n==================================================")
    print(f" LADON AUDIT LOG INTEGRITY VERIFIER")
    print(f" Target Log : {log_path}")
    print(f" Public Key : {pub_path}")
    print(f"==================================================\n")

    is_valid, message, broken_index = AuditLogger.verify_log_file(
        log_path=log_path, public_key_path=pub_path
    )

    if is_valid:
        print(f" [✓] VERIFICATION PASSED")
        print(f"     {message}\n")
        sys.exit(0)
    else:
        print(f" [!] TAMPERING DETECTED")
        print(f"     Broken Entry Index : {broken_index}")
        print(f"     Details            : {message}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
