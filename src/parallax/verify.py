"""Repeatable verification suite for PARALLAX Linux/ARM64 and local environments.

Verifies:
1. Package imports, metadata, and runtime platform detection.
2. Clean server startup, deterministic connection handling, and teardown.
3. Vulnerable PULSE/1 server exposes the unauthenticated READ_DIAG flaw.
4. Corrected PULSE/1 server rejects the unauthorized READ_DIAG query.
5. Existing demo suite executes without errors.
6. Integrity manifest generation and verification.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import platform
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any

import parallax
from parallax.manifest import calculate_sha256, generate_manifest, verify_manifest
from parallax.pulse.client import PulseClient
from parallax.pulse.constants import MessageType
from parallax.pulse.demo import run_demo_suite, run_flaw_demo
from parallax.pulse.server import PulseServer


@dataclasses.dataclass
class CheckResult:
    name: str
    passed: bool
    details: str


class LabVerifier:
    """Deterministic, repeatable verification checks for PARALLAX."""

    def __init__(self, host: str = "127.0.0.1", verbose: bool = False) -> None:
        self.host = host
        self.verbose = verbose
        self.results: list[CheckResult] = []

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"    [DEBUG] {msg}")

    def verify_environment(self) -> CheckResult:
        """Verify package import, version metadata, and report host platform info."""
        os_name = platform.system()
        arch = platform.machine()
        py_ver = platform.python_version()
        pkg_ver = getattr(parallax, "__version__", "unknown")

        details = f"OS={os_name}, Arch={arch}, Python={py_ver}, parallax={pkg_ver}"
        passed = bool(pkg_ver and pkg_ver != "unknown")
        return CheckResult("Environment and Package Metadata", passed, details)

    def verify_server_lifecycle(self) -> CheckResult:
        """Verify server binds to loopback, accepts connection, and releases socket deterministically."""
        server = PulseServer(host=self.host, port=0, vulnerable=False)
        server.start()
        bound_port = server.port

        if bound_port <= 0:
            server.stop()
            return CheckResult("Server Lifecycle", False, f"Invalid bound port: {bound_port}")

        self.log(f"Server ephemeral bind on port {bound_port}")

        # Connect client and send HELLO (server responds with STATUS)
        try:
            with PulseClient(host=self.host, port=bound_port, timeout=2.0) as client:
                hello = client.hello()
                if hello.msg_type != MessageType.STATUS:
                    return CheckResult("Server Lifecycle", False, f"Unexpected response: {hello}")
        finally:
            server.stop()

        # Verify deterministic socket release (no socket leak or hang)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            err = sock.connect_ex((self.host, bound_port))
            # connect_ex returns errno; non-zero indicates connection refused/closed
            if err == 0:
                sock.close()
                return CheckResult(
                    "Server Lifecycle",
                    False,
                    f"Port {bound_port} still listening after server.stop()",
                )
        finally:
            sock.close()

        return CheckResult(
            "Server Lifecycle & Teardown",
            True,
            f"Clean startup, HELLO exchange, and deterministic port release on {bound_port}",
        )

    def verify_vulnerable_flaw(self) -> CheckResult:
        """Verify vulnerable server reproduces the unauthenticated diagnostic access flaw."""
        with PulseServer(host=self.host, port=0, vulnerable=True) as server:
            with PulseClient(host=self.host, port=server.port, timeout=2.0) as client:
                res = run_flaw_demo(client, target_description="Verification Vulnerable Daemon")

                auth_resp = res["auth"]
                diag_resp = res["diag"]

                if auth_resp.msg_type != MessageType.ERROR:
                    return CheckResult(
                        "Vulnerable Flaw Reproduction",
                        False,
                        f"Expected AUTH failure, got {auth_resp.msg_type}",
                    )

                if diag_resp.msg_type != MessageType.READ_DIAG:
                    return CheckResult(
                        "Vulnerable Flaw Reproduction",
                        False,
                        f"Expected READ_DIAG success, got {diag_resp.msg_type}",
                    )

                helper_path = diag_resp.payload.get("helper_path")
                ticket = diag_resp.payload.get("diagnostic_ticket")
                if not helper_path or not ticket:
                    return CheckResult(
                        "Vulnerable Flaw Reproduction",
                        False,
                        f"Missing expected diagnostic telemetry: {diag_resp.payload}",
                    )

        return CheckResult(
            "Vulnerable Flaw Reproduction",
            True,
            f"Flaw verified: READ_DIAG permitted after failed AUTH (helper_path={helper_path})",
        )

    def verify_corrected_defense(self) -> CheckResult:
        """Verify corrected server rejects unauthenticated diagnostic access."""
        with PulseServer(host=self.host, port=0, vulnerable=False) as server:
            with PulseClient(host=self.host, port=server.port, timeout=2.0) as client:
                res = run_flaw_demo(client, target_description="Verification Corrected Daemon")

                auth_resp = res["auth"]
                diag_resp = res["diag"]

                if auth_resp.msg_type != MessageType.ERROR:
                    return CheckResult(
                        "Corrected Defense Enforcement",
                        False,
                        f"Expected AUTH failure, got {auth_resp.msg_type}",
                    )

                if diag_resp.msg_type != MessageType.ERROR:
                    return CheckResult(
                        "Corrected Defense Enforcement",
                        False,
                        f"Expected ERROR on READ_DIAG, got {diag_resp.msg_type}",
                    )

                code = diag_resp.payload.get("code")
                if code != 403:
                    return CheckResult(
                        "Corrected Defense Enforcement",
                        False,
                        f"Expected error code 403, got {code}",
                    )

        return CheckResult(
            "Corrected Defense Enforcement",
            True,
            "Defense verified: READ_DIAG rejected with 403 Forbidden after failed AUTH",
        )

    def verify_demo_suite(self) -> CheckResult:
        """Verify the existing demo suite executes without errors."""
        exit_code = run_demo_suite(host=self.host, port=None, mode="both")
        passed = (exit_code == 0)
        return CheckResult(
            "Demo Suite Execution",
            passed,
            "Self-contained demo suite completed both vulnerable and corrected modes",
        )

    def verify_manifest_subsystem(self) -> CheckResult:
        """Verify evidence manifest calculation and tamper detection."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            f1 = tmp_path / "sample.txt"
            f1.write_text("forensic synthetic sample\n", encoding="utf-8")

            manifest = generate_manifest(tmp_path, base_dir=tmp_path)
            is_valid, errors = verify_manifest(manifest, base_dir=tmp_path)
            if not is_valid:
                return CheckResult("Manifest Subsystem", False, f"Manifest validation failed: {errors}")

            # Tamper check
            f1.write_text("tampered data\n", encoding="utf-8")
            is_tampered_valid, _ = verify_manifest(manifest, base_dir=tmp_path)
            if is_tampered_valid:
                return CheckResult("Manifest Subsystem", False, "Tampering was not detected")

        return CheckResult(
            "Manifest Subsystem",
            True,
            "SHA-256 calculation, manifest generation, and tamper detection passed",
        )

    def verify_workspace_evidence(self) -> CheckResult:
        """Verify the integrity of existing raw forensic evidence artifacts."""
        ev_dir = Path("evidence").resolve()
        manifest_file = ev_dir / "manifests" / "manifest.json"
        if not manifest_file.is_file():
            return CheckResult(
                "Workspace Evidence Integrity",
                False,
                "Missing evidence/manifests/manifest.json",
            )

        with manifest_file.open("r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        is_valid, errors = verify_manifest(manifest_data, base_dir=ev_dir)
        if not is_valid:
            return CheckResult(
                "Workspace Evidence Integrity",
                False,
                f"Manifest verification failed: {errors}",
            )

        count = len(manifest_data.get("artifacts", []))
        return CheckResult(
            "Workspace Evidence Integrity",
            True,
            f"All {count} raw evidence artifacts verified against SHA-256 manifest",
        )

    def run_all(self) -> list[CheckResult]:
        """Run all verification checks in deterministic order."""
        checks = [
            self.verify_environment,
            self.verify_server_lifecycle,
            self.verify_vulnerable_flaw,
            self.verify_corrected_defense,
            self.verify_demo_suite,
            self.verify_manifest_subsystem,
            self.verify_workspace_evidence,
        ]

        self.results = []
        for check in checks:
            try:
                res = check()
            except Exception as err:
                res = CheckResult(check.__name__, False, f"Unhandled exception: {err}")
            self.results.append(res)
        return self.results


def run_verification(host: str = "127.0.0.1", verbose: bool = False) -> int:
    """CLI runner printing formatted status report."""
    print("=" * 70)
    print(" PARALLAX Investigation Foundation — Verification Suite")
    print("=" * 70)

    verifier = LabVerifier(host=host, verbose=verbose)
    results = verifier.run_all()

    all_passed = True
    for res in results:
        status_tag = "[PASS]" if res.passed else "[FAIL]"
        print(f"{status_tag} {res.name}")
        print(f"       Details: {res.details}")
        if not res.passed:
            all_passed = False

    print("=" * 70)
    if all_passed:
        print("[+] ALL VERIFICATION CHECKS PASSED.")
        return 0
    else:
        print("[!] VERIFICATION FAILED.")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="PARALLAX Lab Verification Suite")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    return run_verification(host=args.host, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
