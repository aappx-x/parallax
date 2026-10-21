"""Repeatable end-to-end offline investigation scenario test for PARALLAX Milestone 6.

Validates:
1. Deterministic synthetic evidence generation and SHA-256 manifest verification.
2. Vulnerable vs. corrected PULSE/1 protocol execution.
3. Strict prerequisite gating and rejection of incorrect findings without answer key disclosure.
4. Full investigation playthrough (P01–P14) unlocking final incident verdict (P15).
5. Comprehensive verdict report synthesis establishing true attacker entry vector,
   setuid helper privilege escalation, legitimate -420s optical tap clock drift,
   and multi-source exoneration of employee rhea.
6. Anti-tamper detection on modified evidence artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import pytest

from parallax.evidence import (
    FULL_VAULT_PASSPHRASE,
    VAULT_PLAINTEXT_HEADER,
    build_evidence_workspace,
)
from parallax.manifest import parse_sha256sums, verify_manifest, verify_sha256sums
from parallax.objectives import (
    OBJECTIVES,
    OBJECTIVES_BY_ID,
    ProgressTracker,
    generate_final_report,
    validate_submission,
)
from parallax.pulse.client import PulseClient
from parallax.pulse.server import PulseServer


def test_full_investigation_scenario_playthrough():
    """Execute complete end-to-end repeatable investigation playthrough."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ev_root = Path(tmp_dir) / "evidence"
        progress_file = Path(tmp_dir) / ".progress.json"

        # -----------------------------------------------------------------
        # 1. Generate pristine synthetic evidence and verify manifests
        # -----------------------------------------------------------------
        artifacts = build_evidence_workspace(ev_root, write_manifest=True)
        assert len(artifacts) >= 16

        manifest_path = ev_root / "manifests" / "manifest.json"
        sha_path = ev_root / "manifests" / "SHA256SUMS"
        assert manifest_path.is_file()
        assert sha_path.is_file()

        with manifest_path.open("r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        assert manifest_data["total_files"] == 16
        is_valid, errors = verify_manifest(manifest_data, base_dir=ev_root)
        assert is_valid is True, f"Manifest verification failed: {errors}"

        is_valid_sha, sha_errs = verify_sha256sums(sha_path.read_text(encoding="utf-8"), base_dir=ev_root)
        assert is_valid_sha is True, f"SHA256SUMS verification failed: {sha_errs}"

        # -----------------------------------------------------------------
        # 2. Exercise vulnerable and corrected PULSE protocol daemons
        # -----------------------------------------------------------------
        # Vulnerable daemon reproduction
        with PulseServer(host="127.0.0.1", port=0, vulnerable=True) as vuln_server:
            with PulseClient(host="127.0.0.1", port=vuln_server.port) as client:
                client.hello()
                client.auth(username="svc-pulse", password="invalid_password")
                # Flaw: READ_DIAG permitted after failed AUTH
                diag_resp = client.read_diag("system_config")
                assert diag_resp.payload.get("helper_path") == "/usr/local/bin/pulse-helper"
                assert "DIAG-TKT-7741-ALPHA" in diag_resp.payload.get("diagnostic_ticket", "")
                client.close_session()

        # Corrected daemon defense enforcement
        with PulseServer(host="127.0.0.1", port=0, vulnerable=False) as corr_server:
            with PulseClient(host="127.0.0.1", port=corr_server.port) as client:
                client.hello()
                client.auth(username="svc-pulse", password="invalid_password")
                # Defense: READ_DIAG rejected with 403
                corr_resp = client.read_diag("system_config")
                assert corr_resp.payload.get("code") == 403
                assert "Authentication required" in corr_resp.payload.get("error", "")
                client.close_session()

        # -----------------------------------------------------------------
        # 3. Initialize Progress Tracker & Test Negative / Rejection Cases
        # -----------------------------------------------------------------
        tracker = ProgressTracker(progress_file)

        # Negative test 1: Submitting locked objective (P02 before P01)
        res_locked = validate_submission("P02", "magic PULS", ["EV-NET-001"], tracker=tracker)
        assert res_locked.success is False
        assert "LOCKED" in res_locked.message

        # Negative test 2: Submitting wrong answer without leaking answer key
        res_wrong = validate_submission("P01", "port 8080", ["EV-CFG-001"], tracker=tracker)
        assert res_wrong.success is False
        assert "does not identify the correct TCP listening port" in res_wrong.message

        # Negative test 3: Submitting correct answer but missing required evidence ID
        res_no_ev = validate_submission("P01", "7741", ["EV-NET-001"], tracker=tracker)
        assert res_no_ev.success is False
        assert "requires at least one service configuration" in res_no_ev.message

        # -----------------------------------------------------------------
        # 4. Step-by-Step Playthrough: Objectives P01 through P14
        # -----------------------------------------------------------------
        ground_truth_answers = [
            ("P01", "TCP port 7741", ["EV-CFG-001", "EV-SRV-001"]),
            ("P02", "PULS magic bytes (0x50554c53)", ["EV-NET-001", "EV-NET-003"]),
            ("P03", "Attacker IP: 198.51.100.24", ["EV-NET-001", "EV-NET-003"]),
            ("P04", "Accepted unauthenticated READ_DIAG (0x04)", ["EV-NET-001", "EV-LOG-001"]),
            ("P05", "Timestamp delta is 420 seconds (7 minutes)", ["EV-NET-002", "EV-LOG-001"]),
            ("P06", "Optical tap hardware RTC drift (-420s) in metadata matches invariant delta across paired session events", ["EV-NET-002", "EV-LOG-001"]),
            ("P07", "Leaked helper /usr/local/bin/pulse-helper and token DIAG-TKT-7741-ALPHA (fragA)", ["EV-NET-001", "EV-NET-003"]),
            ("P08", "Dedicated user svc-pulse (UID 1002); helper is mode 4750 setuid root", ["EV-SYS-001", "EV-SYS-003"]),
            ("P09", "Unsafe argument --archive-check passed into system() call with root privileges", ["EV-SYS-003", "EV-CFG-001"]),
            ("P10", "Unlocked vault with fragB-sig9902 revealing header MERIDIAN-AERO-VAULT-v2.4", ["EV-DAT-001", "EV-DAT-002"]),
            ("P11", "Suspicious event serial 894 attributed tar command to rhea (auid=1001)", ["EV-LOG-002"]),
            ("P12", "Auth.log shows zero PAM sessions for rhea, wtmp shows zero active terminals, and history is clean", ["EV-LOG-003", "EV-LOG-004"]),
            ("P13", "Kernel audit event 892 shows pulse-helper (PID 1418) spawned by PULSE daemon (PPID 1412) under svc-pulse", ["EV-LOG-002", "EV-SRV-001"]),
            ("P14", "Orphan EXECVE record missing atomic kernel SYSCALL companion with unset ses=4294967295", ["EV-LOG-002"]),
        ]

        for obj_id, ans, ev_ids in ground_truth_answers:
            res = validate_submission(obj_id, ans, ev_ids, tracker=tracker)
            assert res.success is True, f"Failed objective {obj_id}: {res.message}"
            assert tracker.is_completed(obj_id)

        # -----------------------------------------------------------------
        # 5. Final Verdict Submission & Report Verification (P15)
        # -----------------------------------------------------------------
        # Check that P15 is now UNLOCKED
        p15 = OBJECTIVES_BY_ID["P15"]
        assert tracker.get_status(p15) == "UNLOCKED"

        verdict_text = (
            "1. Entry Point: External threat actor connecting from 198.51.100.24 to PULSE/1 on TCP 7741. "
            "Exploited state machine logic flaw where READ_DIAG queries were processed after 401 error. "
            "2. Privilege Escalation: Exploited command injection in setuid root helper /usr/local/bin/pulse-helper "
            "via unsanitized --archive-check input running as svc-pulse (PID 1418 spawned by PPID 1412). "
            "3. Clock Offset: Upstream optical tap TAP-MERIDIAN-01 had 420-second hardware RTC drift, confirmed by "
            "capture.meta and constant invariant deltas across 4 paired session milestones. "
            "4. Rhea Exoneration: Audit event 894 was a fabricated orphan EXECVE record injected via root shell. "
            "Rhea is exonerated by absent companion SYSCALL records, unset ses=4294967295, zero PAM sessions in "
            "auth.log, zero terminal sessions in wtmp, clean bash history, and authentic kernel audit records "
            "proving pulse-helper was executed by svc-pulse."
        )

        res_p15 = validate_submission(
            "P15",
            verdict_text,
            ["EV-NET-001", "EV-LOG-001", "EV-LOG-002", "EV-SYS-003"],
            tracker=tracker,
        )
        assert res_p15.success is True, f"P15 validation failed: {res_p15.message}"
        assert tracker.is_completed("P15")

        # Verify synthesized incident report
        report = generate_final_report(tracker=tracker)
        assert "MERIDIAN RESEARCH INCIDENT — FINAL INCIDENT VERDICT REPORT" in report
        assert "PULSE/1 daemon listening on TCP port 7741" in report
        assert "198.51.100.24" in report
        assert "4750" in report
        assert "420 seconds" in report
        assert "EMPLOYEE RHEA VANCE IS FULLY EXONERATED" in report
        for i in range(1, 16):
            assert f"[X] P{i:02d}:" in report

        # -----------------------------------------------------------------
        # 6. Anti-Tamper Verification
        # -----------------------------------------------------------------
        # Modifying any evidence file must cause manifest verification to fail
        audit_file = ev_root / "raw" / "logs" / "audit.log"
        original_bytes = audit_file.read_bytes()
        audit_file.write_bytes(original_bytes + b"\n# Tampered line\n")

        tampered_valid, tampered_errs = verify_manifest(manifest_data, base_dir=ev_root)
        assert tampered_valid is False
        assert any("audit.log" in err for err in tampered_errs)
