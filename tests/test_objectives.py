"""Unit tests for the PARALLAX investigation objectives registry and validation engine."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from parallax.objectives import (
    OBJECTIVES,
    OBJECTIVES_BY_ID,
    ProgressTracker,
    generate_final_report,
    validate_submission,
)


class TestObjectivesRegistry:
    """Verify objective metadata, prerequisites graph, and catalog integrity."""

    def test_objective_count_and_ids(self):
        assert len(OBJECTIVES) == 15
        expected_ids = [f"P{i:02d}" for i in range(1, 16)]
        actual_ids = [obj.id for obj in OBJECTIVES]
        assert actual_ids == expected_ids

    def test_prerequisite_graph_validity(self):
        all_ids = set(OBJECTIVES_BY_ID.keys())
        for obj in OBJECTIVES:
            for prereq in obj.prerequisites:
                assert prereq in all_ids, f"Objective {obj.id} has unknown prerequisite: {prereq}"
                assert prereq != obj.id, f"Self-referential prerequisite in {obj.id}"

        # P15 must require all P01 through P14
        p15 = OBJECTIVES_BY_ID["P15"]
        assert len(p15.prerequisites) == 14
        for i in range(1, 15):
            assert f"P{i:02d}" in p15.prerequisites

    def test_required_evidence_ids_non_empty(self):
        for obj in OBJECTIVES:
            assert len(obj.required_evidence_ids) >= 1, f"Objective {obj.id} has no required evidence IDs"


class TestObjectiveValidationRules:
    """Test individual deterministic validation rules (correct and rejected inputs)."""

    def test_p01_validation(self):
        obj = OBJECTIVES_BY_ID["P01"]
        # Correct with valid evidence
        res = obj.validator("The service was bound to port 7741", ["EV-CFG-001"])
        assert res.success is True
        assert "7741" in res.finding

        # Incorrect port
        res_bad = obj.validator("Listening on port 8080", ["EV-CFG-001"])
        assert res_bad.success is False
        assert "does not identify the correct TCP listening port" in res_bad.message

        # Missing required evidence ID
        res_no_ev = obj.validator("7741", ["EV-NET-001"])
        assert res_no_ev.success is False
        assert "requires at least one service configuration" in res_no_ev.message

    def test_p02_validation(self):
        obj = OBJECTIVES_BY_ID["P02"]
        res = obj.validator("4-byte magic is PULS (0x50554c53)", ["EV-NET-001"])
        assert res.success is True

        res_bad = obj.validator("Magic identifier is HTTP", ["EV-NET-001"])
        assert res_bad.success is False

    def test_p03_validation(self):
        obj = OBJECTIVES_BY_ID["P03"]
        res = obj.validator("Attacker client IP: 198.51.100.24", ["EV-NET-001"])
        assert res.success is True

        res_bad = obj.validator("Client IP was 10.0.0.1", ["EV-NET-001"])
        assert res_bad.success is False

    def test_p04_validation(self):
        obj = OBJECTIVES_BY_ID["P04"]
        res = obj.validator("The daemon processed READ_DIAG (0x04) without authentication", ["EV-NET-001"])
        assert res.success is True

        res_bad = obj.validator("It allowed STATUS frame", ["EV-NET-001"])
        assert res_bad.success is False

    def test_p05_validation(self):
        obj = OBJECTIVES_BY_ID["P05"]
        res = obj.validator("Difference is 420 seconds (7 minutes)", ["EV-NET-002"])
        assert res.success is True

        res_bad = obj.validator("Delta is 3600 seconds", ["EV-NET-002"])
        assert res_bad.success is False

    def test_p06_validation(self):
        obj = OBJECTIVES_BY_ID["P06"]
        res = obj.validator(
            "Optical tap hardware RTC drift documented in tap metadata matches invariant delta across paired session events",
            ["EV-NET-002", "EV-LOG-001"]
        )
        assert res.success is True

        # Incomplete answer lacking corroboration
        res_bad = obj.validator("Host was timestomped", ["EV-NET-002"])
        assert res_bad.success is False

    def test_p07_validation(self):
        obj = OBJECTIVES_BY_ID["P07"]
        res = obj.validator(
            "Leaked helper path /usr/local/bin/pulse-helper and diagnostic ticket DIAG-TKT-7741-ALPHA",
            ["EV-NET-001"]
        )
        assert res.success is True

        res_bad = obj.validator("Leaked only password", ["EV-NET-001"])
        assert res_bad.success is False

    def test_p08_validation(self):
        obj = OBJECTIVES_BY_ID["P08"]
        res = obj.validator(
            "Service identity is svc-pulse (UID 1002); helper is mode 4750 setuid root",
            ["EV-SYS-001", "EV-SYS-003"]
        )
        assert res.success is True

        res_bad = obj.validator("Runs as root directly", ["EV-SYS-001"])
        assert res_bad.success is False

    def test_p09_validation(self):
        obj = OBJECTIVES_BY_ID["P09"]
        res = obj.validator(
            "Command injection in --archive-check argument executed unsafely via system() call under setuid root",
            ["EV-SYS-003", "EV-CFG-001"]
        )
        assert res.success is True

        res_bad = obj.validator("Buffer overflow in heap", ["EV-SYS-003"])
        assert res_bad.success is False

    def test_p10_validation(self):
        obj = OBJECTIVES_BY_ID["P10"]
        res = obj.validator(
            "Unlocked with fragB-sig9902 revealing header MERIDIAN-AERO-VAULT-v2.4",
            ["EV-DAT-001", "EV-DAT-002"]
        )
        assert res.success is True

        res_bad = obj.validator("Plaintext was secret_flag_123", ["EV-DAT-001", "EV-DAT-002"])
        assert res_bad.success is False

    def test_p11_validation(self):
        obj = OBJECTIVES_BY_ID["P11"]
        res = obj.validator("Audit event serial 894 attributed tar command to rhea (auid=1001)", ["EV-LOG-002"])
        assert res.success is True

        res_bad = obj.validator("Event 100 executed by root", ["EV-LOG-002"])
        assert res_bad.success is False

    def test_p12_validation(self):
        obj = OBJECTIVES_BY_ID["P12"]
        res = obj.validator(
            "PAM auth.log shows zero sessions opened for rhea, wtmp shows no interactive terminal allocations, and history is clean",
            ["EV-LOG-003", "EV-LOG-004"]
        )
        assert res.success is True

        # Only one evidence source supplied
        res_single_ev = obj.validator("rhea has alibi", ["EV-LOG-003"])
        assert res_single_ev.success is False
        assert "requires at least two independent corroborating sources" in res_single_ev.message

    def test_p13_validation(self):
        obj = OBJECTIVES_BY_ID["P13"]
        res = obj.validator(
            "Pulse-helper (child PID 1418) was spawned by PULSE/1 daemon (PPID 1412) under svc-pulse",
            ["EV-LOG-002", "EV-SRV-001"]
        )
        assert res.success is True

        res_bad = obj.validator("Spawned by bash PID 999", ["EV-LOG-002"])
        assert res_bad.success is False

    def test_p14_validation(self):
        obj = OBJECTIVES_BY_ID["P14"]
        res = obj.validator(
            "Event 894 is an orphan EXECVE record missing atomic kernel SYSCALL and PROCTITLE records, with unset ses=4294967295",
            ["EV-LOG-002"]
        )
        assert res.success is True

        res_bad = obj.validator("Log file had bad permissions", ["EV-LOG-002"])
        assert res_bad.success is False


class TestProgressTrackingAndPrerequisites:
    """Test progress state persistence, prerequisite enforcement, and final verdict unlock."""

    def test_prerequisite_gating_and_progression(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            progress_file = Path(tmp_dir) / ".progress.json"
            tracker = ProgressTracker(progress_file)

            # Initially P01 is unlocked, P02 is locked
            assert tracker.get_status(OBJECTIVES_BY_ID["P01"]) == "UNLOCKED"
            assert tracker.get_status(OBJECTIVES_BY_ID["P02"]) == "LOCKED"

            # Attempting to submit P02 while locked is rejected
            res_locked = validate_submission("P02", "magic PULS", ["EV-NET-001"], tracker=tracker)
            assert res_locked.success is False
            assert "is LOCKED" in res_locked.message

            # Solve P01
            res_p01 = validate_submission("P01", "port 7741", ["EV-CFG-001"], tracker=tracker)
            assert res_p01.success is True
            assert tracker.is_completed("P01")

            # Now P02 is unlocked
            assert tracker.get_status(OBJECTIVES_BY_ID["P02"]) == "UNLOCKED"

            # Solve P02
            res_p02 = validate_submission("P02", "magic PULS", ["EV-NET-001"], tracker=tracker)
            assert res_p02.success is True
            assert tracker.is_completed("P02")

    def test_final_verdict_locked_until_all_preceding_complete(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            progress_file = Path(tmp_dir) / ".progress.json"
            tracker = ProgressTracker(progress_file)

            # Mark P01 through P13 as complete, leaving P14 incomplete
            for i in range(1, 14):
                tracker.mark_completed(f"P{i:02d}", ["EV-CFG-001"], "Sample finding")

            # P15 remains locked because P14 is incomplete
            p15 = OBJECTIVES_BY_ID["P15"]
            assert tracker.get_status(p15) == "LOCKED"
            res_locked = validate_submission(
                "P15",
                "attacker pulse 7741 setuid helper drift 420 rhea exonerated",
                ["EV-NET-001"],
                tracker=tracker,
            )
            assert res_locked.success is False
            assert "P14" in res_locked.message

            # Mark P14 complete
            tracker.mark_completed("P14", ["EV-LOG-002"], "Tampering finding")
            assert tracker.get_status(p15) == "UNLOCKED"

            # Solve P15
            res_p15 = validate_submission(
                "P15",
                "External attacker targeted PULSE/1 TCP 7741 from 198.51.100.24. "
                "Exploited setuid pulse-helper --archive-check command injection under svc-pulse. "
                "7-minute timestamp offset explained by 420s optical tap RTC drift in capture.meta. "
                "Rhea is exonerated against fabricated orphan audit record with multi-source alibi.",
                ["EV-NET-001", "EV-LOG-001", "EV-LOG-002", "EV-SYS-003"],
                tracker=tracker,
            )
            assert res_p15.success is True
            assert tracker.is_completed("P15")

            # Final report can be generated
            report = generate_final_report(tracker=tracker)
            assert "OFFICIAL FORENSIC SYNTHESIS" in report
            assert "EMPLOYEE RHEA VANCE IS FULLY EXONERATED" in report
