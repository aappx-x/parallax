"""Tests for synthetic forensic evidence generation, structure, and integrity verification."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

from parallax.evidence import (
    ATTACKER_IP,
    DAEMON_USER,
    HELPER_PATH,
    KEY_FRAGMENT,
    TAP_CLOCK_OFFSET_SECONDS,
    TAP_DEVICE_ID,
    TARGET_PORT,
    build_evidence_workspace,
    generate_capture_metadata,
    generate_evidence_index,
    generate_pulse_transcript,
    generate_service_config,
    generate_service_inventory,
)
from parallax.manifest import (
    calculate_sha256,
    generate_manifest,
    parse_sha256sums,
    verify_manifest,
    verify_sha256sums,
)


class TestEvidenceArtifactGeneration:
    """Test individual artifact structure and required incident metadata."""

    def test_capture_metadata_structure(self):
        meta = generate_capture_metadata()
        assert meta["evidence_id"] == "EV-NET-002"
        assert meta["tap_device_id"] == TAP_DEVICE_ID
        assert meta["clock_offset_seconds"] == TAP_CLOCK_OFFSET_SECONDS
        assert meta["clock_offset_seconds"] == -420
        assert meta["clock_sync_status"] == "DEGRADED"
        assert meta["source_classification"] == "SYNTHETIC_METADATA"
        assert "reference_sync" in meta
        assert meta["reference_sync"]["clock_offset_seconds"] == -420
        assert "investigator_warning" in meta
        assert "definitive proof" in meta["investigator_warning"].lower()

    def test_pulse_transcript_content_and_flaw(self):
        transcript = generate_pulse_transcript()
        assert "EV-NET-001" in transcript
        assert ATTACKER_IP in transcript
        assert str(TARGET_PORT) in transcript
        assert DAEMON_USER in transcript

        # Protocol sequence
        assert "CLIENT -> SERVER [HELLO / 0x01]" in transcript
        assert "SERVER -> CLIENT [STATUS / 0x03]" in transcript
        assert "CLIENT -> SERVER [AUTH / 0x02]" in transcript
        assert "Authentication Failed" in transcript
        assert "CLIENT -> SERVER [READ_DIAG / 0x04]" in transcript
        assert HELPER_PATH in transcript
        assert KEY_FRAGMENT in transcript
        assert "CLIENT -> SERVER [CLOSE / 0x05]" in transcript

    def test_service_config_structure(self):
        config = generate_service_config()
        assert "EV-CFG-001" in config
        assert f"listen_port = {TARGET_PORT}" in config
        assert f"user = {DAEMON_USER}" in config
        assert f"helper_path = {HELPER_PATH}" in config
        assert "archive_directory = /var/archive/meridian" in config

    def test_service_inventory_structure(self):
        inv = generate_service_inventory()
        assert inv["evidence_id"] == "EV-SRV-001"
        assert inv["hostname"] == "meridian-lab"
        assert inv["system_ip"] == "10.0.4.15"

        services = inv["services"]
        assert len(services) >= 1
        pulse_svc = services[0]
        assert pulse_svc["name"] == "pulse.service"
        assert pulse_svc["user"] == DAEMON_USER
        assert TARGET_PORT in pulse_svc["listen_ports"]
        assert pulse_svc["main_pid"] == 1412
        assert "cgroup" in pulse_svc

    def test_evidence_index_content(self):
        index = generate_evidence_index()
        assert "EV-NET-001" in index
        assert "EV-NET-002" in index
        assert "EV-CFG-001" in index
        assert "EV-SRV-001" in index
        assert "Facts vs Hypotheses" in index
        assert "Limitations & Clock Skew" in index


class TestEvidenceWorkspaceAndManifest:
    """Test evidence workspace building, deterministic hashes, and manifest verification."""

    def test_deterministic_generation(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            p1 = Path(d1)
            p2 = Path(d2)

            res1 = build_evidence_workspace(p1, write_manifest=True)
            res2 = build_evidence_workspace(p2, write_manifest=True)

            for key in ("EV-NET-001", "EV-NET-002", "EV-CFG-001", "EV-SRV-001", "INDEX", "SHA256SUMS"):
                bytes1 = res1[key].read_bytes()
                bytes2 = res2[key].read_bytes()
                assert bytes1 == bytes2, f"Artifact {key} differed across builds"

    def test_manifest_verification_success(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_root = Path(tmp_dir)
            build_evidence_workspace(ev_root, write_manifest=True)

            manifest_json_path = ev_root / "manifests" / "manifest.json"
            assert manifest_json_path.is_file()

            with manifest_json_path.open("r", encoding="utf-8") as f:
                manifest_data = json.load(f)

            assert manifest_data["total_files"] == 4
            is_valid, errors = verify_manifest(manifest_data, base_dir=ev_root)
            assert is_valid is True, f"Manifest verification failed: {errors}"
            assert len(errors) == 0

            # Test standard sha256sums file verification
            sha_sums_path = ev_root / "manifests" / "SHA256SUMS"
            assert sha_sums_path.is_file()
            sha_content = sha_sums_path.read_text(encoding="utf-8")
            parsed = parse_sha256sums(sha_content)
            assert len(parsed) == 4

            is_valid_sha, errors_sha = verify_sha256sums(sha_content, base_dir=ev_root)
            assert is_valid_sha is True
            assert len(errors_sha) == 0

    def test_tamper_detection_on_evidence_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_root = Path(tmp_dir)
            build_evidence_workspace(ev_root, write_manifest=True)

            manifest_json_path = ev_root / "manifests" / "manifest.json"
            with manifest_json_path.open("r", encoding="utf-8") as f:
                manifest_data = json.load(f)

            # Tamper with the transcript file
            transcript_file = ev_root / "raw" / "network" / "pulse_session.transcript"
            original_content = transcript_file.read_text(encoding="utf-8")
            transcript_file.write_text(original_content + "\n# MALICIOUS TAMPERING INJECTION\n", encoding="utf-8")

            is_valid, errors = verify_manifest(manifest_data, base_dir=ev_root)
            assert is_valid is False
            assert any("pulse_session.transcript" in err for err in errors)
            assert any("Checksum mismatch" in err for err in errors)

    def test_missing_file_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_root = Path(tmp_dir)
            build_evidence_workspace(ev_root, write_manifest=True)

            manifest_json_path = ev_root / "manifests" / "manifest.json"
            with manifest_json_path.open("r", encoding="utf-8") as f:
                manifest_data = json.load(f)

            # Delete a file
            conf_file = ev_root / "raw" / "system" / "pulse.conf"
            conf_file.unlink()

            is_valid, errors = verify_manifest(manifest_data, base_dir=ev_root)
            assert is_valid is False
            assert any("Missing file" in err for err in errors)
            assert any("pulse.conf" in err for err in errors)


class TestRepositoryEvidenceWorkspace:
    """Validate that the active repository evidence workspace is valid and pristine."""

    def test_repo_evidence_workspace_integrity(self):
        repo_root = Path(__file__).resolve().parent.parent
        ev_dir = repo_root / "evidence"

        manifest_file = ev_dir / "manifests" / "manifest.json"
        assert manifest_file.is_file(), "Repository is missing evidence/manifests/manifest.json"

        with manifest_file.open("r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        is_valid, errors = verify_manifest(manifest_data, base_dir=ev_dir)
        assert is_valid is True, f"Repository evidence workspace failed validation: {errors}"
        assert manifest_data["total_files"] == 4
