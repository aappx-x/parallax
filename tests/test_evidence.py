"""Tests for synthetic forensic evidence generation, structure, and integrity verification."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

from parallax.evidence import (
    ARTIFACT_METADATA,
    ATTACKER_IP,
    DAEMON_USER,
    FULL_VAULT_PASSPHRASE,
    HELPER_PATH,
    KEY_FRAGMENT,
    TAP_CLOCK_OFFSET_SECONDS,
    TAP_DEVICE_ID,
    TARGET_PORT,
    VAULT_PLAINTEXT_HEADER,
    build_evidence_workspace,
    decrypt_vault,
    generate_audit_log,
    generate_auth_log,
    generate_capture_metadata,
    generate_daemon_log,
    generate_diag_ticket,
    generate_encrypted_vault,
    generate_evidence_index,
    generate_file_permissions,
    generate_group,
    generate_passwd,
    generate_pcap_capture,
    generate_pulse_service_unit,
    generate_pulse_transcript,
    generate_rhea_bash_history,
    generate_service_config,
    generate_service_inventory,
    generate_wtmp_sessions,
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

    def test_pcap_capture_binary_structure(self):
        pcap_data = generate_pcap_capture()
        assert len(pcap_data) > 100
        # Check standard libpcap magic header (0xa1b2c3d4)
        assert pcap_data[:4] == b"\xd4\xc3\xb2\xa1"
        # Check that PULS magic frames exist inside the TCP payloads
        assert b"PULS\x01\x01" in pcap_data
        assert b"PULS\x01\x04" in pcap_data
        assert KEY_FRAGMENT.encode("utf-8") in pcap_data

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

    def test_audit_log_records_genuine_and_forged(self):
        audit = generate_audit_log()
        # Genuine kernel audit record: event 892 for pulse-helper under svc-pulse (uid 1002, ppid 1412)
        assert 'msg=audit(1726305672.390:892)' in audit
        assert 'exe="/usr/local/bin/pulse-helper"' in audit
        assert 'uid=1002' in audit
        assert 'euid=0' in audit
        assert 'ppid=1412' in audit
        assert 'pid=1418' in audit

        # Forged record: event 894 framing rhea (auid 1001, ses=4294967295)
        assert 'msg=audit(1726305672.410:894)' in audit
        assert 'auid=1001' in audit
        assert 'ses=4294967295' in audit
        assert 'a0="tar"' in audit
        assert 'a2="/var/archive/meridian/research_vault.tar.gz"' in audit
        # Verify absence of companion SYSCALL record for event 894
        assert 'type=SYSCALL msg=audit(1726305672.410:894)' not in audit

    def test_daemon_log_timestamps_and_pairing(self):
        log = generate_daemon_log()
        assert "03:21:02.108422Z" in log
        assert "03:21:15.221045Z" in log
        assert "03:21:28.401890Z" in log
        assert "03:22:05.894102Z" in log
        assert "Authentication failed" in log
        assert "Dispatched system_config diagnostic payload" in log

    def test_auth_log_and_wtmp_alibi(self):
        auth_log = generate_auth_log()
        assert "analyst" in auth_log
        assert "rhea" not in auth_log

        wtmp = generate_wtmp_sessions()
        assert wtmp["historical_sessions_summary"]["rhea"]["sessions_on_incident_date"] == 0

    def test_system_accounts_and_permissions(self):
        passwd = generate_passwd()
        assert "analyst:x:1000:1000:" in passwd
        assert "rhea:x:1001:1001:" in passwd
        assert f"{DAEMON_USER}:x:1002:1002:" in passwd

        group = generate_group()
        assert "systemd-journal:x:101:analyst" in group

        perms = generate_file_permissions()
        helper_perm = perms["paths"][HELPER_PATH]
        assert helper_perm["mode_octal"] == "4750"
        assert helper_perm["setuid"] is True

        rhea_hist = generate_rhea_bash_history()
        assert "tar" not in rhea_hist

    def test_encrypted_vault_and_key_recovery(self):
        enc_data = generate_encrypted_vault()
        assert enc_data.startswith(b"Salted__")
        decrypted = decrypt_vault(enc_data, FULL_VAULT_PASSPHRASE)
        assert VAULT_PLAINTEXT_HEADER.encode("utf-8") in decrypted

        ticket = generate_diag_ticket()
        assert ticket["key_derivation"]["combined_passphrase"] == FULL_VAULT_PASSPHRASE

    def test_evidence_index_content(self):
        index = generate_evidence_index()
        for ev_id in ("EV-NET-001", "EV-NET-002", "EV-NET-003", "EV-LOG-001", "EV-LOG-002",
                      "EV-CFG-001", "EV-SRV-001", "EV-SYS-001", "EV-DAT-001"):
            assert ev_id in index
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

            for key in res1:
                if key == "manifest.json":
                    continue
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

            assert manifest_data["total_files"] == len(ARTIFACT_METADATA)
            is_valid, errors = verify_manifest(manifest_data, base_dir=ev_root)
            assert is_valid is True, f"Manifest verification failed: {errors}"
            assert len(errors) == 0

            # Test standard sha256sums file verification
            sha_sums_path = ev_root / "manifests" / "SHA256SUMS"
            assert sha_sums_path.is_file()
            sha_content = sha_sums_path.read_text(encoding="utf-8")
            parsed = parse_sha256sums(sha_content)
            assert len(parsed) == len(ARTIFACT_METADATA)

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

            # Remove one of the files
            conf_file = ev_root / "raw" / "system" / "pulse.conf"
            conf_file.unlink()

            is_valid, errors = verify_manifest(manifest_data, base_dir=ev_root)
            assert is_valid is False
            assert any("pulse.conf" in err for err in errors)
            assert any("Missing file" in err for err in errors)

    def test_regeneration_preserves_notes_and_derived(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_root = Path(tmp_dir)
            build_evidence_workspace(ev_root, write_manifest=True)

            # Create user note and derived file
            user_note = ev_root / "notes" / "analyst_scratchpad.txt"
            user_note.write_text("Investigator hypothesis notes", encoding="utf-8")
            derived_file = ev_root / "derived" / "timeline.csv"
            derived_file.write_text("timestamp,event", encoding="utf-8")

            # Rebuild evidence workspace
            build_evidence_workspace(ev_root, write_manifest=True)

            assert user_note.is_file()
            assert user_note.read_text(encoding="utf-8") == "Investigator hypothesis notes"
            assert derived_file.is_file()
            assert derived_file.read_text(encoding="utf-8") == "timestamp,event"
