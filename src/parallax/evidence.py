"""Synthetic forensic evidence generator for the Meridian Research incident.

Generates deterministic, pristine raw forensic artifacts:
1. EV-NET-001: Synthetic PULSE/1 communication transcript demonstrating the auth flaw.
2. EV-NET-002: Synthetic network capture metadata with documented -420s clock offset.
3. EV-CFG-001: Synthetic PULSE/1 service configuration snapshot (/etc/pulse/pulse.conf).
4. EV-SRV-001: Synthetic host service footprint inventory (/etc/systemd/inventory).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Meridian Research Scenario Constants
SCENARIO_NAME = "Meridian Research Incident"
INCIDENT_DATE = "2026-09-14"
ATTACKER_IP = "198.51.100.24"
ATTACKER_PORT = 49822
TARGET_IP = "10.0.4.15"
TARGET_PORT = 7741
TAP_DEVICE_ID = "TAP-MERIDIAN-01"
TAP_INTERFACE = "eth0-span"
TAP_CLOCK_OFFSET_SECONDS = -420
DAEMON_USER = "svc-pulse"
HELPER_PATH = "/usr/local/bin/pulse-helper"
CONFIG_PATH = "/etc/pulse/pulse.conf"
ARCHIVE_DIR = "/var/archive/meridian"
DIAG_TICKET = "DIAG-TKT-7741-ALPHA"
KEY_FRAGMENT = "meridian-vault-2024-fragA"


def generate_capture_metadata() -> dict[str, Any]:
    """Generate EV-NET-002: Upstream network tap capture metadata."""
    return {
        "evidence_id": "EV-NET-002",
        "scenario": SCENARIO_NAME,
        "artifact_format": "JSON",
        "source_system": TAP_DEVICE_ID,
        "tap_device_id": TAP_DEVICE_ID,
        "interface": TAP_INTERFACE,
        "location": "Rack 4, Switch DC2-SW01 (Upstream Optical Tap)",
        "capture_target": f"{TARGET_IP}:{TARGET_PORT}",
        "capture_start_utc": f"{INCIDENT_DATE}T03:14:00Z",
        "capture_end_utc": f"{INCIDENT_DATE}T03:16:00Z",
        "clock_sync_status": "DEGRADED",
        "clock_offset_seconds": TAP_CLOCK_OFFSET_SECONDS,
        "reference_sync": {
            "recorded_timestamp": f"{INCIDENT_DATE}T03:14:02.108422Z",
            "clock_offset_seconds": TAP_CLOCK_OFFSET_SECONDS,
            "calibrated_utc_timestamp": f"{INCIDENT_DATE}T03:21:02.108422Z",
        },
        "source_classification": "SYNTHETIC_METADATA",
        "calibration_note": (
            f"Hardware tap RTC drifted {TAP_CLOCK_OFFSET_SECONDS}s relative to workstation host NTP clock."
        ),
        "investigator_warning": (
            "Synthetic source metadata. A uniform timestamp difference alone must not be "
            "represented as definitive proof of its cause. Empirical corroboration against "
            "independent host event logs is required to substantiate time synchronization anomalies."
        ),
    }


def generate_pulse_transcript() -> str:
    """Generate EV-NET-001: Synthetic PULSE/1 communication transcript."""
    lines = [
        "# ============================================================================",
        "# PARALLAX FORENSIC EVIDENCE — PULSE/1 WIRE TRANSCRIPT",
        "# Evidence ID: EV-NET-001",
        f"# Tap Source:  {TAP_DEVICE_ID} ({TAP_INTERFACE})",
        f"# Capture Window (Tap RTC Time): {INCIDENT_DATE}T03:14:02Z to {INCIDENT_DATE}T03:15:06Z",
        f"# Note: Hardware tap clock reflects recorded offset: {TAP_CLOCK_OFFSET_SECONDS} seconds.",
        f"# Client: {ATTACKER_IP}:{ATTACKER_PORT} <---> Server: {TARGET_IP}:{TARGET_PORT}",
        "# Protocol: PULSE/1 (Magic: 0x50554c53, Version: 1)",
        "# ============================================================================",
        "",
        f"[{INCIDENT_DATE}T03:14:02.108422Z] TCP 3-WAY HANDSHAKE ESTABLISHED",
        f"  SRC: {ATTACKER_IP}:{ATTACKER_PORT} -> DST: {TARGET_IP}:{TARGET_PORT} [SYN, ACK]",
        "",
        f"[{INCIDENT_DATE}T03:14:02.115201Z] FRAME 1: CLIENT -> SERVER [HELLO / 0x01]",
        "  Length: 64 bytes",
        '  Payload: {"client": "pulse-cli/0.1.0", "protocol_version": 1, "session_mode": "interactive"}',
        "",
        f"[{INCIDENT_DATE}T03:14:02.118940Z] FRAME 2: SERVER -> CLIENT [STATUS / 0x03]",
        "  Length: 88 bytes",
        '  Payload: {"status": "ready", "service": "PULSE/1", "version": "0.1.0", "vulnerable_mode": true}',
        "",
        f"[{INCIDENT_DATE}T03:14:15.221045Z] FRAME 3: CLIENT -> SERVER [AUTH / 0x02]",
        "  Length: 63 bytes",
        f'  Payload: {{"username": "{DAEMON_USER}", "password": "WrongPasswordAttempt#99"}}',
        "",
        f"[{INCIDENT_DATE}T03:14:15.224810Z] FRAME 4: SERVER -> CLIENT [ERROR / 0x06]",
        "  Length: 46 bytes",
        '  Payload: {"error": "Authentication Failed", "code": 401}',
        "",
        f"[{INCIDENT_DATE}T03:14:28.401890Z] FRAME 5: CLIENT -> SERVER [READ_DIAG / 0x04]",
        "  Length: 27 bytes",
        '  Payload: {"section": "system_config"}',
        "",
        f"[{INCIDENT_DATE}T03:14:28.406120Z] FRAME 6: SERVER -> CLIENT [READ_DIAG / 0x04]",
        "  Length: 312 bytes",
        f'  Payload: {{"section": "system_config", "service": "PULSE/1", "version": "0.1.0", "daemon_user": "{DAEMON_USER}", "helper_path": "{HELPER_PATH}", "config_path": "{CONFIG_PATH}", "archive_directory": "{ARCHIVE_DIR}", "diagnostic_ticket": "{DIAG_TICKET}", "encryption_passphrase_fragment": "{KEY_FRAGMENT}"}}',
        "",
        f"[{INCIDENT_DATE}T03:15:05.894102Z] FRAME 7: CLIENT -> SERVER [CLOSE / 0x05]",
        "  Length: 28 bytes",
        '  Payload: {"reason": "client_finished"}',
        "",
        f"[{INCIDENT_DATE}T03:15:05.897300Z] FRAME 8: SERVER -> CLIENT [CLOSE / 0x05]",
        "  Length: 47 bytes",
        '  Payload: {"status": "closed", "message": "Session terminated"}',
        "",
        f"[{INCIDENT_DATE}T03:15:05.901240Z] TCP CONNECTION TERMINATED [FIN, ACK]",
        "# End of transcript (EV-NET-001)",
    ]
    return "\n".join(lines) + "\n"


def generate_service_config() -> str:
    """Generate EV-CFG-001: PULSE/1 daemon configuration file snapshot."""
    lines = [
        "# /etc/pulse/pulse.conf",
        "# Meridian Research PULSE/1 Telemetry Service Configuration",
        "# Seized during incident triage from host: meridian-lab (10.0.4.15)",
        "# Evidence ID: EV-CFG-001",
        "",
        "[daemon]",
        "service_name = PULSE/1",
        "listen_address = 0.0.0.0",
        f"listen_port = {TARGET_PORT}",
        f"user = {DAEMON_USER}",
        f"group = {DAEMON_USER}",
        "max_clients = 32",
        "client_timeout_seconds = 10.0",
        "log_level = INFO",
        "log_file = /var/log/pulse/pulse.log",
        "",
        "[maintenance]",
        f"helper_path = {HELPER_PATH}",
        f"archive_directory = {ARCHIVE_DIR}",
        "diagnostic_ticket_prefix = DIAG-TKT-7741",
        f"vault_key_fragment = {KEY_FRAGMENT}",
        "",
        "[security]",
        "enable_auth = true",
        "allow_diagnostic_unauth = false",
    ]
    return "\n".join(lines) + "\n"


def generate_service_inventory() -> dict[str, Any]:
    """Generate EV-SRV-001: Synthetic host service footprint inventory snapshot."""
    return {
        "evidence_id": "EV-SRV-001",
        "scenario": SCENARIO_NAME,
        "hostname": "meridian-lab",
        "system_ip": TARGET_IP,
        "collected_utc": f"{INCIDENT_DATE}T06:00:00Z",
        "collector": "triage-collector-v1.4",
        "description": "System service inventory captured during initial host forensic triage",
        "services": [
            {
                "name": "pulse.service",
                "description": "PULSE/1 Telemetry and Diagnostics Daemon",
                "state": "active",
                "main_pid": 1412,
                "user": DAEMON_USER,
                "listen_ports": [TARGET_PORT],
                "bind_address": "0.0.0.0",
                "binary_path": "/usr/local/bin/pulse-daemon",
                "config_file": CONFIG_PATH,
                "cgroup": "system.slice/pulse.service",
            }
        ],
    }


from parallax.manifest import write_manifests

ARTIFACT_METADATA: dict[str, dict[str, Any]] = {
    "raw/network/pulse_session.transcript": {
        "evidence_id": "EV-NET-001",
        "source_system": TAP_DEVICE_ID,
        "format": "text/transcript",
        "description": "Synthetic wire communication transcript of PULSE/1 session on port 7741",
    },
    "raw/network/capture.meta": {
        "evidence_id": "EV-NET-002",
        "source_system": TAP_DEVICE_ID,
        "format": "application/json",
        "description": "Synthetic network tap capture metadata documenting hardware clock offset (-420s)",
    },
    "raw/system/pulse.conf": {
        "evidence_id": "EV-CFG-001",
        "source_system": "meridian-lab",
        "format": "text/ini",
        "description": "Synthetic PULSE/1 daemon configuration file snapshot (/etc/pulse/pulse.conf)",
    },
    "raw/system/service_inventory.json": {
        "evidence_id": "EV-SRV-001",
        "source_system": "meridian-lab",
        "format": "application/json",
        "description": "Synthetic host service footprint inventory snapshot",
    },
}


def generate_evidence_index() -> str:
    """Generate markdown evidence index describing artifacts, origin, purpose, and limitations."""
    lines = [
        "# PARALLAX — Evidence Artifact Index",
        "",
        "This index documents all raw forensic artifacts collected for the **Meridian Research Incident** (Milestone 3).",
        "",
        "---",
        "",
        "## 1. Evidence Artifact Catalog",
        "",
        "| Evidence ID | Path | Format | Source System | Ground Truth Role | Integrity Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
        "| **`EV-NET-001`** | `raw/network/pulse_session.transcript` | `text/transcript` | `TAP-MERIDIAN-01` | PULSE/1 session wire transcript demonstrating auth flaw | Indexed in `manifest.json` |",
        "| **`EV-NET-002`** | `raw/network/capture.meta` | `application/json` | `TAP-MERIDIAN-01` | Optical tap metadata documenting -420s clock drift | Indexed in `manifest.json` |",
        "| **`EV-CFG-001`** | `raw/system/pulse.conf` | `text/ini` | `meridian-lab` | Service configuration snapshot (/etc/pulse/pulse.conf) | Indexed in `manifest.json` |",
        "| **`EV-SRV-001`** | `raw/system/service_inventory.json` | `application/json` | `meridian-lab` | Host service footprint inventory (/etc/systemd) | Indexed in `manifest.json` |",
        "",
        "---",
        "",
        "## 2. Artifact Details, Purpose & Limitations",
        "",
        "### EV-NET-001: PULSE/1 Communication Transcript (`raw/network/pulse_session.transcript`)",
        "- **Origin**: Upstream optical network tap `TAP-MERIDIAN-01` on SPAN interface `eth0-span`.",
        "- **Purpose**: Records the chronological wire-level exchange between client `198.51.100.24:49822` and host service `10.0.4.15:7741`. Demonstrates that after submitting invalid credentials (`AUTH`), the client successfully dispatched a `READ_DIAG` frame and received sensitive internal parameters (`helper_path`, `diagnostic_ticket`, `encryption_passphrase_fragment`).",
        "- **Facts vs Hypotheses**: The transcript establishes that an unauthenticated client received sensitive diagnostics over TCP port 7741. It does **not** prove the physical identity of the human attacker, nor does it establish whether the leaked helper was subsequently executed on the host.",
        "- **Limitations & Clock Skew**: Timestamps reflect the internal clock of the hardware tap, which was lagging true UTC by 420 seconds (7 minutes).",
        "",
        "### EV-NET-002: Upstream Network Tap Metadata (`raw/network/capture.meta`)",
        "- **Origin**: Management control-plane diagnostic export from tap appliance `TAP-MERIDIAN-01`.",
        "- **Purpose**: Documents the hardware capture environment, interface mapping, capture window, and clock synchronization status (`DEGRADED`, `clock_offset_seconds: -420`).",
        "- **Facts vs Hypotheses**: The metadata provides an empirical source statement regarding hardware RTC drift. **Important**: A uniform timestamp difference alone must not be represented as definitive proof of its cause; independent corroboration against host event logs is required.",
        "- **Limitations**: Control-plane metadata is an operational record, not an immutable cryptographic proof.",
        "",
        "### EV-CFG-001: PULSE/1 Service Configuration (`raw/system/pulse.conf`)",
        "- **Origin**: File seized from target host filesystem at `/etc/pulse/pulse.conf`.",
        "- **Purpose**: Confirms service operational parameters: TCP port `7741`, dedicated service user `svc-pulse`, maintenance helper path `/usr/local/bin/pulse-helper`, and archive repository `/var/archive/meridian`.",
        "- **Facts vs Hypotheses**: Demonstrates the intended on-disk configuration. Does not guarantee that runtime processes adhered to these parameters if configuration was modified or loaded dynamically.",
        "- **Limitations**: Static on-disk state snapshot.",
        "",
        "### EV-SRV-001: Service Inventory Snapshot (`raw/system/service_inventory.json`)",
        "- **Origin**: Output of automated initial triage script executed on `meridian-lab` (`10.0.4.15`).",
        "- **Purpose**: Corroborates that `pulse.service` was actively running under `MainPID=1412` and owned cgroup `system.slice/pulse.service`.",
        "- **Facts vs Hypotheses**: Confirms process existence and binding to port 7741 at the time of triage collection. Does not establish which specific requests PID 1412 handled.",
        "- **Limitations**: Point-in-time triage capture.",
        "",
        "---",
        "",
        "## 3. Evidence Integrity Verification",
        "",
        "All artifacts are cryptographically protected via SHA-256 manifests stored in `evidence/manifests/`.",
        "",
        "### POSIX Checksum Verification",
        "```bash",
        "cd evidence && sha256sum -c manifests/SHA256SUMS",
        "```",
        "",
        "### Automated Verification Tool",
        "```bash",
        "python3 -m parallax.verify",
        "```",
    ]
    return "\n".join(lines) + "\n"


def build_evidence_workspace(
    evidence_root: Path | str,
    write_manifest: bool = True,
) -> dict[str, Path]:
    """Populate pristine raw synthetic forensic evidence in the evidence workspace.

    Args:
        evidence_root: Root path to the evidence workspace directory.
        write_manifest: Whether to generate SHA256SUMS and manifest.json.

    Returns:
        Mapping of evidence IDs to their generated Path objects.
    """
    root = Path(evidence_root).resolve()
    raw_dir = root / "raw"
    net_dir = raw_dir / "network"
    sys_dir = raw_dir / "system"
    manifest_dir = root / "manifests"

    net_dir.mkdir(parents=True, exist_ok=True)
    sys_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)

    # 1. EV-NET-001: pulse_session.transcript
    p_transcript = net_dir / "pulse_session.transcript"
    p_transcript.write_text(generate_pulse_transcript(), encoding="utf-8")

    # 2. EV-NET-002: capture.meta
    p_meta = net_dir / "capture.meta"
    p_meta.write_text(
        json.dumps(generate_capture_metadata(), indent=2) + "\n",
        encoding="utf-8",
    )

    # 3. EV-CFG-001: pulse.conf
    p_conf = sys_dir / "pulse.conf"
    p_conf.write_text(generate_service_config(), encoding="utf-8")

    # 4. EV-SRV-001: service_inventory.json
    p_inv = sys_dir / "service_inventory.json"
    p_inv.write_text(
        json.dumps(generate_service_inventory(), indent=2) + "\n",
        encoding="utf-8",
    )

    # 5. Evidence Index: INDEX.md
    p_index = root / "INDEX.md"
    p_index.write_text(generate_evidence_index(), encoding="utf-8")

    results = {
        "EV-NET-001": p_transcript,
        "EV-NET-002": p_meta,
        "EV-CFG-001": p_conf,
        "EV-SRV-001": p_inv,
        "INDEX": p_index,
    }

    if write_manifest:
        sha_path, json_path = write_manifests(
            scan_dir=raw_dir,
            manifest_dir=manifest_dir,
            base_dir=root,
            scenario_name=SCENARIO_NAME,
            metadata_lookup=ARTIFACT_METADATA,
        )
        results["SHA256SUMS"] = sha_path
        results["manifest.json"] = json_path

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PARALLAX synthetic forensic evidence.")
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=Path("evidence"),
        help="Path to evidence workspace root (default: evidence)",
    )
    args = parser.parse_args()

    artifacts = build_evidence_workspace(args.evidence_root)
    print(f"[+] Successfully generated {len(artifacts)} synthetic evidence files:")
    for ev_id, path in artifacts.items():
        print(f"    - {ev_id}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
