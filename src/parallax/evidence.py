"""Synthetic forensic evidence generator for the Meridian Research incident.

Generates deterministic, pristine raw forensic artifacts:
1. EV-NET-001: Synthetic PULSE/1 communication transcript demonstrating the auth flaw.
2. EV-NET-002: Synthetic network capture metadata with documented -420s clock offset.
3. EV-NET-003: Synthetic raw packet capture (PCAP) with wire-level PULSE/1 frames.
4. EV-LOG-001: Synthetic host application log (/var/log/pulse/pulse.log).
5. EV-LOG-002: Synthetic Linux audit log (/var/log/audit/audit.log) with manipulated record.
6. EV-LOG-003: Synthetic PAM authentication log (/var/log/auth.log) establishing rhea's alibi.
7. EV-LOG-004: Synthetic terminal session history (/var/log/wtmp.json).
8. EV-CFG-001: Synthetic PULSE/1 daemon configuration snapshot (/etc/pulse/pulse.conf).
9. EV-CFG-002: Synthetic systemd unit definition (/etc/systemd/system/pulse.service).
10. EV-SRV-001: Synthetic host service footprint inventory (/etc/systemd/inventory).
11. EV-SYS-001: Synthetic user database snapshot (/etc/passwd).
12. EV-SYS-002: Synthetic group database snapshot (/etc/group).
13. EV-SYS-003: Synthetic file ownership & permissions inventory (/etc/security/file_permissions.json).
14. EV-USR-001: Synthetic user shell history (/home/rhea/.bash_history).
15. EV-DAT-001: Synthetic encrypted archive (/var/archive/meridian/research_vault.tar.gz.enc).
16. EV-DAT-002: Synthetic transient diagnostic ticket (/var/tmp/.diag_ticket).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
from typing import Any

from parallax.manifest import write_manifests

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
KEY_FRAGMENT_B = "fragB-sig9902"
FULL_VAULT_PASSPHRASE = f"{KEY_FRAGMENT}:{KEY_FRAGMENT_B}"
VAULT_PLAINTEXT_HEADER = "MERIDIAN-AERO-VAULT-v2.4"


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


def generate_pcap_capture() -> bytes:
    """Generate EV-NET-003: Synthetic standard libpcap packet capture.

    Contains full Ethernet, IPv4, TCP packets corresponding exactly to
    the 8 PULSE/1 frames, 3-way handshake, and connection termination.
    Timestamps match tap RTC time (starting at 03:14:02.108422Z).
    """
    def _ip_checksum(data: bytes) -> int:
        if len(data) % 2 == 1:
            data += b"\x00"
        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    # Base tap epoch (corresponding to 2026-09-14 03:14:02.108422Z)
    base_ts = 1726305242.108422

    client_ip = ATTACKER_IP
    server_ip = TARGET_IP
    client_port = ATTACKER_PORT
    server_port = TARGET_PORT

    client_mac = bytes.fromhex("00163e516418")
    server_mac = bytes.fromhex("00163e000415")

    def _make_frame(ts: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
        src_mac = client_mac if src_ip == client_ip else server_mac
        dst_mac = server_mac if src_ip == client_ip else client_mac
        eth = dst_mac + src_mac + struct.pack("!H", 0x0800)

        total_len = 20 + 20 + len(payload)
        ip_hdr_no_chk = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0x00, total_len, 1001, 0x4000, 64, 6, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )
        ip_chk = _ip_checksum(ip_hdr_no_chk)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0x00, total_len, 1001, 0x4000, 64, 6, ip_chk,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )

        tcp_hdr_no_chk = struct.pack(
            "!HHIIHHHH",
            src_port, dst_port, seq, ack, (5 << 12) | flags, 65535, 0, 0,
        )
        pseudo_hdr = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, 20 + len(payload),
        )
        tcp_chk = _ip_checksum(pseudo_hdr + tcp_hdr_no_chk + payload)
        tcp_hdr = struct.pack(
            "!HHIIHHHH",
            src_port, dst_port, seq, ack, (5 << 12) | flags, 65535, tcp_chk, 0,
        )

        raw_frame = eth + ip_hdr + tcp_hdr + payload
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        pcap_rec_hdr = struct.pack("<IIII", sec, usec, len(raw_frame), len(raw_frame))
        return pcap_rec_hdr + raw_frame

    # Standard libpcap global header (magic 0xa1b2c3d4, v2.4, LINKTYPE_ETHERNET = 1)
    pcap = bytearray(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    # Handshake
    pcap.extend(_make_frame(base_ts, client_ip, server_ip, client_port, server_port, 1000, 0, 0x02))
    pcap.extend(_make_frame(base_ts + 0.001, server_ip, client_ip, server_port, client_port, 5000, 1001, 0x12))
    pcap.extend(_make_frame(base_ts + 0.002, client_ip, server_ip, client_port, server_port, 1001, 5001, 0x10))

    # Frame 1: HELLO
    hello_pl = b'{"client": "pulse-cli/0.1.0", "protocol_version": 1, "session_mode": "interactive"}'
    f1 = b"PULS\x01\x01" + struct.pack("!H", len(hello_pl)) + hello_pl
    pcap.extend(_make_frame(base_ts + 0.006779, client_ip, server_ip, client_port, server_port, 1001, 5001, 0x18, f1))

    # Frame 2: STATUS
    status_pl = b'{"status": "ready", "service": "PULSE/1", "version": "0.1.0", "vulnerable_mode": true}'
    f2 = b"PULS\x01\x03" + struct.pack("!H", len(status_pl)) + status_pl
    pcap.extend(_make_frame(base_ts + 0.010518, server_ip, client_ip, server_port, client_port, 5001, 1001 + len(f1), 0x18, f2))

    # Frame 3: AUTH
    auth_pl = f'{{"username": "{DAEMON_USER}", "password": "WrongPasswordAttempt#99"}}'.encode("utf-8")
    f3 = b"PULS\x01\x02" + struct.pack("!H", len(auth_pl)) + auth_pl
    pcap.extend(_make_frame(base_ts + 13.112623, client_ip, server_ip, client_port, server_port, 1001 + len(f1), 5001 + len(f2), 0x18, f3))

    # Frame 4: ERROR
    err_pl = b'{"error": "Authentication Failed", "code": 401}'
    f4 = b"PULS\x01\x06" + struct.pack("!H", len(err_pl)) + err_pl
    pcap.extend(_make_frame(base_ts + 13.116388, server_ip, client_ip, server_port, client_port, 5001 + len(f2), 1001 + len(f1) + len(f3), 0x18, f4))

    # Frame 5: READ_DIAG request
    diag_req_pl = b'{"section": "system_config"}'
    f5 = b"PULS\x01\x04" + struct.pack("!H", len(diag_req_pl)) + diag_req_pl
    pcap.extend(_make_frame(base_ts + 26.293468, client_ip, server_ip, client_port, server_port, 1001 + len(f1) + len(f3), 5001 + len(f2) + len(f4), 0x18, f5))

    # Frame 6: READ_DIAG response (secret leak)
    diag_resp_pl = (
        f'{{"section": "system_config", "service": "PULSE/1", "version": "0.1.0", '
        f'"daemon_user": "{DAEMON_USER}", "helper_path": "{HELPER_PATH}", "config_path": "{CONFIG_PATH}", '
        f'"archive_directory": "{ARCHIVE_DIR}", "diagnostic_ticket": "{DIAG_TICKET}", '
        f'"encryption_passphrase_fragment": "{KEY_FRAGMENT}"}}'
    ).encode("utf-8")
    f6 = b"PULS\x01\x04" + struct.pack("!H", len(diag_resp_pl)) + diag_resp_pl
    pcap.extend(_make_frame(base_ts + 26.297698, server_ip, client_ip, server_port, client_port, 5001 + len(f2) + len(f4), 1001 + len(f1) + len(f3) + len(f5), 0x18, f6))

    # Frame 7: CLOSE request
    close_req_pl = b'{"reason": "client_finished"}'
    f7 = b"PULS\x01\x05" + struct.pack("!H", len(close_req_pl)) + close_req_pl
    pcap.extend(_make_frame(base_ts + 63.785680, client_ip, server_ip, client_port, server_port, 1001 + len(f1) + len(f3) + len(f5), 5001 + len(f2) + len(f4) + len(f6), 0x18, f7))

    # Frame 8: CLOSE response
    close_resp_pl = b'{"status": "closed", "message": "Session terminated"}'
    f8 = b"PULS\x01\x05" + struct.pack("!H", len(close_resp_pl)) + close_resp_pl
    pcap.extend(_make_frame(base_ts + 63.788878, server_ip, client_ip, server_port, client_port, 5001 + len(f2) + len(f4) + len(f6), 1001 + len(f1) + len(f3) + len(f5) + len(f7), 0x18, f8))

    # Teardown
    pcap.extend(_make_frame(base_ts + 63.792818, client_ip, server_ip, client_port, server_port, 1001 + len(f1) + len(f3) + len(f5) + len(f7), 5001 + len(f2) + len(f4) + len(f6) + len(f8), 0x11))
    pcap.extend(_make_frame(base_ts + 63.793818, server_ip, client_ip, server_port, client_port, 5001 + len(f2) + len(f4) + len(f6) + len(f8), 1002 + len(f1) + len(f3) + len(f5) + len(f7), 0x10))

    return bytes(pcap)


def generate_daemon_log() -> str:
    """Generate EV-LOG-001: PULSE/1 daemon host log (/var/log/pulse/pulse.log).

    Timestamps reflect true UTC host system time (NTP calibrated),
    which is exactly +420s ahead of the optical tap RTC clock.
    """
    lines = [
        f"[{INCIDENT_DATE}T03:21:02.108422Z] [INFO] [pulse.server] Accepted TCP connection from {ATTACKER_IP}:{ATTACKER_PORT} (session_id=SES-7741-ALPHA)",
        f"[{INCIDENT_DATE}T03:21:02.115201Z] [INFO] [pulse.server] [SES-7741-ALPHA] Received HELLO (protocol_version=1, client=pulse-cli/0.1.0)",
        f"[{INCIDENT_DATE}T03:21:02.118940Z] [INFO] [pulse.server] [SES-7741-ALPHA] Emitted STATUS (service=PULSE/1, version=0.1.0, vulnerable_mode=true)",
        f"[{INCIDENT_DATE}T03:21:15.221045Z] [WARN] [pulse.server] [SES-7741-ALPHA] Authentication failed for username='{DAEMON_USER}' from {ATTACKER_IP} (invalid credentials)",
        f"[{INCIDENT_DATE}T03:21:15.224810Z] [WARN] [pulse.server] [SES-7741-ALPHA] Emitted ERROR 401: Authentication Failed",
        f"[{INCIDENT_DATE}T03:21:28.401890Z] [WARN] [pulse.server] [SES-7741-ALPHA] Received READ_DIAG request for section='system_config' from unauthenticated session",
        f"[{INCIDENT_DATE}T03:21:28.406120Z] [INFO] [pulse.server] [SES-7741-ALPHA] Dispatched system_config diagnostic payload (helper={HELPER_PATH}, ticket={DIAG_TICKET})",
        f"[{INCIDENT_DATE}T03:21:40.010500Z] [INFO] [pulse.server] [SES-7741-ALPHA] Diagnostic ticket written to /var/tmp/.diag_ticket",
        f"[{INCIDENT_DATE}T03:21:45.390000Z] [INFO] [pulse.server] [SES-7741-ALPHA] Invoked maintenance helper: {HELPER_PATH} --archive-check {ARCHIVE_DIR}/research_vault.tar.gz.enc; ... (child pid=1418)",
        f"[{INCIDENT_DATE}T03:22:05.894102Z] [INFO] [pulse.server] [SES-7741-ALPHA] Received CLOSE frame: reason='client_finished'",
        f"[{INCIDENT_DATE}T03:22:05.897300Z] [INFO] [pulse.server] [SES-7741-ALPHA] Emitted CLOSE acknowledgment",
        f"[{INCIDENT_DATE}T03:22:05.901240Z] [INFO] [pulse.server] [SES-7741-ALPHA] Connection closed gracefully by client",
    ]
    return "\n".join(lines) + "\n"


def generate_audit_log() -> str:
    """Generate EV-LOG-002: Linux auditd log (/var/log/audit/audit.log).

    Contains genuine kernel SYSCALL/EXECVE/PROCTITLE records for pulse-helper
    proving real process lineage (ppid=1412, pid=1418, uid=1002 svc-pulse, euid=0 root),
    followed by exactly ONE manipulated orphan EXECVE record framing rhea (auid=1001, ses unset).
    """
    lines = [
        "# Linux Audit Log Seized from meridian-lab (10.0.4.15)",
        "# Audit Rules Active: -a always,exit -F arch=b64 -S execve -F path=/usr/local/bin/pulse-helper -k pulse_helper_exec",
        "",
        "# Event 890: Baseline cron activity",
        'type=SYSCALL msg=audit(1726305600.010:890): arch=c00000b7 syscall=221 success=yes exit=0 a0=aaaae0100000 a1=aaaae0100500 a2=0 a3=0 items=2 ppid=401 pid=1301 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="cron" exe="/usr/sbin/cron" key=(null)',
        'type=EXECVE msg=audit(1726305600.010:890): argc=1 a0="/usr/sbin/cron"',
        'type=PROCTITLE msg=audit(1726305600.010:890): proctitle=2F7573722F7362696E2F63726F6E',
        "",
        "# Event 892: Genuine kernel syscall audit record capturing pulse-helper invocation",
        'type=SYSCALL msg=audit(1726305672.390:892): arch=c00000b7 syscall=221 success=yes exit=0 a0=aaaad1024000 a1=aaaad1024800 a2=aaaad1025000 a3=0 items=2 ppid=1412 pid=1418 auid=4294967295 uid=1002 gid=1002 euid=0 suid=0 fsuid=0 egid=1002 sgid=1002 fsgid=1002 tty=(none) ses=4294967295 comm="pulse-helper" exe="/usr/local/bin/pulse-helper" key="pulse_helper_exec"',
        'type=EXECVE msg=audit(1726305672.390:892): argc=3 a0="/usr/local/bin/pulse-helper" a1="--archive-check" a2="/var/archive/meridian/research_vault.tar.gz.enc; cat /var/tmp/.diag_ticket > /tmp/.vault_key; tar -xzf /var/archive/meridian/research_vault.tar.gz.enc -C /tmp"',
        'type=PROCTITLE msg=audit(1726305672.390:892): proctitle=2F7573722F6C6F63616C2F62696E2F70756C73652D68656C706572002D2D617263686976652D636865636B002F7661722F617263686976652F6D6572696469616E2F72657365617263685F7661756C742E7461722E677A2E656E63',
        "",
        "# Event 893: Shell child dispatched by helper via system()",
        'type=SYSCALL msg=audit(1726305672.398:893): arch=c00000b7 syscall=221 success=yes exit=0 a0=aaaad1030000 a1=aaaad1030800 a2=aaaad1031000 a3=0 items=2 ppid=1418 pid=1419 auid=4294967295 uid=0 gid=1002 euid=0 suid=0 fsuid=0 egid=1002 sgid=1002 fsgid=1002 tty=(none) ses=4294967295 comm="sh" exe="/bin/dash" key="pulse_helper_exec"',
        'type=EXECVE msg=audit(1726305672.398:893): argc=3 a0="/bin/sh" a1="-c" a2="/bin/tar -tzf /var/archive/meridian/research_vault.tar.gz.enc; cat /var/tmp/.diag_ticket > /tmp/.vault_key; tar -xzf /var/archive/meridian/research_vault.tar.gz.enc -C /tmp >/dev/null 2>&1"',
        'type=PROCTITLE msg=audit(1726305672.398:893): proctitle=2F62696E2F7368002D6300',
        "",
        "# Forensic Anomaly: Fabricated orphan record injected out-of-band to frame rhea",
        'type=EXECVE msg=audit(1726305672.410:894): argc=3 a0="tar" a1="-czf" a2="/var/archive/meridian/research_vault.tar.gz" auid=1001 ses=4294967295',
    ]
    return "\n".join(lines) + "\n"


def generate_auth_log() -> str:
    """Generate EV-LOG-003: Linux authentication log (/var/log/auth.log).

    Demonstrates user rhea had zero PAM login sessions on the incident date.
    """
    lines = [
        "Sep 14 00:00:01 meridian-lab CRON[412]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Sep 14 00:00:01 meridian-lab CRON[412]: pam_unix(cron:session): session closed for user root",
        "Sep 14 01:15:22 meridian-lab sshd[840]: Accepted publickey for analyst from 10.0.4.1 port 52310 ssh2: ED25519 SHA256:6Fk818vYtP0...",
        "Sep 14 01:15:22 meridian-lab sshd[840]: pam_unix(sshd:session): session opened for user analyst(uid=1000) by (uid=0)",
        "Sep 14 01:15:22 meridian-lab systemd-logind[402]: New session 3 of user analyst.",
        "Sep 14 02:00:01 meridian-lab CRON[980]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Sep 14 02:00:01 meridian-lab CRON[980]: pam_unix(cron:session): session closed for user root",
        "Sep 14 03:00:01 meridian-lab CRON[1301]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Sep 14 03:00:01 meridian-lab CRON[1301]: pam_unix(cron:session): session closed for user root",
        "Sep 14 04:00:01 meridian-lab CRON[1520]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Sep 14 04:00:01 meridian-lab CRON[1520]: pam_unix(cron:session): session closed for user root",
    ]
    return "\n".join(lines) + "\n"


def generate_wtmp_sessions() -> dict[str, Any]:
    """Generate EV-LOG-004: Terminal session inventory snapshot from /var/log/wtmp."""
    return {
        "evidence_id": "EV-LOG-004",
        "scenario": SCENARIO_NAME,
        "source": "/var/log/wtmp",
        "extracted_utc": f"{INCIDENT_DATE}T06:00:00Z",
        "active_sessions_at_breach_window": [
            {
                "user": "analyst",
                "uid": 1000,
                "terminal": "pts/0",
                "host": "10.0.4.1",
                "login_utc": f"{INCIDENT_DATE}T01:15:22Z",
                "logout_utc": None,
                "state": "logged_in",
            }
        ],
        "historical_sessions_summary": {
            "rhea": {
                "uid": 1001,
                "last_login_utc": "2026-09-11T14:10:00Z",
                "last_logout_utc": "2026-09-11T17:45:00Z",
                "last_terminal": "pts/1",
                "sessions_on_incident_date": 0,
            }
        },
    }


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


def generate_pulse_service_unit() -> str:
    """Generate EV-CFG-002: Systemd service unit definition (/etc/systemd/system/pulse.service)."""
    lines = [
        "[Unit]",
        "Description=PULSE/1 Telemetry and Diagnostics Daemon",
        "After=network.target",
        "",
        "[Service]",
        "Type=simple",
        f"User={DAEMON_USER}",
        f"Group={DAEMON_USER}",
        f"ExecStart=/usr/local/bin/pulse-daemon --config {CONFIG_PATH}",
        "Restart=always",
        "RestartSec=3",
        "StandardOutput=append:/var/log/pulse/pulse.log",
        "StandardError=append:/var/log/pulse/pulse.log",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
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


def generate_passwd() -> str:
    """Generate EV-SYS-001: User database snapshot (/etc/passwd)."""
    lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "sync:x:4:65534:sync:/bin:/bin/sync",
        "systemd-journal-remote:x:998:998:systemd Journal Remote:/run/systemd:/usr/sbin/nologin",
        "systemd-network:x:999:999:systemd Network Management:/:/usr/sbin/nologin",
        "analyst:x:1000:1000:Security Analyst,,,:/home/analyst:/bin/bash",
        "rhea:x:1001:1001:Rhea Vance (Flight Dynamics),,,:/home/rhea:/bin/bash",
        f"{DAEMON_USER}:x:1002:1002:PULSE Telemetry Service,,,:/var/run/pulse:/usr/sbin/nologin",
    ]
    return "\n".join(lines) + "\n"


def generate_group() -> str:
    """Generate EV-SYS-002: Group database snapshot (/etc/group)."""
    lines = [
        "root:x:0:",
        "daemon:x:1:",
        "bin:x:2:",
        "sys:x:3:",
        "adm:x:4:",
        "sudo:x:27:",
        "systemd-journal:x:101:analyst",
        "analyst:x:1000:",
        "rhea:x:1001:",
        f"{DAEMON_USER}:x:1002:",
    ]
    return "\n".join(lines) + "\n"


def generate_file_permissions() -> dict[str, Any]:
    """Generate EV-SYS-003: Discretionary access control & file permissions inventory."""
    return {
        "evidence_id": "EV-SYS-003",
        "scenario": SCENARIO_NAME,
        "collected_utc": f"{INCIDENT_DATE}T06:00:00Z",
        "paths": {
            HELPER_PATH: {
                "owner": "root",
                "group": DAEMON_USER,
                "mode_octal": "4750",
                "mode_symbolic": "-rwsr-x---",
                "setuid": True,
                "acls": "user:analyst:r-x",
                "description": "Proprietary maintenance helper binary with setuid root",
            },
            ARCHIVE_DIR: {
                "owner": "root",
                "group": "root",
                "mode_octal": "0700",
                "mode_symbolic": "drwx------",
                "setuid": False,
                "acls": "",
                "description": "Protected backup archive directory",
            },
            f"{ARCHIVE_DIR}/research_vault.tar.gz.enc": {
                "owner": "root",
                "group": "root",
                "mode_octal": "0600",
                "mode_symbolic": "-rw-------",
                "setuid": False,
                "description": "Encrypted research telemetry vault archive",
            },
            CONFIG_PATH: {
                "owner": "root",
                "group": DAEMON_USER,
                "mode_octal": "0640",
                "mode_symbolic": "-rw-r-----",
                "setuid": False,
                "description": "PULSE/1 daemon configuration file",
            },
            "/var/log/audit/audit.log": {
                "owner": "root",
                "group": "root",
                "mode_octal": "0600",
                "mode_symbolic": "-rw-------",
                "acls": "user:analyst:r--",
                "description": "Kernel audit subsystem log",
            },
            "/var/log/pulse/pulse.log": {
                "owner": DAEMON_USER,
                "group": DAEMON_USER,
                "mode_octal": "0640",
                "mode_symbolic": "-rw-r-----",
                "acls": "user:analyst:r--",
                "description": "PULSE/1 daemon application log",
            },
        },
    }


def generate_rhea_bash_history() -> str:
    """Generate EV-USR-001: Shell history for employee rhea (/home/rhea/.bash_history).

    Proves absence of archive export commands or terminal pts/0 sessions.
    """
    lines = [
        "git status",
        "git pull origin main",
        "python3 run_orbital_simulation.py --steps 1000 --config configs/flight_profile.yaml",
        "cat output/telemetry_summary.csv | head -n 20",
        "pytest tests/test_trajectory.py",
        "vim docs/calibration_notes.md",
        "exit",
    ]
    return "\n".join(lines) + "\n"


def generate_diag_ticket() -> dict[str, Any]:
    """Generate EV-DAT-002: Transient diagnostic ticket (/var/tmp/.diag_ticket)."""
    return {
        "evidence_id": "EV-DAT-002",
        "scenario": SCENARIO_NAME,
        "ticket_id": DIAG_TICKET,
        "created_utc": f"{INCIDENT_DATE}T03:21:40Z",
        "vault_target": f"{ARCHIVE_DIR}/research_vault.tar.gz.enc",
        "key_derivation": {
            "fragment_a": KEY_FRAGMENT,
            "fragment_b": KEY_FRAGMENT_B,
            "combined_passphrase": FULL_VAULT_PASSPHRASE,
        },
        "algorithm": "AES-256-CBC-PBKDF2",
    }


def generate_encrypted_vault() -> bytes:
    """Generate EV-DAT-001: Encrypted research vault archive (/var/archive/meridian/research_vault.tar.gz.enc).

    Encrypted with OpenSSL-compatible AES-256-CBC PBKDF2 (salt=MERIDIAN1) using FULL_VAULT_PASSPHRASE.
    Plaintext contains VAULT_PLAINTEXT_HEADER.
    """
    plaintext = (
        f"{VAULT_PLAINTEXT_HEADER}: Confidential Aerospace Telemetry Vault\n"
        "Classification: Meridian Research Proprietary\n"
        "Status: Archived Flight Profile Records (Payload Validated)\n"
    ).encode("utf-8")

    salt = b"MERIDIAN"
    derived = hashlib.pbkdf2_hmac("sha256", FULL_VAULT_PASSPHRASE.encode("utf-8"), salt, 10000, dklen=48)
    key = derived[:32]
    iv = derived[32:48]

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
    except ImportError:
        # Deterministic stream fallback if cryptography is absent
        keystream = bytearray()
        block_counter = 0
        while len(keystream) < len(plaintext) + 16:
            keystream.extend(hashlib.sha256(key + iv + struct.pack("!I", block_counter)).digest())
            block_counter += 1
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        ciphertext = bytes(a ^ b for a, b in zip(padded, keystream[:len(padded)]))

    return b"Salted__" + salt + ciphertext


def decrypt_vault(data: bytes, passphrase: str) -> bytes:
    """Decrypt an OpenSSL-compatible AES-256-CBC PBKDF2 vault payload.

    Args:
        data: Encrypted bytes starting with b"Salted__".
        passphrase: The combined passphrase string.

    Returns:
        Decrypted plaintext bytes.
    """
    if not data.startswith(b"Salted__") or len(data) < 16:
        raise ValueError("Invalid encrypted vault format: missing Salted__ header")

    salt = data[8:16]
    ciphertext = data[16:]
    derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 10000, dklen=48)
    key = derived[:32]
    iv = derived[32:48]

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ImportError:
        keystream = bytearray()
        block_counter = 0
        while len(keystream) < len(ciphertext):
            keystream.extend(hashlib.sha256(key + iv + struct.pack("!I", block_counter)).digest())
            block_counter += 1
        padded = bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))
        pad_len = padded[-1]
        return padded[:-pad_len]


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
    "raw/network/capture.pcap": {
        "evidence_id": "EV-NET-003",
        "source_system": TAP_DEVICE_ID,
        "format": "application/vnd.tcpdump.pcap",
        "description": "Synthetic raw packet capture (PCAP) recording PULSE/1 TCP wire session",
    },
    "raw/logs/pulse.log": {
        "evidence_id": "EV-LOG-001",
        "source_system": "meridian-lab",
        "format": "text/log",
        "description": "Synthetic host PULSE/1 daemon application log (/var/log/pulse/pulse.log)",
    },
    "raw/logs/audit.log": {
        "evidence_id": "EV-LOG-002",
        "source_system": "meridian-lab",
        "format": "text/audit",
        "description": "Synthetic Linux audit log (/var/log/audit/audit.log) containing genuine and forged records",
    },
    "raw/logs/auth.log": {
        "evidence_id": "EV-LOG-003",
        "source_system": "meridian-lab",
        "format": "text/syslog",
        "description": "Synthetic PAM authentication log (/var/log/auth.log) establishing rhea alibi",
    },
    "raw/logs/wtmp.json": {
        "evidence_id": "EV-LOG-004",
        "source_system": "meridian-lab",
        "format": "application/json",
        "description": "Synthetic terminal session inventory snapshot (/var/log/wtmp)",
    },
    "raw/system/pulse.conf": {
        "evidence_id": "EV-CFG-001",
        "source_system": "meridian-lab",
        "format": "text/ini",
        "description": "Synthetic PULSE/1 daemon configuration file snapshot (/etc/pulse/pulse.conf)",
    },
    "raw/system/pulse.service": {
        "evidence_id": "EV-CFG-002",
        "source_system": "meridian-lab",
        "format": "text/systemd",
        "description": "Synthetic systemd unit configuration (/etc/systemd/system/pulse.service)",
    },
    "raw/system/service_inventory.json": {
        "evidence_id": "EV-SRV-001",
        "source_system": "meridian-lab",
        "format": "application/json",
        "description": "Synthetic host service footprint inventory snapshot",
    },
    "raw/system/passwd": {
        "evidence_id": "EV-SYS-001",
        "source_system": "meridian-lab",
        "format": "text/passwd",
        "description": "Synthetic user account database snapshot (/etc/passwd)",
    },
    "raw/system/group": {
        "evidence_id": "EV-SYS-002",
        "source_system": "meridian-lab",
        "format": "text/group",
        "description": "Synthetic group membership database snapshot (/etc/group)",
    },
    "raw/system/file_permissions.json": {
        "evidence_id": "EV-SYS-003",
        "source_system": "meridian-lab",
        "format": "application/json",
        "description": "Synthetic discretionary access control and setuid file permissions snapshot",
    },
    "raw/system/rhea_bash_history": {
        "evidence_id": "EV-USR-001",
        "source_system": "meridian-lab",
        "format": "text/plain",
        "description": "Synthetic shell command history snapshot for user rhea (/home/rhea/.bash_history)",
    },
    "raw/data/research_vault.tar.gz.enc": {
        "evidence_id": "EV-DAT-001",
        "source_system": "meridian-lab",
        "format": "application/octet-stream",
        "description": "Synthetic encrypted research archive vault (/var/archive/meridian/research_vault.tar.gz.enc)",
    },
    "raw/data/diag_ticket": {
        "evidence_id": "EV-DAT-002",
        "source_system": "meridian-lab",
        "format": "application/json",
        "description": "Synthetic diagnostic token remnant (/var/tmp/.diag_ticket) with key material",
    },
}


def generate_evidence_index() -> str:
    """Generate markdown evidence index describing artifacts, origin, purpose, and limitations."""
    lines = [
        "# PARALLAX — Evidence Artifact Index",
        "",
        "This index documents all raw forensic artifacts collected for the **Meridian Research Incident** (Milestone 6).",
        "",
        "---",
        "",
        "## 1. Evidence Artifact Catalog",
        "",
        "| Evidence ID | Path | Format | Source System | Ground Truth Role | Integrity Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
        "| **`EV-NET-001`** | `raw/network/pulse_session.transcript` | `text/transcript` | `TAP-MERIDIAN-01` | PULSE/1 wire transcript demonstrating auth flaw | Indexed in `manifest.json` |",
        "| **`EV-NET-002`** | `raw/network/capture.meta` | `application/json` | `TAP-MERIDIAN-01` | Optical tap metadata documenting -420s clock drift | Indexed in `manifest.json` |",
        "| **`EV-NET-003`** | `raw/network/capture.pcap` | `application/vnd.tcpdump.pcap` | `TAP-MERIDIAN-01` | Raw packet capture with wire frames and TCP handshake | Indexed in `manifest.json` |",
        "| **`EV-LOG-001`** | `raw/logs/pulse.log` | `text/log` | `meridian-lab` | Host application log showing connections, auth failure, leaked diag | Indexed in `manifest.json` |",
        "| **`EV-LOG-002`** | `raw/logs/audit.log` | `text/audit` | `meridian-lab` | Kernel audit log: genuine helper syscalls + 1 forged record | Indexed in `manifest.json` |",
        "| **`EV-LOG-003`** | `raw/logs/auth.log` | `text/syslog` | `meridian-lab` | Host authentication log demonstrating rhea alibi (no PAM sessions) | Indexed in `manifest.json` |",
        "| **`EV-LOG-004`** | `raw/logs/wtmp.json` | `application/json` | `meridian-lab` | Terminal session inventory snapshot proving no sessions for rhea | Indexed in `manifest.json` |",
        "| **`EV-CFG-001`** | `raw/system/pulse.conf` | `text/ini` | `meridian-lab` | Service configuration snapshot (/etc/pulse/pulse.conf) | Indexed in `manifest.json` |",
        "| **`EV-CFG-002`** | `raw/system/pulse.service` | `text/systemd` | `meridian-lab` | Service systemd unit definition (/etc/systemd/system/pulse.service) | Indexed in `manifest.json` |",
        "| **`EV-SRV-001`** | `raw/system/service_inventory.json` | `application/json` | `meridian-lab` | Host service footprint inventory (/etc/systemd) | Indexed in `manifest.json` |",
        "| **`EV-SYS-001`** | `raw/system/passwd` | `text/passwd` | `meridian-lab` | User account database snapshot (/etc/passwd) | Indexed in `manifest.json` |",
        "| **`EV-SYS-002`** | `raw/system/group` | `text/group` | `meridian-lab` | Group database snapshot (/etc/group) | Indexed in `manifest.json` |",
        "| **`EV-SYS-003`** | `raw/system/file_permissions.json` | `application/json` | `meridian-lab` | Discretionary access control & setuid permissions inventory | Indexed in `manifest.json` |",
        "| **`EV-USR-001`** | `raw/system/rhea_bash_history` | `text/plain` | `meridian-lab` | Shell history for user rhea proving absence of archive commands | Indexed in `manifest.json` |",
        "| **`EV-DAT-001`** | `raw/data/research_vault.tar.gz.enc` | `application/octet-stream` | `meridian-lab` | Encrypted research archive vault in /var/archive/meridian | Indexed in `manifest.json` |",
        "| **`EV-DAT-002`** | `raw/data/diag_ticket` | `application/json` | `meridian-lab` | Diagnostic ticket token remnant in /var/tmp/.diag_ticket | Indexed in `manifest.json` |",
        "",
        "---",
        "",
        "## 2. Artifact Details, Purpose & Limitations",
        "",
        "### EV-NET-001 & EV-NET-003: PULSE/1 Wire Transcripts & Packet Capture",
        "- **Origin**: Upstream optical network tap `TAP-MERIDIAN-01` on SPAN interface `eth0-span`.",
        "- **Purpose**: Records the chronological wire exchange between client `198.51.100.24:49822` and host service `10.0.4.15:7741`. Demonstrates that after submitting invalid credentials (`AUTH`), the client successfully dispatched a `READ_DIAG` frame and received sensitive parameters (`helper_path`, `diagnostic_ticket`, `encryption_passphrase_fragment`).",
        "- **Limitations & Clock Skew**: Timestamps reflect tap RTC time lagging true UTC by 420 seconds (7 minutes).",
        "",
        "### EV-NET-002: Upstream Network Tap Metadata (`raw/network/capture.meta`)",
        "- **Origin**: Management control-plane diagnostic export from tap appliance `TAP-MERIDIAN-01`.",
        "- **Purpose**: Documents hardware capture environment, interface mapping, capture window, and clock synchronization status (`DEGRADED`, `clock_offset_seconds: -420`).",
        "- **Facts vs Hypotheses**: Metadata documents hardware drift. Corroboration against host logs is required to prove operational drift vs timestomping.",
        "",
        "### EV-LOG-001: PULSE/1 Daemon Application Log (`raw/logs/pulse.log`)",
        "- **Origin**: Host log `/var/log/pulse/pulse.log` recorded under true UTC host system time.",
        "- **Purpose**: Confirms connection events, failed authentication, unauthenticated diagnostic dispatch, and helper execution at timestamps exactly +420s ahead of tap records.",
        "",
        "### EV-LOG-002: Linux Audit Log (`raw/logs/audit.log`)",
        "- **Origin**: Host `/var/log/audit/audit.log` generated by kernel audit subsystem via `/etc/audit/rules.d/audit.rules`.",
        "- **Purpose**: Contains authentic kernel `SYSCALL` records linking `pulse-helper` execution to `svc-pulse` (UID 1002, PPID 1412), alongside exactly one forged orphan `EXECVE` record framing `rhea` (AUID 1001, ses=4294967295, lacking companion `SYSCALL`/`PROCTITLE` records).",
        "",
        "### EV-LOG-003 & EV-LOG-004: PAM Authentication and Session History",
        "- **Origin**: Host `/var/log/auth.log` and `/var/log/wtmp`.",
        "- **Purpose**: Proves user `rhea` had zero active PAM logins or terminal allocations (`pts/0`) during the incident window.",
        "",
        "### EV-SYS-001, EV-SYS-002, EV-SYS-003, EV-CFG-001, EV-CFG-002: System Configuration & DAC",
        "- **Origin**: Target host snapshots.",
        "- **Purpose**: Documents user accounts, group memberships, and setuid file mode `4750` on `/usr/local/bin/pulse-helper`.",
        "",
        "### EV-DAT-001 & EV-DAT-002: Encrypted Vault & Diagnostic Ticket",
        "- **Origin**: Filesystem artifacts seized from `/var/archive/meridian` and `/var/tmp`.",
        "- **Purpose**: Contains the encrypted vault and cryptographic key derivation materials required for decryption.",
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
    logs_dir = raw_dir / "logs"
    sys_dir = raw_dir / "system"
    data_dir = raw_dir / "data"
    manifest_dir = root / "manifests"
    derived_dir = root / "derived"
    notes_dir = root / "notes"

    # Ensure directories exist (preserves existing notes and derived data)
    net_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    sys_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)
    derived_dir.mkdir(parents=True, exist_ok=True)
    notes_dir.mkdir(parents=True, exist_ok=True)

    def _write_lf_text(p: Path, text: str) -> None:
        p.write_bytes(text.encode("utf-8"))

    # 1. EV-NET-001: pulse_session.transcript
    p_transcript = net_dir / "pulse_session.transcript"
    _write_lf_text(p_transcript, generate_pulse_transcript())

    # 2. EV-NET-002: capture.meta
    p_meta = net_dir / "capture.meta"
    _write_lf_text(p_meta, json.dumps(generate_capture_metadata(), indent=2) + "\n")

    # 3. EV-NET-003: capture.pcap
    p_pcap = net_dir / "capture.pcap"
    p_pcap.write_bytes(generate_pcap_capture())

    # 4. EV-LOG-001: pulse.log
    p_pulselog = logs_dir / "pulse.log"
    _write_lf_text(p_pulselog, generate_daemon_log())

    # 5. EV-LOG-002: audit.log
    p_auditlog = logs_dir / "audit.log"
    _write_lf_text(p_auditlog, generate_audit_log())

    # 6. EV-LOG-003: auth.log
    p_authlog = logs_dir / "auth.log"
    _write_lf_text(p_authlog, generate_auth_log())

    # 7. EV-LOG-004: wtmp.json
    p_wtmp = logs_dir / "wtmp.json"
    _write_lf_text(p_wtmp, json.dumps(generate_wtmp_sessions(), indent=2) + "\n")

    # 8. EV-CFG-001: pulse.conf
    p_conf = sys_dir / "pulse.conf"
    _write_lf_text(p_conf, generate_service_config())

    # 9. EV-CFG-002: pulse.service
    p_service = sys_dir / "pulse.service"
    _write_lf_text(p_service, generate_pulse_service_unit())

    # 10. EV-SRV-001: service_inventory.json
    p_inv = sys_dir / "service_inventory.json"
    _write_lf_text(p_inv, json.dumps(generate_service_inventory(), indent=2) + "\n")

    # 11. EV-SYS-001: passwd
    p_passwd = sys_dir / "passwd"
    _write_lf_text(p_passwd, generate_passwd())

    # 12. EV-SYS-002: group
    p_group = sys_dir / "group"
    _write_lf_text(p_group, generate_group())

    # 13. EV-SYS-003: file_permissions.json
    p_perms = sys_dir / "file_permissions.json"
    _write_lf_text(p_perms, json.dumps(generate_file_permissions(), indent=2) + "\n")

    # 14. EV-USR-001: rhea_bash_history
    p_rhea_hist = sys_dir / "rhea_bash_history"
    _write_lf_text(p_rhea_hist, generate_rhea_bash_history())

    # 15. EV-DAT-001: research_vault.tar.gz.enc
    p_vault = data_dir / "research_vault.tar.gz.enc"
    p_vault.write_bytes(generate_encrypted_vault())

    # 16. EV-DAT-002: diag_ticket
    p_ticket = data_dir / "diag_ticket"
    _write_lf_text(p_ticket, json.dumps(generate_diag_ticket(), indent=2) + "\n")

    # Evidence Index: INDEX.md
    p_index = root / "INDEX.md"
    _write_lf_text(p_index, generate_evidence_index())

    results = {
        "EV-NET-001": p_transcript,
        "EV-NET-002": p_meta,
        "EV-NET-003": p_pcap,
        "EV-LOG-001": p_pulselog,
        "EV-LOG-002": p_auditlog,
        "EV-LOG-003": p_authlog,
        "EV-LOG-004": p_wtmp,
        "EV-CFG-001": p_conf,
        "EV-CFG-002": p_service,
        "EV-SRV-001": p_inv,
        "EV-SYS-001": p_passwd,
        "EV-SYS-002": p_group,
        "EV-SYS-003": p_perms,
        "EV-USR-001": p_rhea_hist,
        "EV-DAT-001": p_vault,
        "EV-DAT-002": p_ticket,
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
