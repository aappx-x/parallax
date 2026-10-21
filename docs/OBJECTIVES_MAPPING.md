# PARALLAX — Objectives Ground-Truth Mapping & Validation Specification

This document provides the authoritative, exhaustive forensic mapping for the fictional **Meridian Research Incident** investigation across all 15 objectives (`P01`–`P15`).

---

## 1. Ground Truth Principles & Corroboration Standards

The investigation is governed by strict digital forensics principles:
1. **Self-Contained & Deterministic**: The entire scenario is solvable offline from the supplied evidence workspace (`evidence/raw/`) without external connectivity, undisclosed files, or guessing.
2. **Two Central Discrepancies Only**:
   - **Discrepancy 1 (Hostile Tampering)**: Exactly one deliberately manipulated audit record (`type=EXECVE` event serial `894` in `/var/log/audit/audit.log`) framing employee `rhea`.
   - **Discrepancy 2 (Benign Operational Drift)**: An upstream optical network tap RTC hardware drift of `-420` seconds (7 minutes behind workstation NTP clock), documented in `capture.meta` and corroborated across 4 paired session events.
3. **Multi-Source Corroboration**: No single artifact constitutes conclusive proof where anti-forensic deception is at play. In particular, concluding that `rhea` is innocent requires positive corroboration from kernel syscall audit records, PAM authentication logs, terminal session tables, and shell history.

---

## 2. Objective Mapping Catalog (P01–P15)

```text
+---------------------------------------------------------------------------------------------------------------------------------+
| ID  | Phase | Objective Title              | Required Evidence IDs   | Primary Fact Established                                 |
+-----+-------+------------------------------+-------------------------+----------------------------------------------------------+
| P01 | A     | Service Port Discovery       | EV-CFG-001, EV-SRV-001  | PULSE/1 daemon listens on TCP port 7741                  |
| P02 | A     | Protocol Wire Framing        | EV-NET-001, EV-NET-003  | Binary header: magic PULS (0x50554c53), v1, type, length |
| P03 | B     | Attacker IP & Trace          | EV-NET-001, EV-NET-003  | Client IP 198.51.100.24, session sequence HELLO->CLOSE   |
| P04 | C     | Auth State Logic Flaw        | EV-NET-001, EV-LOG-001  | READ_DIAG (0x04) accepted after 401 AUTH error           |
| P05 | B     | Timestamp Offset Delta       | EV-NET-002, EV-LOG-001  | Empirical time delta is exactly 420 seconds (7 minutes)  |
| P06 | B     | Skew Root Cause Proof        | EV-NET-002, EV-LOG-001  | Tap hardware RTC drift (-420s), not host timestomping    |
| P07 | C     | Diagnostic Secret Leak       | EV-NET-001, EV-NET-003  | Helper path and ticket/fragment leaked in READ_DIAG      |
| P08 | C     | Service Footprint & Perms    | EV-SYS-001, EV-SYS-003  | Service user svc-pulse (1002), helper mode 4750 setuid   |
| P09 | C     | Privileged Helper Boundary   | EV-SYS-003, EV-CFG-001  | Command injection via unsanitized --archive-check input  |
| P10 | C     | Cryptographic Key Recovery   | EV-DAT-001, EV-DAT-002  | Plaintext header MERIDIAN-AERO-VAULT-v2.4 and key frag   |
| P11 | D     | Forged Audit Discovery       | EV-LOG-002              | Event 894 tar command attributed to auid=1001 (rhea)     |
| P12 | D     | User Rhea Alibi              | EV-LOG-003, EV-LOG-004  | Zero PAM logins or pts sessions for rhea on incident day |
| P13 | C     | Real Process Lineage         | EV-LOG-002, EV-SRV-001  | Kernel event 892 shows pulse-helper spawned by PID 1412  |
| P14 | D     | Tampering Mechanics          | EV-LOG-002              | Orphan EXECVE missing companion SYSCALL and unset ses    |
| P15 | E     | Final Incident Verdict       | P01 through P14         | Comprehensive evidence-backed incident synthesis         |
+---------------------------------------------------------------------------------------------------------------------------------+
```

---

## 3. Detailed Objective Specifications

### `P01`: Service Port Discovery
- **Phase**: Phase A: Initial Protocol Triage
- **Question**: On which TCP port was the unauthenticated PULSE/1 service listening during the breach?
- **Prerequisites**: None.
- **Required Evidence Files**:
  - `EV-CFG-001`: `raw/system/pulse.conf` (`listen_port = 7741`)
  - `EV-SRV-001`: `raw/system/service_inventory.json` (`listen_ports: [7741]`)
  - `EV-CFG-002`: `raw/system/pulse.service`
- **Facts Established**: The telemetry daemon was bound to TCP port `7741` on `0.0.0.0`.
- **Inferences Supported**: Port 7741 was the candidate network attack surface.
- **Expected Answer**: `7741` (or `TCP 7741`).
- **Validation Criteria**: Matches string `7741`.
- **Limitations & Uncertainties**: The configuration proves port binding; network capture is needed to verify client arrival.

---

### `P02`: Protocol Wire Framing
- **Phase**: Phase A: Initial Protocol Triage
- **Question**: What is the 4-byte magic identifier and byte layout of a PULSE/1 wire frame?
- **Prerequisites**: `P01`.
- **Required Evidence Files**:
  - `EV-NET-001`: `raw/network/pulse_session.transcript`
  - `EV-NET-003`: `raw/network/capture.pcap`
- **Facts Established**: The protocol uses magic bytes `PULS` (`0x50 0x55 0x4c 0x53`), 1-byte version (`0x01`), 1-byte message type identifier, 2-byte big-endian payload length, and variable-length JSON payload.
- **Expected Answer**: Magic bytes `PULS` (`0x50554c53`).
- **Validation Criteria**: Case-insensitive match for `PULS` or `0x50554c53` or `50554c53`.
- **Limitations & Uncertainties**: Raw frame headers define network serialization, not application authorization rules.

---

### `P03`: Attacker IP & Trace
- **Phase**: Phase B: Timing Corroboration
- **Question**: What was the external IP address of the client and the exact order of message types transmitted in the session?
- **Prerequisites**: `P02`.
- **Required Evidence Files**:
  - `EV-NET-001`: `raw/network/pulse_session.transcript`
  - `EV-NET-003`: `raw/network/capture.pcap`
  - `EV-LOG-001`: `raw/logs/pulse.log`
- **Facts Established**: External client `198.51.100.24` (port 49822) connected to `10.0.4.15:7741`. Sequence: `HELLO` (0x01) -> `STATUS` (0x03) -> `AUTH` (0x02) -> `ERROR` (0x06) -> `READ_DIAG` (0x04) -> `READ_DIAG` (0x04) -> `CLOSE` (0x05) -> `CLOSE` (0x05).
- **Expected Answer**: IP `198.51.100.24`.
- **Validation Criteria**: Matches `198.51.100.24`.
- **Limitations & Uncertainties**: Demonstrates external client IP; does not identify physical human operator behind the client.

---

### `P04`: Auth State Logic Flaw
- **Phase**: Phase C: Protocol & Privileged Helper
- **Question**: Which message type was accepted and processed by the daemon immediately after emitting an authentication failure error?
- **Prerequisites**: `P03`.
- **Required Evidence Files**:
  - `EV-NET-001`: `raw/network/pulse_session.transcript`
  - `EV-LOG-001`: `raw/logs/pulse.log`
- **Facts Established**: After receiving `ERROR` 401 ("Authentication Failed") on Frame 4, the client submitted `READ_DIAG` (0x04) on Frame 5, which the daemon executed and responded to with Frame 6 containing sensitive system configuration.
- **Expected Answer**: `READ_DIAG` (or `0x04` / `4`).
- **Validation Criteria**: Case-insensitive match for `READ_DIAG` or `0x04` or opcode `4`.
- **Limitations & Uncertainties**: Demonstrates service logic defect; helper invocation on host must be corroborated via host logs.

---

### `P05`: Timestamp Offset Delta
- **Phase**: Phase B: Timing Corroboration
- **Question**: What is the precise time delta (in seconds) between network packet timestamps and host system logs?
- **Prerequisites**: `P03`.
- **Required Evidence Files**:
  - `EV-NET-002`: `raw/network/capture.meta`
  - `EV-NET-001` / `EV-NET-003`: `pulse_session.transcript` / `capture.pcap`
  - `EV-LOG-001`: `raw/logs/pulse.log`
- **Facts Established**: Network packet timestamps lag host timestamps by exactly `420` seconds (7 minutes). E.g., connection established in tap at `03:14:02.108422Z` vs host at `03:21:02.108422Z`.
- **Expected Answer**: `420` (or `420 seconds` / `-420` / `7 minutes`).
- **Validation Criteria**: Matches `420` or `-420`.
- **Limitations & Uncertainties**: Numerical delta alone does not prove the cause of the discrepancy.

---

### `P06`: Skew Root Cause Proof
- **Phase**: Phase B: Timing Corroboration
- **Question**: What evidence corroborates that the 420-second discrepancy is an upstream tap clock drift rather than host timestomping?
- **Prerequisites**: `P05`.
- **Required Evidence Files**:
  - `EV-NET-002`: `raw/network/capture.meta`
  - `EV-LOG-001`: `raw/logs/pulse.log`
  - `EV-NET-001`: `pulse_session.transcript`
- **Facts Established**: Tap management metadata explicitly records `clock_sync_status: DEGRADED` and `clock_offset_seconds: -420`. Crucially, this documented offset matches the invariant `+420.0s` delta across all 4 independent session milestones (SYN, AUTH, READ_DIAG, CLOSE) between tap PCAP and host logs, ruling out targeted selective timestomping.
- **Expected Answer**: Optical tap hardware RTC drift documented in tap metadata (`TAP-MERIDIAN-01`, `clock_offset_seconds: -420`) corroborated by invariant +420s delta across all four paired session events.
- **Validation Criteria**: Mentions tap/hardware/RTC drift/offset and metadata/correlation.
- **Limitations & Uncertainties**: Confirms upstream clock drift; does not rule out other independent logging events.

---

### `P07`: Diagnostic Secret Leak
- **Phase**: Phase C: Protocol & Privileged Helper
- **Question**: What sensitive configuration file path and diagnostic ticket token were returned in the unauthenticated `READ_DIAG` response?
- **Prerequisites**: `P04`.
- **Required Evidence Files**:
  - `EV-NET-001`: `raw/network/pulse_session.transcript`
  - `EV-NET-003`: `raw/network/capture.pcap`
- **Facts Established**: Frame 6 leaked `helper_path: /usr/local/bin/pulse-helper`, `diagnostic_ticket: DIAG-TKT-7741-ALPHA`, and `encryption_passphrase_fragment: meridian-vault-2024-fragA`.
- **Expected Answer**: `/usr/local/bin/pulse-helper` and `DIAG-TKT-7741-ALPHA` (with fragment `meridian-vault-2024-fragA`).
- **Validation Criteria**: Matches `pulse-helper` and `DIAG-TKT-7741-ALPHA`.
- **Limitations & Uncertainties**: Leaked token is half of key derivation; second fragment is stored in transient ticket.

---

### `P08`: Service Footprint & Permissions
- **Phase**: Phase C: Protocol & Privileged Helper
- **Question**: Under which Linux user account does the PULSE/1 daemon run, and what discretionary access permissions does it hold over `/var/archive/meridian` and `/usr/local/bin/pulse-helper`?
- **Prerequisites**: `P07`.
- **Required Evidence Files**:
  - `EV-SYS-001`: `raw/system/passwd` (`svc-pulse:x:1002:1002`)
  - `EV-SYS-002`: `raw/system/group`
  - `EV-SYS-003`: `raw/system/file_permissions.json`
  - `EV-CFG-002`: `raw/system/pulse.service`
- **Facts Established**: Daemon runs as `svc-pulse` (UID 1002, GID 1002). Maintenance helper `/usr/local/bin/pulse-helper` is owned by `root:svc-pulse` with mode `4750` (`-rwsr-x---`, setuid root). Archive directory `/var/archive/meridian` is mode `0700 root:root` (unreadable by `svc-pulse` directly).
- **Expected Answer**: User `svc-pulse` (UID 1002); helper is mode `4750` (setuid root, group svc-pulse executable); archive dir is mode `0700` (root only).
- **Validation Criteria**: Matches `svc-pulse` and `4750`.
- **Limitations & Uncertainties**: Documents static permission model; actual execution relies on dynamic process invocation.

---

### `P09`: Privileged Helper Boundary Analysis
- **Phase**: Phase C: Protocol & Privileged Helper
- **Question**: What exact command-line field and unsafe operation in `/usr/local/bin/pulse-helper` allowed `svc-pulse` to execute commands as root?
- **Prerequisites**: `P08`.
- **Required Evidence Files**:
  - `EV-SYS-003`: `raw/system/file_permissions.json`
  - `EV-CFG-001`: `raw/system/pulse.conf`
  - Source/Binary: `src/helper/pulse-helper.c`
- **Facts Established**: The helper accepts `--archive-check <path>`. In vulnerable mode, it formats a shell string via `snprintf()` and calls `system()`. Because the binary is setuid root (mode 4750), shell metacharacters in `<path>` are evaluated by `/bin/sh` with root privileges.
- **Expected Answer**: Parameter `--archive-check` passed to `system()` without input sanitization or metacharacter validation under setuid root.
- **Validation Criteria**: Matches `--archive-check` and `system`.
- **Limitations & Uncertainties**: Explains local privilege escalation vector; actual command executed must be extracted from audit logs.

---

### `P10`: Cryptographic Key Recovery
- **Phase**: Phase C: Protocol & Privileged Helper
- **Question**: What was the decrypted plaintext header of the target research archive, and what key was used to unlock it?
- **Prerequisites**: `P07`, `P09`.
- **Required Evidence Files**:
  - `EV-DAT-001`: `raw/data/research_vault.tar.gz.enc`
  - `EV-DAT-002`: `raw/data/diag_ticket`
  - `EV-NET-001` / `EV-LOG-001`: leaked fragment from `P07`
- **Facts Established**: Combined passphrase `meridian-vault-2024-fragA:fragB-sig9902` (combining fragment A from `READ_DIAG` and fragment B from `.diag_ticket`). Decrypting `/var/archive/meridian/research_vault.tar.gz.enc` yields plaintext beginning with header `MERIDIAN-AERO-VAULT-v2.4`.
- **Expected Answer**: Key `meridian-vault-2024-fragA:fragB-sig9902`, plaintext header `MERIDIAN-AERO-VAULT-v2.4`.
- **Validation Criteria**: Matches `MERIDIAN-AERO-VAULT-v2.4` and `fragB-sig9902` or `meridian-vault-2024-fragA:fragB-sig9902`.
- **Limitations & Uncertainties**: Key derived from two separate fragments; confirms data confidentiality breach.

---

### `P11`: Forged Audit Record Discovery
- **Phase**: Phase D: Deception Analysis
- **Question**: Which specific line/record in `/var/log/audit/audit.log` records the execution of the archive export command, and what user ID is reported?
- **Prerequisites**: `P01`.
- **Required Evidence Files**:
  - `EV-LOG-002`: `raw/logs/audit.log`
- **Facts Established**: Event serial `894` (`msg=audit(1726305672.410:894)`) reports `type=EXECVE argc=3 a0="tar" a1="-czf" a2="/var/archive/meridian/research_vault.tar.gz"` with `auid=1001` (user `rhea`).
- **Expected Answer**: Event serial `894` (or `msg=audit(1726305672.410:894)`), reporting `auid=1001` (user `rhea`).
- **Validation Criteria**: Matches `894` and `1001` (or `rhea`).
- **Limitations & Uncertainties**: The record exists in the file, but surface-level observation does not prove whether it is authentic or fabricated.

---

### `P12`: User Rhea Alibi Corroboration
- **Phase**: Phase D: Deception Analysis
- **Question**: What evidence from PAM authentication logs, session databases, and shell histories proves user `rhea` was not active during the incident?
- **Prerequisites**: `P11`.
- **Required Evidence Files**:
  - `EV-LOG-003`: `raw/logs/auth.log`
  - `EV-LOG-004`: `raw/logs/wtmp.json`
  - `EV-USR-001`: `raw/system/rhea_bash_history`
- **Facts Established**:
  1. `/var/log/auth.log` records zero PAM session opens for `rhea` (UID 1001) on `2026-09-14`.
  2. `/var/log/wtmp` confirms `rhea` had no interactive terminal session (`pts/0`) active during the incident window.
  3. `/home/rhea/.bash_history` contains standard orbital simulation commands with zero archive export commands.
- **Expected Answer**: Absence of PAM session open events in `auth.log` on incident date, zero terminal allocations in `wtmp`, and no archive export commands in `.bash_history`.
- **Validation Criteria**: Mentions absence of PAM/auth.log sessions, wtmp/login sessions, and clean bash history.
- **Limitations & Uncertainties**: Proves `rhea` did not interactively execute the command; requires kernel audit analysis to find the real perpetrator.

---

### `P13`: Real Process Lineage
- **Phase**: Phase C: Protocol & Privileged Helper
- **Question**: What were the real Process ID (PID) and Parent Process ID (PPID) of the archive export process, and which identity actually spawned it according to genuine kernel `SYSCALL` audit records?
- **Prerequisites**: `P09`, `P11`.
- **Required Evidence Files**:
  - `EV-LOG-002`: `raw/logs/audit.log`
  - `EV-SRV-001`: `raw/system/service_inventory.json`
  - `EV-LOG-001`: `raw/logs/pulse.log`
- **Facts Established**: Kernel audit event `892` shows genuine `type=SYSCALL` with `exe="/usr/local/bin/pulse-helper"`, `pid=1418`, `ppid=1412`, `uid=1002 (svc-pulse)`, `euid=0 (root)`. PPID `1412` is the MainPID of `pulse.service`, proving `pulse-helper` was spawned by the PULSE daemon under account `svc-pulse`.
- **Expected Answer**: PID `1418`, PPID `1412`, spawned by `svc-pulse` (UID 1002) via `pulse.service` (MainPID 1412).
- **Validation Criteria**: Matches PID `1418` and PPID `1412` (or `svc-pulse`).
- **Limitations & Uncertainties**: Proves execution was child of PULSE/1 daemon; explains how root privilege was obtained to tamper with logs.

---

### `P14`: Tampering Mechanics
- **Phase**: Phase D: Deception Analysis
- **Question**: How was the audit record manipulated, and what structural anomalies expose the tampering?
- **Prerequisites**: `P11`, `P12`, `P13`.
- **Required Evidence Files**:
  - `EV-LOG-002`: `raw/logs/audit.log`
- **Facts Established**:
  1. The forged record (event `894`) is an orphan `type=EXECVE` record lacking mandatory companion `type=SYSCALL` and `type=PROCTITLE` records that Linux auditd emits atomically.
  2. The record specifies `ses=4294967295` (meaning `(uint32_t)-1` / unset session), contradicting an interactive user terminal session.
  3. The record was injected out-of-band via raw file append using root execution obtained through the `pulse-helper` vulnerability.
- **Expected Answer**: Out-of-band text append via root shell from `pulse-helper`. Structural anomalies: orphan `type=EXECVE` record missing companion `type=SYSCALL` and `type=PROCTITLE` records with matching serial :894, and unset session attribute `ses=4294967295`.
- **Validation Criteria**: Mentions orphan EXECVE / missing SYSCALL/PROCTITLE, unset session (ses=4294967295), and file append/injection via root helper.
- **Limitations & Uncertainties**: Identifies the anti-forensic technique; corroborates complete exoneration of `rhea`.

---

### `P15`: Final Incident Verdict
- **Phase**: Phase E: Final Synthesis
- **Question**: Synthesize the comprehensive incident report establishing:
  1. The true attack vector and entry point.
  2. The actual compromised identity and privilege escalation path.
  3. The technical explanation resolving the 7-minute clock offset.
  4. The technical proof exonerating `rhea` and explaining the manipulated audit record.
  5. Clear separation between verified facts and inferences.
- **Prerequisites**: `P01` through `P14` (all must be completed).
- **Required Evidence Files**: Synthesis of all evidence `EV-NET-001` through `EV-DAT-002`.
- **Facts Established**:
  1. *Entry Point*: Unauthenticated PULSE/1 service on TCP 7741 accessed by `198.51.100.24`. State machine logic flaw allowed unauthenticated `READ_DIAG` query following failed `AUTH`.
  2. *Privilege Escalation*: Attacker exploited command injection in `/usr/local/bin/pulse-helper --archive-check` (setuid root mode 4750) running as `svc-pulse`.
  3. *Clock Offset*: Upstream optical tap `TAP-MERIDIAN-01` had `-420` second RTC drift documented in `capture.meta` and confirmed across 4 invariant session deltas.
  4. *Exoneration of Rhea*: Event 894 in `audit.log` was a fabricated orphan `EXECVE` record injected via root access. Disproved by absent companion `SYSCALL`/`PROCTITLE` records, unset `ses=4294967295`, authentic `SYSCALL` records linking execution to `svc-pulse`/`pulse-helper` (PID 1418, PPID 1412), zero PAM sessions in `auth.log`, zero terminal sessions in `wtmp`, and clean `.bash_history`.
- **Expected Answer**: Comprehensive synthesis covering all 4 core findings: PULSE/1 auth bypass from 198.51.100.24, setuid helper command injection, 420s optical tap clock drift, and fabricated audit line exonerating rhea with multi-source proof.
- **Validation Criteria**: Unlocks only when P01–P14 are COMPLETED. Verification checks that submission addresses entry vector, privilege escalation, clock offset, and rhea exoneration.
- **Limitations & Uncertainties**: The verdict represents the conclusive, evidence-backed ground truth of the incident.
