# PARALLAX — Scenario Design: The Meridian Research Incident

---

## 1. Incident Ground Truth

### 1.1 Context & Target
The incident takes place on a single self-contained Linux workstation hosted by **Meridian Research**, an aerospace computation laboratory. The system runs an experimental internal telemetry daemon known as **PULSE/1** bound to TCP port `7741`.

### 1.2 Attacker Identity & Entry Point
- **External Origin**: Fictional external IP `198.51.100.24` (RFC 5737 documentation prefix).
- **Service Target**: The PULSE/1 service running under the unprivileged dedicated system account `svc-pulse`.
- **Initial Connection**: The attacker establishes a TCP connection to port `7741`.

### 1.3 PULSE/1 Exploitation Mechanism
The service utilizes the standard binary framing layout:
- `4 bytes`: Magic identifier (`PULS` / `0x50554c53`)
- `1 byte`: Protocol version (`0x01`)
- `1 byte`: Message type identifier
- `2 bytes`: Big-endian (network byte order) unsigned 16-bit integer denoting payload length
- `N bytes`: UTF-8 encoded JSON payload

The agreed initial message types are:
1. `HELLO` (`0x01`): Client initiates session handshake.
2. `AUTH` (`0x02`): Client submits credentials.
3. `STATUS` (`0x03`): Server returns operational telemetry.
4. `READ_DIAG` (`0x04`): Diagnostic query request.
5. `CLOSE` (`0x05`): Graceful connection termination.
6. `ERROR` (`0x06`): Error condition notification.

**The Flaw**: When the attacker submits invalid credentials via `AUTH`, the server emits an `ERROR` message (`"Authentication Failed"`). However, the internal state machine fails to set an authorization guard flag and fails to reset or disconnect the session. The attacker immediately issues a `READ_DIAG` request with payload `{"section": "system_config"}`. The daemon erroneously processes the query and leaks internal configuration parameters, including the path to an internal maintenance utility (`/usr/local/bin/pulse-helper`) and an encryption passphrase fragment used for backup archives.

### 1.4 Privileged Helper Architecture & Vulnerability
- **Helper Architecture**: `/usr/local/bin/pulse-helper` is a minimal, compiled ARM64 C utility owned by `root:svc-pulse` with file permissions `4750` (`-rwsr-x---`).
- **Permissions**: When invoked by `svc-pulse`, it executes with effective UID 0 (root). It does not use ambient file capabilities; its elevated rights derive strictly from the setuid bit.
- **Intended Functionality**: Performs maintenance verification on protected backup archives in `/var/archive/meridian/` (owned by `root:root`, mode `0700`).
- **Exact Input Field**: The command-line argument `--archive-check <path>`.
- **Unsafe Operation**: In the archive integrity verification path, the helper formats a shell command string using `snprintf()` and executes it via `system()` without argument sanitization:
  ```c
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "/bin/tar -tzf %s >/dev/null 2>&1", archive_path);
  system(cmd);
  ```
- **Privilege Boundary Violation**: Because the binary runs setuid root, `system()` invokes `/bin/sh -c` with effective UID 0. Supplying shell metacharacters in `--archive-check` (e.g., `"/var/archive/meridian/research_vault.tar.gz.enc; <payload>"`) allows `svc-pulse` to execute arbitrary shell commands with root privileges.
- **Expected Vulnerable vs. Fixed Behavior**:
  - *Vulnerable Behavior*: Executes `/bin/sh -c` with unsanitized input under `euid=0`, permitting command chaining.
  - *Fixed Behavior*: Avoids the shell entirely by using `execv()` with a fixed argument vector (`{"/bin/tar", "-tzf", archive_path, NULL}`), validates that `archive_path` resides strictly within `/var/archive/meridian/` without directory traversal (`..`) or metacharacters, and drops privileges via `setuid(getuid())` before invoking external binaries.
- **Access to Vault**: Exploiting this injection, the attacker executes a command that decrypts `/var/archive/meridian/research_vault.tar.gz.enc` using the key recovered from `READ_DIAG` and stages it in `/tmp`.
- **Operational Limits**: The attacker does not establish persistent root access; execution is limited to transient commands executed through the exploited helper.

### 1.5 Anti-Forensic Tampering (Framing `rhea`)
To conceal the network service compromise and misdirect responders:
- Utilizing the root execution obtained through `pulse-helper`, the attacker appends **exactly one fabricated audit record** to `/var/log/audit/audit.log`.
- **Exact Record Type Forged**: A `type=EXECVE` record claiming employee `rhea` (`auid=1001`) executed an unauthorized archive export command (`tar -czf ...`) from terminal `pts/0`:
  `type=EXECVE msg=audit(1726305672.410:894): argc=3 a0="tar" a1="-czf" a2="/var/archive/meridian/research_vault.tar.gz"`
- The attacker then terminates the PULSE/1 session with a `CLOSE` frame over TCP `7741`.

### 1.6 Ground Truth Corroboration & Lineage Tracking
The true attack chain is corroborated by:
1. **Kernel Syscall Auditing**: Genuine kernel audit records configured via `/etc/audit/rules.d/audit.rules` (`-a always,exit -F arch=b64 -S execve`) capture the true process creation event. The authentic record logs `exe="/usr/local/bin/pulse-helper"` with `uid=1002 (svc-pulse)`, `euid=0`, and parent process ID (`ppid=1412`), proving that the helper was spawned by the PULSE/1 daemon (`PID 1412`).
2. **Systemd Service Cgroup**: `journalctl -u pulse.service` records that `MainPID=1412` was active and owned the cgroup `system.slice/pulse.service` under which `pulse-helper` was invoked.
3. **PULSE/1 Daemon Logs**: Application logs in `/var/log/pulse/pulse.log` record the incoming connection from `198.51.100.24`, the failed `AUTH`, the subsequent `READ_DIAG` query, and the child invocation of `pulse-helper`.
4. **PAM & Session Logs**: `/var/log/auth.log` and `/var/log/wtmp` prove that user `rhea` had no interactive or remote login session active during the incident window.

---

## 2. The Two Central Forensic Discrepancies

The scenario is strictly governed by **exactly two** forensic discrepancies:

```text
+-----------------------------------------------------------------------------------+
|                           The Two Central Discrepancies                           |
+-----------------------------------------------------------------------------------+
|  1. One Deliberately Manipulated Audit Record                                     |
|     - Target: /var/log/audit/audit.log                                            |
|     - Forged Record: Isolated `type=EXECVE` record attributing `tar` to `rhea`.   |
|     - Structural Anomaly: Lacks required companion `type=SYSCALL` and             |
|       `type=PROCTITLE` records with matching event serial (:894).                 |
|     - Corroboration: Disproved by absence of PAM sessions for `rhea` and positive |
|       kernel `SYSCALL` records linking the real process lineage to `svc-pulse`.   |
|                                                                                   |
|  2. One Legitimate Seven-Minute Clock Offset                                      |
|     - Target: /var/log/remote/capture.pcap vs. local host logs                    |
|     - Content: Network packet timestamps lag host system time by exactly 420s.    |
|     - Validation: Corroborated by supplied metadata (`capture.meta`) documenting  |
|       tap hardware drift (-420s) and matched against four paired session events.  |
|     - Reality: Benign operational artifact; not malicious timestomping.           |
+-----------------------------------------------------------------------------------+
```

### 2.1 Discrepancy 1: Manipulated Audit Record Framing `rhea`
- **Origin**: Appended to `/var/log/audit/audit.log` via the transient root execution obtained through `pulse-helper`.
- **Exact Forged Record**: An isolated `type=EXECVE` line attributing command execution to `auid=1001 (rhea)`:
  `type=EXECVE msg=audit(1726305672.410:894): argc=3 a0="tar" a1="-czf" a2="/var/archive/meridian/research_vault.tar.gz"`
- **Absent Companion Records & Significance**:
  - In Linux auditd, kernel syscall auditing configured for `execve` outputs multi-record event groups atomically sharing the same event timestamp and serial number: `type=SYSCALL`, `type=EXECVE`, and `type=PROCTITLE`.
  - In the forged event, the companion `type=SYSCALL` (which records kernel-verified `ppid`, `pid`, `uid`, `euid`, `comm`, and `exe`) and `type=PROCTITLE` records are absent.
  - Because the kernel audit dispatcher emits these records atomically through a netlink socket, an orphan `EXECVE` record indicates out-of-band text insertion rather than a kernel-dispatched audit event.
- **Corroborating Evidence (Why Missing Records Alone Are Not Conclusive)**:
  An incomplete audit record can theoretically arise from buffer drops or system crashes. Therefore, the structural omission is treated as an anomaly indicator, with conclusive proof established through positive corroboration:
  1. *Positive Kernel Audit Evidence*: At the same timestamp, genuine multi-record kernel audit events (`SYSCALL` + `EXECVE` + `PROCTITLE`) record the actual execution of `pulse-helper` with `uid=1002 (svc-pulse)`, `euid=0 (root)`, and `ppid=1418`.
  2. *PAM & Terminal Logs*: `/var/log/auth.log` and `/var/log/wtmp` prove no login or session allocation (`pts/0`) occurred for `rhea` on that date.
  3. *Unset Session Attribute*: The injected line specifies `ses=4294967295` (meaning `(uint32_t)-1` / unset), contradicting an interactive login session.
  4. *Shell History*: `/home/rhea/.bash_history` contains no archive commands.

### 2.2 Discrepancy 2: Legitimate Seven-Minute Clock Offset
- **Origin**: Benign operational artifact. Upstream capture interface `/var/log/remote/capture.pcap` had an unsynchronized hardware RTC running 7 minutes (420 seconds) behind the workstation's NTP-synchronized clock.
- **Capture-Metadata Artifact (`/var/log/remote/capture.meta`)**:
  Co-located with the PCAP, this structured metadata file documents the capture environment:
  ```json
  {
    "tap_device_id": "TAP-MERIDIAN-01",
    "interface": "eth0-span",
    "capture_file": "capture.pcap",
    "clock_sync_status": "DEGRADED",
    "clock_offset_seconds": -420,
    "calibration_note": "Hardware tap RTC drifted -420s relative to workstation host NTP clock."
  }
  ```
- **Validation Through Metadata and Matching Events**:
  A uniform timestamp difference alone does not prove whether time was manipulated or drifted. The 420-second offset is validated because the supplied metadata documentation matches the empirical delta observed across multiple distinct session events:
  1. *TCP SYN Handshake*: PCAP frame arrival at `03:14:02 UTC` matches socket connection in `pulse.log` at `03:21:02 UTC` (`Δt = +420s`).
  2. *Authentication Handshake*: PCAP `AUTH` frame at `03:14:15 UTC` matches `AUTH failed` entry in `pulse.log` at `03:21:15 UTC` (`Δt = +420s`).
  3. *Diagnostic Request*: PCAP `READ_DIAG` query frame at `03:14:28 UTC` matches diagnostic query dispatch in `pulse.log` at `03:21:28 UTC` (`Δt = +420s`).
  4. *Session Teardown*: PCAP `CLOSE` frame at `03:15:05 UTC` matches socket termination in `pulse.log` at `03:22:05 UTC` (`Δt = +420s`).
- **Proof of Truth**: The alignment between the recorded metadata offset and the invariant +420s delta across all four session milestones corroborates that the discrepancy is an upstream tap clock drift, ruling out targeted host timestomping or an unrelated connection.

---

## 3. Evidence Sources & Access Model

### 3.1 Evidence Access Model
The player operates exclusively as the unprivileged account `analyst` (UID `1000`, GID `1000`). The account is **not** granted `sudo`, `wheel`, or administrative membership in `adm`.

Narrowly scoped, read-only access is provisioned using explicit POSIX Access Control Lists (ACLs) and targeted group permissions:
- `/var/log/audit/audit.log`: Read-only access granted via POSIX file ACL: `setfacl -m u:analyst:r /var/log/audit/audit.log`.
- `/var/log/remote/`: Directory and files (`capture.pcap`, `capture.meta`) owned by `root:analyst` with permissions `0640` (files) and `0750` (directory).
- `/var/log/pulse/pulse.log`: Read-only access granted via POSIX file ACL: `setfacl -m u:analyst:r /var/log/pulse/pulse.log`.
- `/var/log/auth.log`: Mode `0644` (world-readable) or POSIX ACL `u:analyst:r`.
- `/var/log/journal/`: `analyst` is a member of the standard Linux `systemd-journal` group, granting non-administrative read-only access to system logs via `journalctl`.
- `/usr/local/bin/pulse-helper`: Mode `4750 root:svc-pulse`, with read permission granted via POSIX ACL `u:analyst:rx` to allow static reverse engineering without execution rights.

### 3.2 Evidence Sources Mapping Table

| Artifact / Path | Format / Subsystem | Status | Incident Fact Supported | Objective(s) |
| :--- | :--- | :--- | :--- | :--- |
| `/etc/pulse/pulse.conf` | Plaintext config | **Genuine** | Service configuration: listening port `7741`, maintenance helper path. | P01, P08 |
| `/var/log/pulse/pulse.log` | Application log | **Genuine** | Records connection from `198.51.100.24`, failed `AUTH`, and `READ_DIAG` dispatch. | P01, P03, P04, P05 |
| `/var/log/remote/capture.pcap` | Libpcap file | **Genuine (Offset)** | Raw packet capture showing wire frames; timestamps lag host clock by 420s. | P02, P03, P05, P06 |
| `/var/log/remote/capture.meta` | JSON metadata | **Genuine** | Documents upstream tap device ID, degraded clock status, and -420s offset. | P05, P06 |
| `/var/log/audit/audit.log` | Linux auditd log | **Manipulated (1 record)** | Contains authentic kernel `SYSCALL` records for `pulse-helper`, plus 1 isolated fabricated `EXECVE` record. | P11, P13, P14 |
| `/var/log/auth.log` | Syslog / PAM | **Genuine** | Proves user `rhea` had no active PAM login sessions during the breach. | P12 |
| `/var/log/journal/` | systemd journal | **Genuine** | Service lifecycle tracking confirming `MainPID=1412` for `pulse.service`. | P08, P13 |
| `/usr/local/bin/pulse-helper` | ARM64 ELF Binary | **Genuine** | Setuid-root binary; contains command injection in `--archive-check` argument handling. | P09 |
| `/var/archive/meridian/` | Filesystem directory | **Genuine** | Contains encrypted research archive (`research_vault.tar.gz.enc`) and access timestamps. | P07, P10 |
| `/home/rhea/.bash_history` | User shell history | **Genuine** | Proves absence of archive export commands in `rhea`'s user account. | P12 |
| `/var/tmp/.diag_ticket` | Encrypted artifact | **Genuine** | Transient diagnostic ticket left by helper execution containing archive decryption key material. | P07, P10 |

---

## 4. Objective Map: P01 to P15

```text
               +-------------------------------------------+
               |  Phase A: Initial Protocol Triage         |
               |  P01: Service Port Discovery              |
               |       |                                   |
               |       v                                   |
               |  P02: Protocol Wire Framing               |
               +-------------------------------------------+
                               |
               +---------------+---------------+
               |                               |
               v                               v
+-------------------------------+   +-------------------------------+
|  Phase B: Timing Corroboration|   |  Phase C: Protocol & Helper   |
|  P03: Attacker IP & Trace     |   |  P04: Auth State Logic Flaw   |
|       |                       |   |       |                       |
|       v                       |   |       v                       |
|  P05: Offset Identification   |   |  P07: Diagnostic Secret Leak  |
|       |                       |   |       |                       |
|       v                       |   +-------+-------+               |
|  P06: Skew Root Cause Proof   |   |               |               |
+-------------------------------+   |               v               |
                                    |         P08: Service Footprint|
                                    |               |               |
                                    v               v               |
                         +--------------------+ P09: Helper Boundary|
                         | P10: Key Recovery  |     |               |
                         +--------------------+     v               |
                                              P13: Process Lineage  |
                                                    |               |
               +------------------------------------+               |
               |                                                    |
               v                                                    |
+-------------------------------+                                   |
|  Phase D: Deception Analysis  |                                   |
|  P11: Forged Audit Discovery  |                                   |
|       |                       |                                   |
|       v                       |                                   |
|  P12: User Rhea Alibi         |                                   |
|       |                       |                                   |
|       v                       |                                   |
|  P14: Tampering Mechanics     |<----------------------------------+
+-------------------------------+
               |
               v
+-------------------------------------------------------------------+
|  Phase E: Final Synthesis                                         |
|  P15: Final Incident Verdict (Unlocks only after P01-P14 pass)    |
+-------------------------------------------------------------------+
```

### Detailed Objective Specifications

#### `P01`: Service Port Discovery
- **Question**: On which TCP port was the unauthenticated PULSE/1 service listening during the breach?
- **Evidence Required**: `/etc/pulse/pulse.conf`, `/var/log/pulse/pulse.log`, systemd unit definitions.
- **Prerequisites**: None.
- **Demonstrates**: Basic service triage and identification of non-standard local listening daemons.

#### `P02`: Protocol Wire Framing
- **Question**: What is the 4-byte magic identifier and byte layout of a PULSE/1 wire frame?
- **Evidence Required**: `/var/log/remote/capture.pcap`.
- **Prerequisites**: `P01`.
- **Demonstrates**: Network protocol reverse engineering and binary framing analysis.

#### `P03`: Attacker IP & Session Sequence
- **Question**: What was the external IP address of the client and the exact order of message types transmitted in the session?
- **Evidence Required**: `/var/log/remote/capture.pcap`, `/var/log/pulse/pulse.log`.
- **Prerequisites**: `P02`.
- **Demonstrates**: Correlation between raw PCAP session traffic and daemon application logs.

#### `P04`: Authentication State Machine Flaw
- **Question**: Which message type was accepted and processed by the daemon immediately after emitting an authentication failure error?
- **Evidence Required**: `/var/log/pulse/pulse.log`, `/var/log/remote/capture.pcap`.
- **Prerequisites**: `P03`.
- **Demonstrates**: Protocol state machine analysis and identification of logic flaws in state transitions.

#### `P05`: Timestamp Offset Identification
- **Question**: What is the precise time delta (in seconds) between network packet timestamps and host system logs, and what offset value is documented in the tap metadata?
- **Evidence Required**: `/var/log/remote/capture.meta`, frame timestamps in `/var/log/remote/capture.pcap`, `/var/log/pulse/pulse.log`.
- **Prerequisites**: `P03`.
- **Demonstrates**: Cross-source chronological timeline reconstruction and identifying tap hardware drift.

#### `P06`: Skew Root Cause Proof
- **Question**: What evidence corroborates that the 420-second discrepancy is an upstream tap clock drift rather than host timestomping?
- **Evidence Required**: Correlation between the documented offset in `/var/log/remote/capture.meta` and the invariant +420s delta across multiple paired session events (SYN, AUTH, READ_DIAG, CLOSE) between `capture.pcap` and `pulse.log`.
- **Prerequisites**: `P05`.
- **Demonstrates**: Multi-source corroboration distinguishing operational tap drift from hostile manipulation.

#### `P07`: Diagnostic Secret Leak
- **Question**: What sensitive configuration file path and diagnostic ticket token were returned in the unauthenticated `READ_DIAG` response?
- **Evidence Required**: Decoded JSON payload of `READ_DIAG` response in `capture.pcap`.
- **Prerequisites**: `P04`.
- **Demonstrates**: Network payload analysis and identification of information disclosure vulnerabilities.

#### `P08`: Service Footprint & Permissions
- **Question**: Under which Linux user account does the PULSE/1 daemon run, and what discretionary access permissions does it hold over `/var/archive/meridian` and `/usr/local/bin/pulse-helper`?
- **Evidence Required**: `/etc/passwd`, `/etc/systemd/system/pulse.service`, file mode `4750` on `/usr/local/bin/pulse-helper`.
- **Prerequisites**: `P07`.
- **Demonstrates**: Linux service identity analysis and DAC/setuid permission auditing.

#### `P09`: Privileged Helper Boundary Analysis
- **Question**: What exact command-line field and unsafe operation in `/usr/local/bin/pulse-helper` allowed `svc-pulse` to execute commands as root?
- **Evidence Required**: Disassembly / inspection of `/usr/local/bin/pulse-helper` (identifying unsafe `system()` call on `--archive-check` input).
- **Prerequisites**: `P08`.
- **Demonstrates**: Linux privilege boundary analysis, setuid binary reverse engineering, and command injection vulnerability identification.

#### `P10`: Cryptographic Key Recovery
- **Question**: What was the decrypted plaintext header of the target research archive, and what key was used to unlock it?
- **Evidence Required**: `/var/tmp/.diag_ticket`, leaked token from `P07`, `/var/archive/meridian/research_vault.tar.gz.enc`.
- **Prerequisites**: `P07`, `P09`.
- **Demonstrates**: Cryptographic analysis, parameter extraction, and local data recovery.

#### `P11`: Forged Audit Record Discovery
- **Question**: Which specific line/record in `/var/log/audit/audit.log` records the execution of the archive export command, and what user ID is reported?
- **Evidence Required**: `/var/log/audit/audit.log`.
- **Prerequisites**: `P01`.
- **Demonstrates**: Linux audit log analysis and identifying focal points of suspected compromise.

#### `P12`: User Rhea Alibi Corroboration
- **Question**: What evidence from PAM authentication logs, session databases, and shell histories proves user `rhea` was not active during the incident?
- **Evidence Required**: `/var/log/auth.log`, `/var/log/wtmp`, `/home/rhea/.bash_history`.
- **Prerequisites**: `P11`.
- **Demonstrates**: Multi-source log corroboration to refute false attribution indicators.

#### `P13`: Real Process Lineage
- **Question**: What were the real Process ID (PID) and Parent Process ID (PPID) of the archive export process, and which identity actually spawned it according to genuine kernel `SYSCALL` audit records?
- **Evidence Required**: Kernel `SYSCALL` records in `/var/log/audit/audit.log`, `pulse.log`, and `journalctl -u pulse.service`.
- **Prerequisites**: `P09`, `P11`.
- **Demonstrates**: Low-level kernel process tracking, PPID correlation, and distinguishing genuine kernel audit records from injected file entries.

#### `P14`: Tampering Mechanics
- **Question**: How was the audit record manipulated, and what structural anomalies (orphan `type=EXECVE` record, missing kernel `type=SYSCALL` companion record, unset session `ses=4294967295`) expose the tampering?
- **Evidence Required**: Detailed audit record comparison in `/var/log/audit/audit.log`.
- **Prerequisites**: `P11`, `P12`, `P13`.
- **Demonstrates**: Deep anti-forensic analysis and detection of log manipulation techniques.

#### `P15`: Final Incident Verdict
- **Question**: Submit the comprehensive incident report establishing:
  1. The true attack vector and entry point.
  2. The actual compromised identity and privilege escalation path.
  3. The technical explanation resolving the 7-minute clock offset.
  4. The technical proof exonerating `rhea` and explaining the manipulated audit record.
  5. Clear separation between verified facts and inferences.
- **Evidence Required**: Synthesis of verified outputs from `P01` through `P14`.
- **Prerequisites**: `P01` through `P14` (all must be completed before submission is unlocked).
- **Demonstrates**: Professional DFIR incident reporting, root-cause analysis, and evidence-supported verdict synthesis.

---

## 5. Technical Parameters & Concrete Implementation Decisions

1. **Helper Binary Implementation**:
   - Binary path: `/usr/local/bin/pulse-helper`, compiled ARM64 C binary, owned by `root:svc-pulse`, mode `4750` (`-rwsr-x---`).
   - Vulnerable argument: `--archive-check <path>`.
   - Vulnerable operation: `snprintf` into fixed buffer passed to `system("/bin/tar -tzf <path> ...")`.
   - Fixed behavior: Uses direct `execv()` without a shell, validates path whitelist, drops privileges.

2. **Audit Tampering Details**:
   - Forged record: An isolated `type=EXECVE` record manually appended to `/var/log/audit/audit.log`.
   - Structural giveaway: Absence of paired `type=SYSCALL` and `type=PROCTITLE` records with matching event serial.
   - Conclusive corroboration: Genuine kernel `SYSCALL` audit events at that timestamp show parent `pulse-helper` under `svc-pulse`, and PAM logs confirm zero active sessions for `rhea`.

3. **Clock-Offset Validation**:
   - Artifact `/var/log/remote/capture.meta` explicitly documents `-420` second tap drift.
   - Corroboration relies on correlating the documented metadata against 4 paired session events (SYN, AUTH, READ_DIAG, CLOSE) between `capture.pcap` and `pulse.log`.

4. **Evidence Access Scheme**:
   - `analyst` (UID 1000) has no `sudo` and is not in `adm`.
   - Read-only access is provisioned via POSIX ACLs (`setfacl`) on `/var/log/audit/audit.log` and `/var/log/pulse/pulse.log`, group ownership on `/var/log/remote/`, and membership in `systemd-journal`.
