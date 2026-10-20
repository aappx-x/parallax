# PARALLAX — Ubuntu ARM64 Lab Setup & Operational Guide

This guide describes how to establish, operate, verify, and cleanly shut down the isolated Ubuntu Server ARM64 lab environment for the **PARALLAX — The Evidence Is Lying** investigation challenge.

---

## 1. Environment & Architecture Overview

- **Host System**: Apple Silicon Mac (M-series ARM64 architecture).
- **Hypervisor**: [UTM](https://mac.getutm.app/) (native Apple Virtualization framework and QEMU backend).
- **Guest OS**: Ubuntu Server 24.04 LTS (Noble Numbat) ARM64.
- **Service Isolation**: All PARALLAX network services bind strictly to loopback (`127.0.0.1`). Public port forwarding and exposure to the host LAN are prohibited.

### Host VM Accessibility Status (Milestone 2)

During the Milestone 2 environment inspection on the developer machine:
- UTM (`/Applications/UTM.app`) was confirmed installed on the macOS host.
- No active or pre-configured Ubuntu Server 24.04 ARM64 VM was detected in UTM storage (`~/Library/Containers/com.utmapp.UTM/Data/Documents/`).
- Consequently, tests and verification in Milestone 2 were executed and validated on the macOS ARM64 host (Darwin `arm64`, Python 3.14), while establishing the complete, tested verification tooling and step-by-step procedures required for the Ubuntu ARM64 environment below.

---

## 2. Preparing the Isolated Ubuntu ARM64 VM in UTM

Follow these steps to instantiate the reference Ubuntu Server 24.04 ARM64 virtual machine:

### A. Download the Official Ubuntu Server ARM64 ISO
Download the Ubuntu 24.04 LTS Server `arm64` ISO:
```bash
# Example official release URL
https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-arm64.iso
```

### B. Create VM in UTM
1. Open UTM and click **Create a New Virtual Machine** (`+`).
2. Select **Virtualize** (do not select Emulate, to leverage native Apple Silicon hardware acceleration).
3. Select **Linux**.
4. Check **Use Apple Virtualization** (or standard QEMU if preferred).
5. Browse and select the downloaded `ubuntu-24.04-live-server-arm64.iso`.
6. Configure Hardware:
   - **RAM**: 4096 MB (4 GB).
   - **CPU Cores**: 2 to 4 cores.
   - **Storage**: 20 GB (QCOW2 or raw disk).
7. Network: Use **Shared Network** (NAT). Do not configure bridged networking or host port forwarding.
8. Shared Directory (optional): Enable VirtFS/WebDAV share pointing to your local repository directory.

### C. OS Installation & User Configuration
1. Start the VM and proceed through the standard Ubuntu installer.
2. Set default user account:
   - Username: `analyst` (or your preferred administrative user).
   - Hostname: `meridian-lab`
3. Install OpenSSH server if terminal access from the host via SSH is desired:
   - If using SSH via UTM port forward, forward only an arbitrary high port (e.g. host `2222` to guest `22`).
   - Never forward the PULSE/1 service port (`7741`) outside the guest loopback.

---

## 3. System Prerequisites & Environment Setup

Log into the Ubuntu VM shell and execute the following:

### A. Update System and Install Prerequisites
Ubuntu 24.04 enforces PEP 668 (`externally-managed-environment`), requiring virtual environments for Python package development.

```bash
sudo apt update && sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    build-essential \
    iproute2 \
    net-tools \
    curl
```

### B. Verify System and Python Versions
```bash
uname -m          # Must output: aarch64
python3 --version  # Must output: Python 3.11.x or 3.12.x
```

### C. Clone or Transfer Repository
If using Git:
```bash
git clone https://github.com/appx/parallax.git
cd parallax
git checkout feature/pulse-protocol
```
If using UTM VirtFS shared directory, mount the share into `/mnt/parallax` or copy it to the home directory:
```bash
cd ~/parallax
```

### D. Create and Activate Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools
```

### E. Install PARALLAX in Editable Mode with Dev Dependencies
```bash
pip install -e ".[dev]"
```

Verify installation:
```bash
python3 -c "import parallax; print('PARALLAX version:', parallax.__version__)"
```
Output:
```text
PARALLAX version: 0.1.0.dev0
```

---

## 4. Repeatable Lab Verification & Test Execution

PARALLAX provides automated verification tools to ensure that the environment, protocol daemon, authentication flaw reproduction, corrected mode, and integrity subsystems function deterministically.

### A. Execute the Automated Test Suite
Run the complete unit and integration test suite:
```bash
pytest -v
```
Expected result: 98 passed tests (on Linux/ARM64) or 90 passed, 8 skipped (on Windows/macOS without C compiler).

### B. Execute Repeatable Lab Verification Suite
Run the self-contained verification tool:
```bash
python3 -m parallax.verify
```
or via the unified CLI:
```bash
python3 -m parallax.pulse verify
```

Expected output:
```text
======================================================================
 PARALLAX Investigation Foundation — Verification Suite
======================================================================
[PASS] Environment and Package Metadata
       Details: OS=Linux, Arch=aarch64, Python=3.12.x, parallax=0.1.0.dev0
[PASS] Server Lifecycle & Teardown
       Details: Clean startup, HELLO exchange, and deterministic port release on <ephemeral-port>
[PASS] Vulnerable Flaw Reproduction
       Details: Flaw verified: READ_DIAG permitted after failed AUTH (helper_path=/usr/local/bin/pulse-helper)
[PASS] Corrected Defense Enforcement
       Details: Defense verified: READ_DIAG rejected with 403 Forbidden after failed AUTH
[PASS] Privileged Helper & Boundary Flaw
       Details: C helper compiled cleanly; vulnerable injection reproduced and hardened execv() verified
[PASS] Linux Security Boundaries
       Details: Specs valid. Linux host audit: <compliant-count>/5 boundary paths present on filesystem
[PASS] Demo Suite Execution
       Details: Self-contained demo suite completed both vulnerable and corrected modes
[PASS] Manifest Subsystem
       Details: SHA-256 calculation, manifest generation, and tamper detection passed
[PASS] Workspace Evidence Integrity
       Details: All 4 raw evidence artifacts verified against SHA-256 manifest
======================================================================
[+] ALL VERIFICATION CHECKS PASSED.
```

### C. Run the Interactive Demonstration Suite
Run the full 4-step breach sequence comparison:
```bash
python3 -m parallax.pulse demo --mode both
```

---

## 5. Operating Standalone PULSE/1 Daemons

To test client interactions against a dedicated background or foreground daemon, run the service on loopback (`127.0.0.1`).

### Starting the Vulnerable Daemon (Scenario Flaw Active)
In a dedicated terminal tab or background job:
```bash
python3 -m parallax.pulse server --host 127.0.0.1 --port 7741 --vulnerable
```
Output:
```text
[*] Starting PULSE/1 daemon on 127.0.0.1:7741 [VULNERABLE (scenario flaw active)]
```

### Starting the Corrected Daemon (Hardened Mode)
```bash
python3 -m parallax.pulse server --host 127.0.0.1 --port 7741
```
Output:
```text
[*] Starting PULSE/1 daemon on 127.0.0.1:7741 [CORRECTED (secure)]
```

---

## 6. Exercising the State Machine Flaw with the CLI Client

While the server is running on `127.0.0.1:7741`, use the CLI client to execute each step of the breach sequence manually:

### Step 1: Handshake (HELLO)
```bash
python3 -m parallax.pulse client --host 127.0.0.1 --port 7741 hello
```
Expected Response:
```json
[STATUS] {
  "status": "ready",
  "service": "PULSE/1",
  "version": "0.1.0",
  "vulnerable_mode": true
}
```

### Step 2: Failed Authentication Attempt (AUTH)
Send invalid credentials:
```bash
python3 -m parallax.pulse client --host 127.0.0.1 --port 7741 auth -u svc-pulse -p WrongPasswordAttempt
```
Expected Response:
```json
[ERROR] {
  "error": "Authentication Failed",
  "code": 401
}
```

### Step 3: Diagnostic Telemetry Request (READ_DIAG)
Request privileged diagnostic configuration:
```bash
python3 -m parallax.pulse client --host 127.0.0.1 --port 7741 read-diag -s system_config
```

- **Against Vulnerable Server**:
  The server erroneously treats the session as authenticated due to the flawed state transition:
  ```json
  [READ_DIAG] {
    "section": "system_config",
    "service": "PULSE/1",
    "version": "0.1.0",
    "daemon_user": "svc-pulse",
    "helper_path": "/usr/local/bin/pulse-helper",
    "config_path": "/etc/pulse/pulse.conf",
    "archive_directory": "/var/archive/meridian",
    "diagnostic_ticket": "DIAG-TKT-7741-ALPHA",
    "encryption_passphrase_fragment": "meridian-vault-2024-fragA"
  }
  ```
- **Against Corrected Server**:
  The server properly enforces state `AUTHENTICATED` and rejects the request:
  ```json
  [ERROR] {
    "error": "Authentication required",
    "code": 403
  }
  ```

### Step 4: Graceful Session Termination (CLOSE)
```bash
python3 -m parallax.pulse client --host 127.0.0.1 --port 7741 close
```
Expected Response:
```json
[CLOSE] {
  "status": "closed",
  "message": "Session terminated"
}
```

---

## 7. Clean Lab Shutdown Procedures

Always ensure all running daemon processes and bound sockets are released before terminating your session:

1. **Stop Foreground Daemons**:
   Press `Ctrl+C` in the terminal running the server. The server intercepts `SIGINT`, ceases accepting connections, closes open client sockets, and releases the listening port.

2. **Verify Port Release**:
   Check if port 7741 is still bound:
   ```bash
   ss -tulpn | grep 7741
   ```
   (Should return no active listeners).

3. **Terminate Lingering Background Daemons (if any)**:
   ```bash
   pkill -f "parallax.pulse server"
   ```

4. **Deactivate Virtual Environment**:
   ```bash
   deactivate
   ```

5. **Shut Down Guest VM**:
   ```bash
   sudo poweroff
   ```

---

## 8. Troubleshooting Common Issues

### Issue 1: `OSError: [Errno 98] Address already in use`
- **Cause**: A previous daemon process was killed without closing its listening socket, or another service is listening on port 7741.
- **Remedy**:
  Find and kill the process holding the port:
  ```bash
  sudo lsof -i :7741
  # or
  fuser -k 7741/tcp
  ```

### Issue 2: `error: externally-managed-environment` on `pip install`
- **Cause**: Ubuntu 24.04 marks system Python packages as externally managed to protect APT integrity.
- **Remedy**: Always create and activate a virtual environment (`python3 -m venv .venv && source .venv/bin/activate`) before running `pip install`. Never use `--break-system-packages`.

### Issue 3: `ModuleNotFoundError: No module named 'parallax'`
- **Cause**: The package was not installed in editable mode, or the virtual environment is inactive.
- **Remedy**:
  ```bash
  source .venv/bin/activate
  pip install -e ".[dev]"
  ```

### Issue 4: Connection refused when running client commands
- **Cause**: The PULSE/1 server is not running or is bound to a different interface.
- **Remedy**: Ensure the server was started with `--host 127.0.0.1 --port 7741` and check status using `ss -tulpn | grep 7741`.

---

## 9. Privileged Helper Security Model & Safe Linux Boundary Validation

Milestone 5 validates the privileged helper security model on actual Ubuntu Linux, reconciles cross-platform UID/GID and shell behavior, and establishes safe, repeatable test procedures without installing live setuid binaries or altering host audit policy.

### 9.1 Helper Architecture & Build Modes

The maintenance helper (`src/helper/pulse-helper.c`) simulates an internal Meridian utility intended for verifying backup archive integrity:

| Target | Build Command | Description | Security Posture |
| :--- | :--- | :--- | :--- |
| **`pulse-helper`** (Vulnerable) | `make pulse-helper` or `cc -Wall -Wextra -O2 -std=c99 -o pulse-helper pulse-helper.c` | Standard build using legacy `system()` dispatch. | Vulnerable to command injection via shell metacharacters in `--archive-check`. |
| **`pulse-helper-fixed`** (Hardened) | `make pulse-helper-fixed` or `cc -Wall -Wextra -O2 -std=c99 -DFIXED_MODE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o pulse-helper-fixed pulse-helper.c` | Hardened reference build. | Path whitelist, metacharacter filtering, traversal blocking, permanent privilege drop (`setgid` + `setuid`), and direct `execv()` dispatch. |

#### Building Both Modes Safely
From within the repository root:
```bash
cd src/helper
make
./pulse-helper --version
./pulse-helper-fixed --version
```

### 9.2 Real UID, Effective UID, and Linux Shell Privilege Behavior

Modern Linux distributions enforce security safeguards that affect setuid process execution:

1. **POSIX Identity Model**:
   - When an unprivileged user (e.g., `svc-pulse`, UID 1002) executes a setuid-root binary (`chmod 4750 root:svc-pulse`), the Linux kernel establishes:
     - Real UID (`ruid`) = 1002
     - Effective UID (`euid`) = 0
     - Saved Set-User-ID (`suid`) = 0
2. **Ubuntu `/bin/sh` Privilege Dropping**:
   - On Ubuntu, `/bin/sh` is symlinked to `dash` (Debian Almquist Shell).
   - When `dash` (or `bash` in POSIX mode) starts without the `-p` (privileged) switch, it checks if `ruid != euid`.
   - If `ruid != euid`, `dash` immediately resets `euid = ruid` (dropping effective privileges to the caller UID).
   - Consequently, calling `system()` directly in a setuid binary causes `dash` to drop root privileges to `svc-pulse`.
3. **Vulnerable Mode Ground-Truth Synchronization**:
   - To authentically exhibit the scenario ground truth (where an attacker escalates from `svc-pulse` to `root` to append a record to root-only `/var/log/audit/audit.log`), classic setuid utilities synchronize `ruid` with `euid` via `setuid(0)` when running elevated.
   - In `pulse-helper.c`, when `geteuid() == 0`, `setuid(0)` is invoked prior to `system()`. This synchronizes `ruid = 0`, ensuring that `/bin/sh` retains root execution.
4. **Hardened Mode Privilege Drop**:
   - In `pulse-helper-fixed`, the helper permanently drops both group and user privileges prior to subprocess execution:
     ```c
     setgid(getgid());  // Drop group privileges first
     setuid(getuid());  // Drop root permanently to real caller UID
     ```
   - It replaces shell dispatch (`system()`) with direct `execv()` invocation of `/usr/bin/tar` or `/bin/tar`, rendering shell injection impossible.

### 9.3 Safe Validation Procedure

The automated test suite (`tests/test_boundary.py`) validates both helper modes without requiring root privileges, setuid installation, or host modifications:

- **Isolated Temporary Directories**: Tests compile and execute helper binaries within isolated temporary workspaces (`tempfile.TemporaryDirectory`).
- **Harmless Marker Files**: Injection testing uses safe canary markers (`touch <tmp_path>/pwned.canary`) within the temporary workspace. No files outside the temporary directory are accessed or created.
- **Path Traversal & Boundary Tests**:
  - Direct traversal attempts (`f"{archive_dir}/../secret.txt"`) are rejected.
  - Out-of-bounds paths (`/etc/passwd`) are rejected.
  - Sibling directory prefix collision attacks (`f"{archive_dir}_evil/payload.tar.gz"` vs `archive_dir`) are strictly blocked by directory boundary validation.
- **Shell Metacharacter Validation**: Verifies rejection of `;`, `&`, `|`, `&&`, `||`, `` ` ``, `$()`, `>`, `<`, and `\n`.
- **Legitimate Archive Functionality**: Verifies that genuine `.tar.gz` archives pass validation and integrity checking in both modes without breaking operational requirements.

### 9.4 What the Tests Demonstrate vs What Remains Unverified

#### What the Tests Demonstrate:
- Command injection vectors are reliably reproducible in `pulse-helper`.
- The hardened helper rejects all metacharacters, traversal sequences, and unauthorized directory paths.
- The hardened helper successfully validates genuine compressed tar archives.
- Systemd service unit files and auditd rules conform to security best practices and least-privilege configurations.
- Evidence workspaces maintain cryptographic SHA-256 integrity across operating systems.

#### What Remains Unverified (Requires Live Isolated VM):
- **Live Setuid Execution**: Testing whether a live binary with mode `4750` owned by `root:svc-pulse` escalates privileges under an actual non-root user (`svc-pulse`) requires live root installation (`sudo chown root:svc-pulse ... && sudo chmod 4750 ...`).
- **Live Kernel Audit Logging**: Validating that `/usr/local/bin/pulse-helper` triggers kernel `SYSCALL` events in `/var/log/audit/audit.log` requires active kernel audit subsystem loading (`auditctl -R /etc/audit/rules.d/audit.rules`).
- **Systemd Service Cgroup Isolation**: Validating `ProtectSystem=full` and `PrivateTmp=true` mount namespace isolation requires live unit startup via `systemctl start pulse.service`.

> [!CAUTION]
> **Safety Notice**: Do not install setuid-root binaries, create local system accounts, or load active kernel audit rules on development host machines. Live privilege boundary tests must only be conducted in a dedicated, isolated guest VM (such as the reference UTM ARM64 VM).

