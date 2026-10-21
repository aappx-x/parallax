# PARALLAX — Maintainer & Appliance Build Guide

This guide describes how to provision, test, sanitize, and package the **PARALLAX** forensic investigation appliance for release across both supported virtualization targets:

- **Target A**: UTM on Apple Silicon (Ubuntu Server 24.04 LTS ARM64 / `aarch64`).
- **Target B**: Oracle VirtualBox on Windows (Ubuntu Server 24.04 LTS x86-64 / `amd64`).

---

## 1. Architectural Principles

1. **Single Codebase & Scenario Truth**: Both architectures run the identical Python application, CLI, synthetic evidence suite, SHA-256 manifests, and 15 investigation objectives.
2. **Minimal Architecture**: No Docker, Kubernetes, web frontends, databases, or third-party orchestration frameworks. The appliance runs standard systemd, auditd, and Python 3.
3. **Safe Preparation vs. Activation**:
   - `provision.sh --prepare` safely configures users, directories, evidence, and builds helpers as mode `0750` (non-setuid).
   - `provision.sh --activate` elevates `pulse-helper` to `04750` (setuid root for `svc-pulse`) and activates `pulse.service`. This step is **strictly restricted to dedicated, disposable guest virtual machines**.

---

## 2. Target Matrix & Environment Status

| Target | Architecture | Guest OS | Tested Environment | Status |
|:-------|:-------------|:---------|:-------------------|:-------|
| **Target A: UTM** | `aarch64` | Ubuntu Server 24.04 LTS | Apple Silicon Mac (macOS 26.4 / Darwin 25.4.0) | **Verified** |
| **Target B: VirtualBox** | `x86_64` | Ubuntu Server 24.04 LTS | Cross-platform build & descriptor validation | **Descriptor Validated** |

> [!CAUTION]
> **Host Safety Rule**:
> Never install a setuid-root helper executable (`pulse-helper`) or modify system accounts on the developer's macOS or Windows host machine. All live privileged testing must take place inside an isolated guest VM.

---

## 3. Provisioning a Fresh Ubuntu 24.04 Guest

### Step 1: Base Operating System Installation
1. Download official Ubuntu Server 24.04 LTS ISO:
   - ARM64: `ubuntu-24.04.5-live-server-arm64.iso`
   - x86-64: `ubuntu-24.04.5-live-server-amd64.iso`
2. Create VM in your hypervisor:
   - RAM: 4096 MB (4 GB)
   - CPU: 2 to 4 cores
   - Disk: 20 GB QCOW2 or VMDK
   - Network: Shared NAT
3. For unattended installation, supply the cloud-init configs from:
   - `infra/provisioning/cloud-init/user-data`
   - `infra/provisioning/cloud-init/meta-data`

### Step 2: Safe Guest Provisioning
Log into the guest VM as root or an administrative user with sudo access:

```bash
# Clone or transfer repository to /opt/parallax
cd /opt/parallax

# Dry-run inspection (evaluates host readiness without mutating)
./infra/provisioning/provision.sh --dry-run

# Execute safe provisioning
sudo ./infra/provisioning/provision.sh --prepare
```

The script will:
1. Verify operating system and architecture (`aarch64` or `x86_64`).
2. Install required packages (`python3`, `auditd`, `build-essential`, `iproute2`, `net-tools`, `acl`).
3. Idempotently configure lab accounts:
   - `analyst` (UID 1000, GID 1000, added to `systemd-journal`)
   - `rhea` (UID 1001, GID 1001)
   - `svc-pulse` (UID 1002, GID 1002)
4. Configure directories with strict Discretionary Access Control (DAC):
   - `/var/archive/meridian` (mode 0700 root:root)
   - `/var/log/pulse` (mode 0750 svc-pulse:svc-pulse)
   - `/etc/pulse` (mode 0755 root:root)
5. Stage synthetic evidence into `/home/analyst/evidence` (preserving existing notes and progress files if present).
6. Validate all 16 evidence SHA-256 checksums against `manifest.json`.
7. Compile `pulse-helper` (vulnerable) and `pulse-helper-fixed` (hardened) in safe mode `0750`.
8. Configure systemd unit `/etc/systemd/system/pulse.service` and audit rules `/etc/audit/rules.d/pulse.rules`.

---

## 4. Validating the Complete Investigation Experience

### A. Run Verification Inside Guest VM
Run the self-contained verification suite:
```bash
python3 -m parallax.verify
```
Expected output: 10 of 10 checks pass, including Linux Security Boundaries, Workspace Evidence Integrity, and all 15 Objectives.

### B. Safe Privileged Boundary Testing (Isolated Guest Only)
Inside the disposable guest VM, test the scenario challenge activation:

```bash
# 1. Activate challenge
sudo ./infra/provisioning/provision.sh --activate

# 2. Verify pulse-helper setuid permissions
ls -la /usr/local/bin/pulse-helper
# Output must show: -rwsr-x--- 1 root svc-pulse ... /usr/local/bin/pulse-helper

# 3. Test loopback service binding
ss -tulpn | grep 7741
# Output must show: 127.0.0.1:7741 bound to python3 (svc-pulse)

# 4. Test harmless command injection in controlled directory
su - svc-pulse -s /bin/bash -c "
  /usr/local/bin/pulse-helper --archive-check '/tmp/test.tar.gz; id > /tmp/marker.txt'
"
cat /tmp/marker.txt
# Output must show: euid=0(root) reflecting the setuid boundary

# 5. Clean up marker
rm -f /tmp/marker.txt

# 6. Deactivate when testing complete
sudo ./infra/provisioning/provision.sh --deactivate
```

---

## 5. Packaging Release Appliances

Run the packaging script from the repository root:

```bash
# Package both UTM (Apple Silicon) and VirtualBox (Windows x86-64)
./infra/packaging/package_appliance.sh --target both
```

Outputs in `dist/`:
- `PARALLAX-Ubuntu-24.04-ARM64.utm.zip`: UTM appliance package for macOS Apple Silicon.
- `PARALLAX-Ubuntu-24.04-x86_64.ova`: VirtualBox appliance for Windows x86-64.
- `RELEASE_SHA256SUMS`: Cryptographic checksums of all release packages.

---

## 6. Pre-Release Verification Checklist

Before publishing release packages, verify:
- [ ] Working tree is clean (`git status`).
- [ ] All 134 automated unit and integration tests pass (`pytest -v`).
- [ ] Verification suite passes (`python3 -m parallax.verify`).
- [ ] No `__pycache__`, `.pytest_cache`, `.DS_Store`, or `.git` files present in VM image.
- [ ] No private SSH keys or sensitive host history stored in guest.
- [ ] Evidence manifest checksums match `evidence/manifests/SHA256SUMS`.
- [ ] Player instructions in `docs/PLAYER_GUIDE.md` match current behavior.
