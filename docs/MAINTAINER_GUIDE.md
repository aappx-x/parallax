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
2. Install required packages (`python3`, `auditd`, `build-essential`, `iproute2`, `net-tools`, `acl`, `zip`).
3. Idempotently configure lab accounts with collision resolution:
   - Detects and preserves existing administrative accounts (e.g. `parallaxadmin` with UID/GID 1000) intact without mutation.
   - Assigns unique, non-conflicting IDs for `analyst`, `rhea`, and `svc-pulse` (defaulting to 1000, 1001, 1002 on clean systems, or 1001, 1002, 1003 when UID 1000 is occupied).
   - Adds `analyst` to `systemd-journal` for unprivileged log inspection.
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

## 5. Producing Virtual Disks

A complete, importable virtual appliance requires a real, provisioned operating system disk image. VM disk images must **never** be checked into Git.

### Target A: UTM on Apple Silicon (ARM64)
To produce the bootable ARM64 QCOW2 disk from a provisioned UTM guest:
1. **Clean Shutdown**: Gracefully shut down the running guest VM to flush all filesystem buffers:
   ```bash
   /Applications/UTM.app/Contents/MacOS/utmctl stop "Linux" --request
   ```
   Or run `sudo poweroff` from within the guest console.
2. **Locate Disk and NVRAM Files**:
   The disk image and UEFI NVRAM variables are stored inside the UTM bundle:
   - Disk: `~/Library/Containers/com.utmapp.UTM/Data/Documents/<VM_NAME>.utm/Data/<UUID>.qcow2`
   - NVRAM: `~/Library/Containers/com.utmapp.UTM/Data/Documents/<VM_NAME>.utm/Data/efi_vars.fd`
3. **Compress Image**: Compress the image with `qemu-img` to reduce distribution footprint (from ~5.3 GB to ~2.4 GB):
   ```bash
   qemu-img convert -O qcow2 -c \
       "$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/Linux.utm/Data/8A013D22-610B-4862-803A-5E6AC0BEC05D.qcow2" \
       /tmp/parallax-disk-arm64.qcow2
   ```
4. **Package Complete Appliance**:
   ```bash
   ./infra/packaging/package_appliance.sh \
       --target utm \
       --disk-arm64 /tmp/parallax-disk-arm64.qcow2 \
       --efi-vars "$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/Linux.utm/Data/efi_vars.fd"
   ```

### Target B: Oracle VirtualBox on Windows (x86-64)
To produce the bootable x86-64 VMDK disk from an x86-64 environment:
1. Install base Ubuntu Server 24.04 LTS x86-64 in VirtualBox or QEMU.
2. Clone repository and run safe provisioning:
   ```bash
   sudo ./infra/provisioning/provision.sh --prepare
   ```
3. Gracefully shut down the guest OS (`sudo poweroff`).
4. Convert the guest disk to stream-optimized VMDK:
   ```bash
   qemu-img convert -O vmdk -o subformat=streamOptimized /path/to/raw_disk /tmp/parallax-disk-x86_64.vmdk
   ```
5. Package the complete OVA appliance:
   ```bash
   ./infra/packaging/package_appliance.sh \
       --target virtualbox \
       --disk-x86_64 /tmp/parallax-disk-x86_64.vmdk
   ```

---

## 6. Packaging Release Appliances

Run the packaging script from the repository root:

```bash
# A. Package complete UTM ARM64 appliance with real virtual disk:
./infra/packaging/package_appliance.sh \
    --target utm \
    --disk-arm64 /path/to/disk-arm64.qcow2

# B. Package complete VirtualBox x86-64 appliance (when x86-64 VMDK is available):
./infra/packaging/package_appliance.sh \
    --target virtualbox \
    --disk-x86_64 /path/to/parallax-disk-x86_64.vmdk

# C. Package specification templates only (no virtual disks):
./infra/packaging/package_appliance.sh --target both
```

Outputs in `dist/`:
- **Complete Bootable Appliances (when disks are supplied)**:
  - `PARALLAX-Ubuntu-24.04-ARM64.utm.zip`: Complete UTM appliance with embedded bootable QCOW2 disk and player guide.
  - `PARALLAX-Ubuntu-24.04-x86_64.ova`: Standard OVF 1.0 OVA appliance with embedded stream-optimized VMDK and `.mf` manifest.
- **Specification Templates (when disks are omitted)**:
  - `PARALLAX-Ubuntu-24.04-ARM64-config.utm.zip`: UTM hardware profile, UEFI settings, and network topology template.
  - `PARALLAX-Ubuntu-24.04-x86_64-ovf-template.tar.gz`: OVF 1.0 XML descriptor and hardware definition template.
- **Documentation & Integrity**:
  - `MAINTAINER_GUIDE.md`: Separate maintainer build and provisioning guide.
  - `RELEASE_SHA256SUMS`: Cryptographic SHA-256 release checksums for all generated release archives.

---

## 7. Pre-Release Verification Checklist

Before publishing release packages, verify:
- [ ] Working tree is clean (`git status`).
- [ ] All automated unit and integration tests pass (`pytest -v`).
- [ ] Verification suite passes (`python3 -m parallax.verify`).
- [ ] Real virtual disks are verified with `qemu-img info` and `qemu-img check` prior to full appliance packaging.
- [ ] No virtual disk images (`*.qcow2`, `*.vmdk`) are staged in Git.
- [ ] No `__pycache__`, `.pytest_cache`, `.DS_Store`, or `.git` files present in release image.
- [ ] Evidence manifest checksums match `evidence/manifests/SHA256SUMS`.
- [ ] Player instructions in `docs/PLAYER_GUIDE.md` match current behavior.
