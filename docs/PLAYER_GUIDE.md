# PARALLAX — Player Investigation Guide

Welcome, Investigator.

You have been retained as an independent digital forensics investigator by **Meridian Research**, an autonomous systems lab whose proprietary telemetry daemon (`PULSE/1`) and internal research vault were breached during an overnight security incident.

The appliance is completely self-contained and operates entirely offline. You do not need internet access or root credentials to solve the challenge.

---

## 1. Quickstart: Importing the Appliance

Choose the appliance package designed for your host operating system and hypervisor:

### Target A: UTM on Apple Silicon (macOS)
- **Host**: Mac with Apple Silicon (M1, M2, M3, M4).
- **Hypervisor**: [UTM 4.x or later](https://mac.getutm.app/).
- **Appliance File**: `PARALLAX-Ubuntu-24.04-ARM64.utm.zip`
- **Import Steps**:
  1. Unzip `PARALLAX-Ubuntu-24.04-ARM64.utm.zip` to extract `PARALLAX-Ubuntu-24.04-ARM64.utm`.
  2. Double-click the `.utm` bundle, or open UTM and drag the file into the virtual machine list.
  3. Select the **PARALLAX-Ubuntu-24.04-ARM64** VM and click the **Start/Play** button.

### Target B: Oracle VirtualBox on Windows (x86-64)
- **Host**: Windows 10 / 11 64-bit on Intel or AMD CPUs (Hardware Virtualization VT-x/AMD-V enabled in BIOS).
- **Hypervisor**: [Oracle VM VirtualBox 7.x](https://www.virtualbox.org/).
- **Appliance File**: `PARALLAX-Ubuntu-24.04-x86_64.ova`
- **Import Steps**:
  1. Open VirtualBox and select **File -> Import Appliance...** (or press `Ctrl+I`).
  2. Browse and select `PARALLAX-Ubuntu-24.04-x86_64.ova`.
  3. Click **Next**, review the hardware settings (2 vCPUs, 4096 MB RAM, NAT network), and click **Finish**.
  4. Select the imported VM and click **Start**.

---

## 2. Logging In

Once the virtual machine boots to the console login prompt:

- **Username**: `analyst`
- **Password**: `analyst`

Your user account operates with standard, unprivileged access. All forensic evidence, documentation, and the investigation engine are directly accessible from your home environment.

---

## 3. The Investigation Workspace

Your home directory contains the pre-staged investigation materials:

```text
/home/analyst/
├── evidence/              # Complete forensic evidence workspace
│   ├── raw/
│   │   ├── network/       # PCAP, network tap transcripts, and tap metadata
│   │   ├── logs/          # Daemon logs, Linux audit log, auth.log, wtmp
│   │   ├── system/        # Service inventory, configs, passwd/group, DAC permissions
│   │   └── data/          # Encrypted research vault, diagnostic ticket
│   ├── manifests/         # SHA256SUMS and cryptographically verified manifests
│   ├── notes/             # Your persistent investigation notes
│   ├── derived/           # Investigation progress and extracted artifacts
│   └── INDEX.md           # Chain-of-custody catalog and evidence IDs
└── parallax/              # PARALLAX application source and tools
```

---

## 4. Using the `parallax` CLI

PARALLAX provides a command-line interface to guide your investigation, inspect objectives, submit findings, and decrypt artifacts:

### Check Overall Progress
```bash
parallax status
```
Displays all 15 investigation objectives (`P01` to `P15`), showing which are completed, available, or locked.

### Inspect an Objective
```bash
parallax inspect P01
```
Displays:
- Objective description and technical prompt.
- Required evidence artifacts (e.g. `EV-NET-001`, `EV-NET-002`).
- Investigative hints and validation instructions.

### Submit an Answer
```bash
parallax submit P01 "TCP 7741"
```
The verification engine evaluates your submission deterministically. If your answer is correct, the objective is marked complete, unlocking downstream prerequisites.

### Decrypting Evidence
When you discover the encryption passphrase fragments during your investigation:
```bash
parallax decrypt --key "meridian-vault-2024-alpha-99x"
```
Successfully decrypted archives will be placed in `evidence/derived/`.

### Generate Final Incident Report
```bash
parallax report
```
Generates a structured incident investigation summary highlighting all completed milestones and evidence citations.

---

## 5. The 15 Investigation Milestones

| ID | Title | Primary Evidence |
|:---|:------|:-----------------|
| `P01` | Service Identification | `EV-NET-001`, `EV-NET-002` |
| `P02` | Protocol Dissection | `EV-NET-001`, `EV-LOG-001` |
| `P03` | Authentication Failure Analysis | `EV-NET-001`, `EV-LOG-001` |
| `P04` | Diagnostic Telemetry Leak | `EV-LOG-001`, `EV-NET-001` |
| `P05` | Network Capture Timing Analysis | `EV-NET-002`, `EV-LOG-001` |
| `P06` | External Threat Actor Profiling | `EV-NET-002`, `EV-LOG-003` |
| `P07` | Service Account Enumeration | `EV-SYS-001`, `EV-SYS-002` |
| `P08` | Privileged Helper Discovery | `EV-SYS-003`, `EV-CFG-002` |
| `P09` | Helper Vulnerability Analysis | `EV-LOG-002`, `EV-SYS-003` |
| `P10` | Audit Log Integrity Audit | `EV-LOG-002`, `EV-USR-001` |
| `P11` | Rhea Activity Verification | `EV-USR-001`, `EV-LOG-004` |
| `P12` | Clock Offset Corroboration | `EV-NET-002`, `EV-LOG-002` |
| `P13` | Cryptographic Vault Decryption | `EV-DAT-001`, `EV-DAT-002` |
| `P14` | Attack Vector Reconstruction | `EV-NET-001`, `EV-LOG-002` |
| `P15` | Incident Final Verdict | Full Evidence Suite |

> [!IMPORTANT]
> **Prerequisite Enforcement**:
> Objective `P15` (Incident Final Verdict) is strictly locked until objectives `P01` through `P14` have been successfully completed.

---

## 6. The Two Central Discrepancies

As noted in your briefing, **two pieces of evidence in this incident are not what they seem**:

1. **The Clock Offset**: The optical tap capturing external network traffic experienced a clock offset relative to the Meridian Research internal servers. Correlate timestamps across network packets and local daemon logs to discover the true chronological sequence.
2. **The Fabricated Audit Record**: An internal audit log contains a forged entry designed to implicate employee `rhea`. Correlate shell history, session records, and process lineage to determine whether `rhea` was truly responsible.

---

## 7. Operational Guidelines

- **No Network Required**: The appliance does not make outbound network connections.
- **Persistent Progress**: Your investigation progress is saved locally in `evidence/derived/.progress.json`.
- **Resetting Progress**: If you wish to restart the investigation from scratch:
  ```bash
  parallax reset
  ```
