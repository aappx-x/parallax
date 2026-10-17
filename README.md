# PARALLAX — The Evidence Is Lying

> **A terminal-first, self-contained Linux cybersecurity investigation challenge exploring deception in digital forensics, custom protocol exploitation, and Linux security boundaries.**

---

## 1. Project Overview

**PARALLAX** is an immersive, terminal-first cybersecurity investigation challenge set within a self-contained Linux environment. The player assumes the role of an unprivileged security responder (`analyst`) tasked with investigating an apparent multi-stage breach.

Unlike traditional Capture-The-Flag (CTF) challenges where logs and forensic artifacts are universally truthful clues, PARALLAX is built around a core premise: **the evidence cannot be accepted at face value**. In sophisticated modern intrusions, adversaries alter logs, timestomp files, forge protocol telemetry, and plant deceptive decoys to misdirect investigators. In PARALLAX, the analyst must critically correlate evidence across multiple independent sources, reverse-engineer a proprietary network service, inspect system security boundaries, expose anti-forensic tampering, and assemble a sound, evidence-backed incident verdict.

---

## 2. Problem & Purpose

### The Problem
Traditional cybersecurity training environments and CTFs often suffer from two major shortcomings:
1. **Unrealistic Trust in Telemetry**: Challenges typically teach analysts to trust log output and system state implicitly, treating evidence as an unambiguous breadcrumb trail.
2. **Artificial Scenarios**: Objectives often rely on disconnected puzzle mechanics rather than cohesive forensic methodology, protocol reverse engineering, and authentic Linux system internals.

### The Purpose
PARALLAX bridges the gap between synthetic CTF puzzles and realistic Digital Forensics and Incident Response (DFIR). It provides:
- A realistic investigation workflow operating entirely from the Linux command line.
- Experience dissecting hostile anti-forensic techniques, including forged logs, timestomping, and planted decoy activity.
- Hands-on reverse engineering of a custom stateful network protocol (`PULSE/1`).
- Practice analyzing Linux privilege boundaries, process hierarchies, and system services in an authentic operational environment.

---

## 3. The Six Planned Pillars

The project is structured around six core technical pillars:

1. **Custom Protocol Engineering (`PULSE/1`)**
   A proprietary stateful TCP protocol featuring documented wire framing, opcode handlers, session states, and deliberate security vulnerabilities for the analyst to dissect and exploit.
2. **Evidence Validation Engine**
   A self-contained, deterministic CLI validation harness that enables the player to verify investigation milestones locally without revealing hints or compromising solution integrity.
3. **Forensic Deception & Anti-Forensics**
   Hostile forensic challenges where system logs, timestamps, and artifacts have been tampered with, forcing the analyst to cross-corroborate signals rather than trust single points of observation.
4. **Linux Security Boundaries**
   Rigorous exploration of Linux security controls, including discretionary access control (DAC), privilege separation, systemd service sandboxing, Linux capabilities, and process isolation.
5. **Supporting Security Challenges**
   Fifteen interconnected investigation objectives weaving together binary reverse engineering, cryptographic analysis, memory/process inspection, and log reconstruction into a coherent narrative.
6. **Reproducible Release Engineering**
   Fully scripted, automated provisioning and packaging pipelines producing an offline, distributable Ubuntu Server ARM64 virtual machine image.

---

## 4. Proposed Architecture

```text
+-------------------------------------------------------------------+
|               PARALLAX Guest VM (Ubuntu Server ARM64)             |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |                    Analyst Session                          |  |
|  |  - User: `analyst` (unprivileged)                           |  |
|  |  - Shell: bash / zsh with standard Linux DFIR toolchain    |  |
|  +-------------------------------------------------------------+  |
|                                 |                                 |
|                                 v                                 |
|  +---------------------+   +---------------------+   +---------+  |
|  | PULSE/1 Service     |   | Scenario Artifacts  |   | System  |  |
|  | - Proprietary TCP   |   | - Tampered Logs     |   | - DAC   |  |
|  | - Daemon / Systemd  |   | - Network PCAPs     |   | - Caps  |  |
|  | - Custom Framing    |   | - Synthetic Trails  |   | - Audit |  |
|  +---------------------+   +---------------------+   +---------+  |
|                                 |                                 |
|                                 v                                 |
|  +-------------------------------------------------------------+  |
|  |              Evidence Validation Engine                     |  |
|  |  - Deterministic state & hash verification                  |  |
|  |  - Non-spoiling feedback loop & milestone tracking          |  |
|  +-------------------------------------------------------------+  |
+-------------------------------------------------------------------+
```

### Planned Repository Structure
```text
parallax/
├── README.md               # Project overview and architectural foundation
├── .gitignore              # Repository exclusion rules
├── pyproject.toml          # Python project and packaging configuration
├── docs/                   # Architectural specifications and design records
│   ├── PROJECT_SCOPE.md    # Scoping, player experience, and safety boundaries
│   └── ROADMAP.md          # Phased development plan and milestones
├── src/                    # Planned: protocol daemon, harness, validation tools
├── tests/                  # Planned: protocol test suite and scenario assertions
└── infra/                  # Planned: provisioning scripts and VM build definitions
```

---

## 5. Development Status

> [!IMPORTANT]
> **Stage 0: Initial Design & Repository Initialization**
> This repository is currently in an early design and planning phase. No challenge daemons, synthetic evidence files, or virtual machine images have been built or released yet. Planned functionality described across the documentation reflects the target architecture and roadmap.

---

## 6. Planned Development Environment

The development environment is explicitly scoped for Apple Silicon workstations hosting an ARM64 Linux guest:

- **Host Workstation**: macOS running on Apple Silicon (M-series / M5).
- **Hypervisor**: [UTM](https://mac.getutm.app/) utilizing Apple's Hypervisor.framework and QEMU ARM64 backend.
- **Guest Operating System**: Ubuntu Server ARM64 (LTS).
- **Tooling Language**: Python 3.11+ for validation logic, harness scripts, and protocol testing.
- **Scope Note**: Cross-platform virtualization (x86_64 emulation) is explicitly out of scope for the initial release milestone to ensure optimal performance and reproducible builds.
