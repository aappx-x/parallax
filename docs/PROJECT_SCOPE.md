# PARALLAX — Project Scope & System Boundaries

---

## 1. Project Goal

The primary goal of **PARALLAX** is to design and develop an authentic, self-contained, terminal-first synthetic cybersecurity investigation lab packaged as an ARM64 Linux virtual machine.

Rather than presenting conventional Capture-The-Flag (CTF) trivia where system logs provide unambiguous clues, the design of PARALLAX aims for realistic investigative depth and reproducibility through a planned synthetic scenario built around **corroboration under conflicting signals**:
> *In a complex cyber breach, forensic telemetry cannot be accepted at face value: logs can be manipulated, clock skews can distort sequences, and benign identities can be framed.*

The project's goal is to challenge players to practice rigorous investigative hygiene: cross-corroborating independent evidence sources across system layers, dissecting a custom network protocol, testing Linux privilege boundaries, and synthesizing verified findings into a substantiated incident verdict.

---

## 2. Intended Player Experience

- **Persona & Starting State**: The player begins the investigation logged into an interactive terminal session as the unprivileged Linux account `analyst`. The player operates throughout as `analyst`; there is no requirement or expectation to log in as other user accounts such as `rhea`.
- **Operating Context**: The player conducts the investigation entirely through standard Linux command-line utilities, text editors, inspection tools, and the planned local `parallax` CLI.
- **Progress Submission & Validation Engine**:
  - The planned local `parallax` CLI runs inside the guest environment, functioning as an offline progress tracker and answer validator.
  - Because the checker executes within a virtual machine entirely controlled by the player, it is designed for deterministic local validation and reducing accidental spoilers—not as a tamper-proof barrier against a player with full control of the virtual hardware.
- **Core Investigation Loop**:
  1. **Triage & Exploration**: Inspect system posture, running processes, service configurations, and initial incident alerts.
  2. **Technical Deconstruction**: Reverse-engineer the custom `PULSE/1` network protocol (evaluating the six agreed message types `HELLO`, `AUTH`, `STATUS`, `READ_DIAG`, `CLOSE`, `ERROR`), analyze Linux service identities and permissions, and examine a controlled privileged-helper security boundary.
  3. **Evidence Corroboration**: Correlate disk, filesystem, process, log, and network evidence to resolve discrepancies between conflicting data sources.
  4. **Progressive Objective Completion**: Submit findings for each of the 15 required investigation objectives through the local CLI. All 15 required objectives must be completed before the final verdict submission becomes available.
  5. **Final Incident Verdict**: Completing all 15 objectives unlocks the verdict submission. Unlocking the verdict does not guarantee that the submitted verdict is correct; the final submission requires the player to clearly distinguish verified, evidence-supported facts from unsupported inferences.

---

## 3. The Agreed Forensic Scenario: Core Deception

To keep the scenario coherent, focused, and independently testable, the central mystery revolves around **exactly two central forensic discrepancies**:

1. **One deliberately manipulated audit record** planted to frame the user `rhea`.
2. **One legitimate seven-minute clock offset** between disparate systems/components that introduces an apparent timestamp anomaly.

In a single-VM environment, how this legitimate seven-minute clock offset will be represented and corroborated (for instance, contrasting timestamps in staged service/network telemetry against local system journald/auditd logs) is a design deliverable to be specified in Stage 1, preserving the single-VM model without introducing a second VM or additional discrepancies.

The player must recognize that not all discrepancies stem from malice: the clock skew is a benign configuration artifact, whereas the altered audit record represents intentional anti-forensic framing. By correlating independent disk, filesystem, process, network, and service logs, the analyst learns to differentiate deliberate deception from operational anomalies.

The scenario deliberately avoids expanding into arbitrary anti-forensic mechanisms (such as widespread timestomped files, forged network packets, or memory injections) without explicit justification and approval.

---

## 4. The Six Core Pillars

| Pillar | Focus | Planned Investigative Role |
| :--- | :--- | :--- |
| **1. Custom Protocol Engineering** | `PULSE/1` proprietary TCP service | Reverse engineering wire framing, the six agreed message types (`HELLO`, `AUTH`, `STATUS`, `READ_DIAG`, `CLOSE`, `ERROR`), session states, and protocol-level vulnerabilities. The initial protocol scope is bounded to these six message types; any additional features require separate design review and approval. |
| **2. Evidence Validation Engine** | Offline local CLI (`parallax`) | Deterministic, offline objective progress tracking and answer validation without accidental spoilers. |
| **3. Forensic Deception** | Two agreed forensic discrepancies | Analyzing one manipulated audit record framing `rhea` and one legitimate 7-minute clock offset. |
| **4. Linux Security Boundaries** | System identities & privileged helper | Inspecting service separation, DAC permissions, and a controlled privileged-helper security boundary. |
| **5. Supporting Security Challenges** | Interconnected technical tasks | Supporting cryptography, file recovery, steganography, and reverse-engineering tasks that feed the investigation. |
| **6. Reproducible Release** | Scenario generation & VM packaging | Automated build scripts, test suites, and packaging for an offline Ubuntu Server ARM64 VM. |

*Note on Memory Forensics*: Memory forensics is out of scope for the current design unless a concrete memory artifact and corresponding task are explicitly defined and approved. Disk, filesystem, process, log, and network evidence are sufficient for the agreed scenario.

---

## 5. Current Status: Implemented vs. Planned

To maintain complete engineering accuracy, the table below documents what is currently established versus what is planned for subsequent roadmap stages:

| Component | Status | Implementation Details |
| :--- | :--- | :--- |
| **Repository Baseline** | **In Review (Stage 0)** | Git `main` branch initialized; baseline configuration files created (`pyproject.toml`, `.gitignore`, `README.md`, docs) but remain untracked and uncommitted pending review. `pyproject.toml` passed TOML syntax parsing and selected metadata assertions; full package build and installation remain unverified until source code is implemented. |
| **Scope & Roadmap** | **Documented Decisions** | Defined in `docs/PROJECT_SCOPE.md` and `docs/ROADMAP.md`. |
| **Scenario Narrative & Objectives** | *Planned (Stage 1)* | Detailed ground truth, 15-objective dependency graph, truth-vs-deception matrix, and single-VM clock offset representation design. |
| **PULSE/1 Protocol Specification** | *Planned (Stage 2)* | Formal wire protocol definition for the six agreed message types (`HELLO`, `AUTH`, `STATUS`, `READ_DIAG`, `CLOSE`, `ERROR`), state transitions, and vulnerability model. |
| **PULSE/1 Daemon Implementation** | *Planned (Stage 3)* | Reference TCP daemon and automated protocol test suite. |
| **Evidence Validation Engine** | *Planned (Stage 4)* | Local CLI progress tracker and objective validation harness. |
| **Synthetic Scenario Artifacts** | *Planned (Stage 5)* | Synthetic network traces, system logs containing the two agreed discrepancies, and challenge files. |
| **Linux Provisioning Scripts** | *Planned (Stage 6)* | Service configurations, system identities, privileged helper boundary, and permission controls. |
| **VM Packaging (UTM / ARM64)** | *Planned (Stage 7)* | Scripted VM builds, unattended boot, disk optimization, and export pipeline. |
| **Release Validation & Walkthrough** | *Planned (Stage 8)* | Full end-to-end verification playthrough from the `analyst` account and solution documentation. |

---

## 6. Scope Boundaries & Target Platform

### Target Platform
- **Host Development Machine**: macOS on Apple Silicon (M-series / M5 architecture).
- **Hypervisor**: [UTM](https://mac.getutm.app/) utilizing Apple's Hypervisor.framework and QEMU ARM64 backend.
- **Guest Operating System**: Ubuntu Server 24.04 LTS ARM64 (subject to verification during implementation).
- **Delivery Format**: Standalone virtual machine bundle / disk image configured for UTM import.

### Current Non-Goals
1. **Cross-Platform x86_64 Emulation**: Initial focus is strictly ARM64 native virtualization on Apple Silicon. Cross-platform emulation is deferred beyond the initial milestone.
2. **Web Scoreboards or Browser Frontends**: PARALLAX is strictly a terminal-first challenge. No web application, browser dashboard, or external score server will be implemented.
3. **Multi-Host Network Simulation**: The challenge is self-contained within a single Linux virtual machine. Distributed multi-node enterprise environments are out of scope.
4. **Internet Connectivity Requirements**: The challenge environment must be fully functional offline; neither the VM nor the validation engine will require external network access during gameplay.
5. **Windows or macOS Targets**: The target investigation environment is exclusively Linux (Ubuntu Server ARM64).

---

## 7. Safety, Synthetic Evidence & Ethics

- **Fictional Context**: All organization names, hostnames, domain names, user accounts, employee profiles, email addresses, and IP ranges utilized in PARALLAX are strictly fictional or drawn from reserved RFC ranges (e.g., RFC 5737 documentation IP prefixes, RFC 2606 reserved domains).
- **Synthetic Evidence**: All logs, network captures (PCAPs), and filesystem artifacts are synthetically generated for educational training. No live corporate data, proprietary threat intelligence, or real personal identifiable information (PII) is included.
- **Isolated Lab Environment**: Vulnerable service configurations, protocol flaws, and privilege escalation mechanics are intentionally crafted for defensive analysis and must only be executed within an isolated, sandboxed virtual machine without public port forwarding.
- **No Weaponized Tooling**: The repository will not contain weaponized malware, autonomous worms, real exploitation payloads, or tools targeting external systems.
