# PARALLAX — Development Roadmap

---

## Overview

This roadmap defines the sequential, reviewable milestones for designing, implementing, testing, and distributing **PARALLAX — The Evidence Is Lying**. 

Each stage is structured as an independent unit of work with defined deliverables, acceptance criteria, and scope boundaries. No stage presumes functionality that has not yet been built.

---

## Stage Progression

```text
+-----------------------------------------------------------------------------+
| Stage 0: Repository Initialization & Baseline Scoping (Current)            |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 1: Requirements & Scenario Narrative Design                           |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 2: PULSE/1 Protocol Formal Specification                              |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 3: PULSE/1 Protocol Implementation & Test Suite                       |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 4: Evidence-Validation Engine & Local Harness                         |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 5: Synthetic Evidence Generation & Artifact Staging                   |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 6: Linux System Provisioning & Security Configuration                 |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 7: VM Packaging & UTM Distribution Pipeline                           |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Stage 8: End-to-End Release Validation & Solution Guide                     |
+-----------------------------------------------------------------------------+
```

---

## Detailed Stages

### Stage 0: Repository Initialization & Baseline Scoping
* **Status**: In Review (Milestone 1)
* **Objective**: Establish a clean, standardized development repository and define clear project boundaries.
* **Deliverables**:
  - Git repository initialized with `main` branch (baseline files remain untracked and uncommitted pending review).
  - Baseline documentation: `README.md`, `docs/PROJECT_SCOPE.md`, `docs/ROADMAP.md`.
  - Exclusion policies: `.gitignore`.
  - Minimal Python configuration: `pyproject.toml` (PEP 517/621).
* **Acceptance Criteria**:
  - Repository contains only essential baseline files without premature placeholders or mock code.
  - Stage 0 remains in review until the initial commit is made; baseline files remain untracked and uncommitted pending review.
  - Python project configuration passes TOML syntax parsing and selected metadata assertions; full package build and installation remain unverified until source code is implemented.

---

### Stage 1: Requirements & Scenario Narrative Design
* **Status**: Planned
* **Objective**: Define the comprehensive incident backstory, forensic ground truth, and the 15 interconnected investigation objectives.
* **Deliverables**:
  - Scenario ground truth document: fictional victim organization, threat actor profile, and attack timeline.
  - Objective dependency graph: 15 progressive milestones mapping required evidence, investigative technique, and unlock prerequisites.
  - Truth-versus-Deception Matrix: explicitly delineating authentic telemetry from the two agreed central discrepancies (the deliberately manipulated audit record framing `rhea` and the legitimate 7-minute clock offset).
  - Single-VM Clock Offset Representation Design: a design deliverable defining how the legitimate seven-minute clock offset is represented and corroborated in a single-VM environment (for example, contrasting timestamps in staged service/network telemetry against local system journald/auditd logs), without introducing a second VM or additional discrepancies.
  - Final verdict rubric: criteria requiring the player to differentiate verified, evidence-supported facts from unsupported inferences.
* **Acceptance Criteria**:
  - Every objective has a defined forensic justification and clear corroboration paths across disk, filesystem, process, log, or network evidence.
  - Anti-forensic elements are strictly bounded to the two agreed central discrepancies.
  - Representation of the seven-minute clock offset is clearly designed for a single-VM architecture prior to artifact implementation.

---

### Stage 2: PULSE/1 Protocol Formal Specification
* **Status**: Planned
* **Objective**: Write the formal technical specification for the custom `PULSE/1` proprietary TCP protocol prior to implementation.
* **Deliverables**:
  - `docs/PULSE1_SPECIFICATION.md`:
    - Protocol wire format: byte ordering, magic headers, message framing, and payload length fields.
    - Opcode catalog: the six agreed initial message types (`HELLO`, `AUTH`, `STATUS`, `READ_DIAG`, `CLOSE`, and `ERROR`). The initial protocol scope is bounded to these six message types; any additional features require separate design review and approval.
    - State machine: connection lifecycle, authentication states, timeouts, and error handling.
    - Intentional security flaws: deliberate logic flaws, missing boundary checks, or authentication flaws designed into the service.
* **Acceptance Criteria**:
  - Specification is complete enough to implement compliant client and server implementations independently without external references.
  - Initial scope is strictly bounded to the six agreed message types.

---

### Stage 3: PULSE/1 Protocol Implementation & Test Suite
* **Status**: Planned
* **Objective**: Implement the reference PULSE/1 daemon service and comprehensive automated test suite prior to VM integration.
* **Deliverables**:
  - Reference daemon codebase under `src/parallax/pulse/`.
  - Automated test suite under `tests/pulse/`:
    - Unit tests for framing, serialization, and opcode dispatch across agreed message types.
    - Stateful connection lifecycle tests.
    - Protocol abuse and vulnerability verification tests proving the intentional flaws function as intended.
* **Acceptance Criteria**:
  - 100% test pass rate across protocol parsing, state transitions, and documented flaw behaviors.
  - Runs cleanly in a local Python 3.11+ environment without external network dependencies.

---

### Stage 4: Evidence-Validation Engine & Local Harness
* **Status**: Planned
* **Objective**: Build the offline validation CLI tool (`parallax`) that acts as a progress tracker and answer validator inside the player-controlled VM.
* **Deliverables**:
  - Validation engine core under `src/parallax/engine/`.
  - CLI interface (`parallax check <objective>`, `parallax status`, `parallax submit`).
  - Validation logic: deterministic checks (hashes, regex, system state) that reduce accidental spoilers.
  - Prerequisite enforcement: all 15 required objectives must be completed before the final verdict submission unlocks.
* **Acceptance Criteria**:
  - Correct objective validation and prerequisite enforcement.
  - Clear feedback on objective pass/fail without exposing answers or accidental spoilers.
  - Fully functional offline inside the guest VM without external network access.
  - Operates as a progress tracker and answer validator, recognizing that absolute anti-tamper security against a player controlling the VM is not a realistic design goal.

---

### Stage 5: Synthetic Evidence Generation & Artifact Staging
* **Status**: Planned
* **Objective**: Build reproducible scripts to generate and stage all forensic evidence and scenario challenge artifacts.
* **Deliverables**:
  - Artifact generation scripts under `src/parallax/artifacts/`:
    - Synthetic PCAP generator for PULSE/1 and background network traffic.
    - System log synthesizer staging the manipulated audit record framing `rhea` and reflecting the 7-minute clock offset.
    - Filesystem and disk artifacts: file recovery, steganography, compiled binary helpers, and cryptographic challenge artifacts.
* **Acceptance Criteria**:
  - All artifacts are generated deterministically via reproducible scripts.
  - Artifacts align strictly with the Scenario Ground Truth and Truth-versus-Deception Matrix without extraneous unapproved discrepancies.

---

### Stage 6: Linux System Provisioning & Security Configuration
* **Status**: Planned
* **Objective**: Develop configuration scripts for an authentic Ubuntu Server ARM64 environment.
* **Deliverables**:
  - Shell provisioning and cloud-init scripts under `infra/provisioning/`.
  - User and service accounts: unprivileged `analyst` account, isolated service identities.
  - Systemd unit configurations for PULSE/1 daemon with tailored isolation and restart policies.
  - Linux security boundary rules: restricted directory permissions (DAC), capability assignment, auditd logging rules, and a controlled privileged-helper boundary.
* **Acceptance Criteria**:
  - Clean execution on a freshly installed Ubuntu Server 24.04 ARM64 instance.
  - `analyst` account operates with unprivileged access while interacting with challenge surfaces and the privileged helper as designed.

---

### Stage 7: VM Packaging & UTM Distribution Pipeline
* **Status**: Planned
* **Objective**: Automate the creation and packaging of the distributable ARM64 virtual machine.
* **Deliverables**:
  - VM build automation scripts under `infra/vm/`.
  - Pre-configured UTM VM bundle (`.utm`) and raw/qcow2 disk image outputs.
  - Post-build optimization: log cleanup and disk image compression.
  - Release manifest: SHA-256 checksums, hardware requirements, and import instructions.
* **Acceptance Criteria (Release Goals to Verify)**:
  - Unattended VM boot verified in UTM on Apple Silicon (M-series).
  - Clean-import success verified on target host.
  - Networking defaults to isolated local/host-only mode with zero external connectivity.

---

### Stage 8: End-to-End Release Validation & Solution Guide
* **Status**: Planned
* **Objective**: Conduct comprehensive playthrough validation, produce reference documentation, and tag the initial release.
* **Deliverables**:
  - Full end-to-end playthrough validation executed strictly from an unprivileged `analyst` shell.
  - Final incident verdict verification proving the player must differentiate verified facts from inferences.
  - Authoritative reference walkthrough ("Gold Master" solution guide and ground truth timeline).
  - Release notes, player briefing document, and final release tagging.
* **Acceptance Criteria**:
  - All 15 objectives successfully verified using only standard Linux CLI tools and the validation harness.
  - Final verdict successfully evaluated and verified.
  - Zero dependencies on external network access during full playthrough.
