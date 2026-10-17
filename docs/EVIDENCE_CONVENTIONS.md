# PARALLAX — Evidence Workspace Conventions

---

## 1. Overview & Principles

This document defines the technical standards for structuring, storing, identifying, and verifying synthetic forensic artifacts within the **PARALLAX** investigation environment.

The design adheres to four foundational digital forensics principles:
1. **Immutability of Original Artifacts**: Pristine synthetic evidence is stored in a dedicated, read-only location and must never be altered in place.
2. **Explicit Provenance**: Every artifact records its synthetic origin, generation script, parameters, and simulated system source.
3. **Rigorous Integrity**: All evidence files are tracked with SHA-256 cryptographic checksums and structured manifests.
4. **Deterministic Chronology**: Timestamps are strictly normalized to UTC (ISO 8601). Known hardware clock skews (such as the -420 second tap drift) are documented explicitly as calibrated offsets rather than silent adjustments.

---

## 2. Directory Hierarchy

The evidence workspace uses a standardized four-tier directory structure:

```text
evidence/
├── README.md               # Directory overview and analyst instructions
├── raw/                    # Pristine original synthetic artifacts (read-only)
│   ├── network/            # Packet captures and tap metadata
│   ├── logs/               # Host system, daemon, and audit logs
│   ├── system/             # Service configs, unit files, binaries
│   └── data/               # Encrypted archives, storage remnants
├── derived/                # Transformed, extracted, or decoded artifacts
│   ├── decoded/            # Decrypted files, extracted strings, decompiled code
│   └── timelines/          # Correlated chronological event tables
├── notes/                  # Investigator hypotheses, triage notes, and scratchpad
└── manifests/              # Cryptographic integrity hashes and provenance records
    ├── SHA256SUMS          # Standard sha256sum format manifest
    └── manifest.json       # Structured machine-readable provenance manifest
```

### Directory Roles
- **`evidence/raw/`**: Simulates the seized or collected disk state from the Meridian Research system. Files placed here represent ground truth artifacts (genuine or manipulated by the attacker). They are treated as read-only.
- **`evidence/derived/`**: Contains analyst-generated or tooling-extracted artifacts (e.g., decrypted vault files, extracted diagnostic payloads, packet dissections). Each derived file must reference its parent raw artifact ID.
- **`evidence/notes/`**: Scratch space for investigation logs, scratchpad queries, hypothesis validation, and timeline notes.
- **`evidence/manifests/`**: Central repository for SHA-256 hashes, file sizes, capture dates, and generator metadata.

---

## 3. Evidence Identification Scheme

Every artifact is assigned a unique, immutable Evidence ID following the syntax:

$$\text{EV}-\langle\text{CATEGORY}\rangle-\langle\text{INDEX}\rangle$$

| Category Code | Description | Examples |
| :--- | :--- | :--- |
| **`NET`** | Network captures, stream extractions, tap metadata | `EV-NET-001` (`capture.pcap`), `EV-NET-002` (`capture.meta`) |
| **`LOG`** | Operating system logs, audit records, daemon traces | `EV-LOG-001` (`pulse.log`), `EV-LOG-002` (`audit.log`) |
| **`CFG`** | Configuration files, policy manifests, unit definitions | `EV-CFG-001` (`pulse.conf`), `EV-CFG-002` (`pulse.service`) |
| **`BIN`** | Executables, privileged helpers, compiled libraries | `EV-BIN-001` (`pulse-helper`) |
| **`DAT`** | Data archives, encrypted vaults, diagnostic tokens | `EV-DAT-001` (`research_vault.tar.gz.enc`) |
| **`DRV`** | Derived analyst artifacts (decrypted, decoded, timeline) | `EV-DRV-001` (`research_vault_extracted/`) |

---

## 4. Timestamps & Timezone Specification

To avoid ambiguity across disparate tools:
1. **Primary Standard**: All timestamps must be represented in **UTC** using ISO 8601 extended format:
   ```text
   YYYY-MM-DDTHH:MM:SSZ
   YYYY-MM-DDTHH:MM:SS.ffffffZ (microsecond precision for packets and audit logs)
   ```
2. **Explicit Offset Modeling**:
   - When an artifact originates from a device with an uncalibrated clock (specifically the upstream network tap exhibiting a -420 second drift), the artifact's raw recorded timestamp is preserved.
   - The associated metadata file (`capture.meta` / `manifest.json`) explicitly declares the offset:
     ```json
     {
       "recorded_timestamp": "2026-09-14T03:14:02.108422Z",
       "clock_offset_seconds": -420,
       "calibrated_utc_timestamp": "2026-09-14T03:21:02.108422Z"
     }
     ```
   - Analysts must document both the recorded hardware time and the calibrated UTC time during timeline reconstruction.

---

## 5. Cryptographic Integrity & Manifests

Integrity verification ensures that artifacts are not inadvertently modified or corrupted during analysis.

### 5.1 Standard `SHA256SUMS`
The `evidence/manifests/SHA256SUMS` file provides standard POSIX checksum compatibility:
```text
<64-hex-char-hash>  <relative-path-from-evidence-root>
```
Verification command:
```bash
cd evidence && sha256sum -c manifests/SHA256SUMS
```

### 5.2 Structured Machine-Readable Manifest (`manifest.json`)
The structured manifest records cryptographic hashes alongside rich provenance data:
```json
{
  "manifest_version": "1.0.0",
  "scenario": "Meridian Research Incident",
  "generated_utc": "2026-10-17T14:30:00Z",
  "artifacts": [
    {
      "evidence_id": "EV-NET-001",
      "path": "raw/network/capture.pcap",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size_bytes": 1048576,
      "source_system": "upstream-tap-01",
      "format": "libpcap",
      "description": "Upstream network tap capture of PULSE/1 traffic on port 7741",
      "generator": {
        "script": "src/parallax/artifacts/gen_network.py",
        "parameters": {"session_id": "SES-7741-ALPHA", "clock_offset": -420}
      }
    }
  ]
}
```

---

## 6. Provenance & Artifact Generation Logging

Every synthetic artifact must be fully reproducible. When evidence generation scripts are implemented in subsequent milestones, each generator must:
1. Accept deterministic seeds or inputs.
2. Emit an integrity record into `manifest.json`.
3. Provide a clear comment header in source or metadata linking the artifact to its corresponding incident ground truth event.
4. Maintain strict separation between genuine background noise and scenario-specific discrepancies.
