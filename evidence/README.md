# PARALLAX — Evidence Workspace

This workspace houses forensic evidence artifacts, derived findings, analyst notes, and cryptographic integrity manifests for the **PARALLAX** cybersecurity investigation.

## Subdirectories

- **`raw/`**: Pristine original synthetic artifacts seized from the target environment. Immutable.
- **`derived/`**: Extracted strings, decrypted files, dissections, and normalized timelines.
- **`notes/`**: Investigator scratchpad, hypothesis testing, and analytical notes.
- **`manifests/`**: Cryptographic integrity manifests (`SHA256SUMS`, `manifest.json`).

For technical standards regarding evidence IDs, timestamps, and integrity verification, refer to [`docs/EVIDENCE_CONVENTIONS.md`](../docs/EVIDENCE_CONVENTIONS.md).
