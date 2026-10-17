# PARALLAX — Evidence Artifact Index

This index documents all raw forensic artifacts collected for the **Meridian Research Incident** (Milestone 3).

---

## 1. Evidence Artifact Catalog

| Evidence ID | Path | Format | Source System | Ground Truth Role | Integrity Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`EV-NET-001`** | `raw/network/pulse_session.transcript` | `text/transcript` | `TAP-MERIDIAN-01` | PULSE/1 session wire transcript demonstrating auth flaw | Indexed in `manifest.json` |
| **`EV-NET-002`** | `raw/network/capture.meta` | `application/json` | `TAP-MERIDIAN-01` | Optical tap metadata documenting -420s clock drift | Indexed in `manifest.json` |
| **`EV-CFG-001`** | `raw/system/pulse.conf` | `text/ini` | `meridian-lab` | Service configuration snapshot (/etc/pulse/pulse.conf) | Indexed in `manifest.json` |
| **`EV-SRV-001`** | `raw/system/service_inventory.json` | `application/json` | `meridian-lab` | Host service footprint inventory (/etc/systemd) | Indexed in `manifest.json` |

---

## 2. Artifact Details, Purpose & Limitations

### EV-NET-001: PULSE/1 Communication Transcript (`raw/network/pulse_session.transcript`)
- **Origin**: Upstream optical network tap `TAP-MERIDIAN-01` on SPAN interface `eth0-span`.
- **Purpose**: Records the chronological wire-level exchange between client `198.51.100.24:49822` and host service `10.0.4.15:7741`. Demonstrates that after submitting invalid credentials (`AUTH`), the client successfully dispatched a `READ_DIAG` frame and received sensitive internal parameters (`helper_path`, `diagnostic_ticket`, `encryption_passphrase_fragment`).
- **Facts vs Hypotheses**: The transcript establishes that an unauthenticated client received sensitive diagnostics over TCP port 7741. It does **not** prove the physical identity of the human attacker, nor does it establish whether the leaked helper was subsequently executed on the host.
- **Limitations & Clock Skew**: Timestamps reflect the internal clock of the hardware tap, which was lagging true UTC by 420 seconds (7 minutes).

### EV-NET-002: Upstream Network Tap Metadata (`raw/network/capture.meta`)
- **Origin**: Management control-plane diagnostic export from tap appliance `TAP-MERIDIAN-01`.
- **Purpose**: Documents the hardware capture environment, interface mapping, capture window, and clock synchronization status (`DEGRADED`, `clock_offset_seconds: -420`).
- **Facts vs Hypotheses**: The metadata provides an empirical source statement regarding hardware RTC drift. **Important**: A uniform timestamp difference alone must not be represented as definitive proof of its cause; independent corroboration against host event logs is required.
- **Limitations**: Control-plane metadata is an operational record, not an immutable cryptographic proof.

### EV-CFG-001: PULSE/1 Service Configuration (`raw/system/pulse.conf`)
- **Origin**: File seized from target host filesystem at `/etc/pulse/pulse.conf`.
- **Purpose**: Confirms service operational parameters: TCP port `7741`, dedicated service user `svc-pulse`, maintenance helper path `/usr/local/bin/pulse-helper`, and archive repository `/var/archive/meridian`.
- **Facts vs Hypotheses**: Demonstrates the intended on-disk configuration. Does not guarantee that runtime processes adhered to these parameters if configuration was modified or loaded dynamically.
- **Limitations**: Static on-disk state snapshot.

### EV-SRV-001: Service Inventory Snapshot (`raw/system/service_inventory.json`)
- **Origin**: Output of automated initial triage script executed on `meridian-lab` (`10.0.4.15`).
- **Purpose**: Corroborates that `pulse.service` was actively running under `MainPID=1412` and owned cgroup `system.slice/pulse.service`.
- **Facts vs Hypotheses**: Confirms process existence and binding to port 7741 at the time of triage collection. Does not establish which specific requests PID 1412 handled.
- **Limitations**: Point-in-time triage capture.

---

## 3. Evidence Integrity Verification

All artifacts are cryptographically protected via SHA-256 manifests stored in `evidence/manifests/`.

### POSIX Checksum Verification
```bash
cd evidence && sha256sum -c manifests/SHA256SUMS
```

### Automated Verification Tool
```bash
python3 -m parallax.verify
```
