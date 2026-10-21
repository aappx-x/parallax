"""Investigation objectives registry, deterministic validation, and progress tracking engine.

Defines the 15 investigation objectives (P01–P15), prerequisite gating,
evidence association, and deterministic answer verification for the
Meridian Research Incident scenario.

Note: Local objective tracking is an educational progress tracker,
not an adversary-resistant security boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable

# Valid evidence IDs recognized by the engine
KNOWN_EVIDENCE_IDS = {
    "EV-NET-001",
    "EV-NET-002",
    "EV-NET-003",
    "EV-LOG-001",
    "EV-LOG-002",
    "EV-LOG-003",
    "EV-LOG-004",
    "EV-CFG-001",
    "EV-CFG-002",
    "EV-SRV-001",
    "EV-SYS-001",
    "EV-SYS-002",
    "EV-SYS-003",
    "EV-USR-001",
    "EV-DAT-001",
    "EV-DAT-002",
}


@dataclass
class ValidationResult:
    """Outcome of validating an objective submission."""
    success: bool
    message: str
    finding: str | None = None


@dataclass
class Objective:
    """Definition and validation rule for an investigation objective."""
    id: str
    phase: str
    title: str
    question: str
    prerequisites: list[str]
    required_evidence_ids: list[str]
    fact_supported: str
    validator: Callable[[str, list[str]], ValidationResult]
    summary_template: str


class ProgressTracker:
    """Manages persistent investigation progress stored in evidence/derived/.progress.json.

    Local progress tracking serves as an educational milestone validator and
    learning mechanism. It is deliberately inspectable and reproducible.
    """

    DEFAULT_PATH = Path("evidence/derived/.progress.json")

    def __init__(self, progress_file: Path | str | None = None) -> None:
        self.progress_file = Path(progress_file) if progress_file else self.DEFAULT_PATH

    def load(self) -> dict[str, Any]:
        if not self.progress_file.is_file():
            return {
                "version": "1.0.0",
                "scenario": "Meridian Research Incident",
                "updated_utc": datetime.now(timezone.utc).isoformat(),
                "completed": {},
            }
        try:
            with self.progress_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {
                "version": "1.0.0",
                "scenario": "Meridian Research Incident",
                "updated_utc": datetime.now(timezone.utc).isoformat(),
                "completed": {},
            }

    def save(self, data: dict[str, Any]) -> None:
        self.progress_file.parent.mkdir(parents=True, exist_ok=True)
        data["updated_utc"] = datetime.now(timezone.utc).isoformat()
        self.progress_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def is_completed(self, objective_id: str) -> bool:
        data = self.load()
        return objective_id in data.get("completed", {})

    def get_status(self, obj: Objective) -> str:
        data = self.load()
        completed = data.get("completed", {})
        if obj.id in completed:
            return "COMPLETED"
        for prereq in obj.prerequisites:
            if prereq not in completed:
                return "LOCKED"
        return "UNLOCKED"

    def mark_completed(self, objective_id: str, evidence_ids: list[str], finding: str) -> None:
        data = self.load()
        if "completed" not in data:
            data["completed"] = {}
        data["completed"][objective_id] = {
            "completed_utc": datetime.now(timezone.utc).isoformat(),
            "evidence_ids": evidence_ids,
            "finding": finding,
        }
        self.save(data)

    def reset(self) -> None:
        if self.progress_file.is_file():
            self.progress_file.unlink()


# -------------------------------------------------------------------------
# Deterministic Objective Validators (P01–P15)
# -------------------------------------------------------------------------

def _val_p01(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-CFG-001", "EV-SRV-001", "EV-CFG-002", "EV-LOG-001"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires at least one service configuration or log evidence ID "
            "(e.g. EV-CFG-001, EV-SRV-001).",
        )
    if not re.search(r"\b7741\b", answer):
        return ValidationResult(
            False,
            "Validation failed: Submitted answer does not identify the correct TCP listening port. "
            "Inspect daemon configuration or service inventory.",
        )
    return ValidationResult(
        True,
        "Confirmed: PULSE/1 daemon was listening on TCP port 7741.",
        finding="PULSE/1 daemon listening on TCP port 7741",
    )


def _val_p02(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-NET-001", "EV-NET-003"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires network capture or transcript evidence (EV-NET-001, EV-NET-003).",
        )
    ans_upper = answer.upper()
    if "PULS" not in ans_upper and "50554C53" not in ans_upper:
        return ValidationResult(
            False,
            "Validation failed: Submitted answer does not identify the 4-byte protocol magic identifier. "
            "Inspect wire frame headers in capture.pcap or pulse_session.transcript.",
        )
    return ValidationResult(
        True,
        "Confirmed: PULSE/1 framing uses 4-byte magic 'PULS' (0x50554c53) with 1-byte version and opcode.",
        finding="Protocol framing identified: magic PULS (0x50554c53), v1",
    )


def _val_p03(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-NET-001", "EV-NET-003", "EV-LOG-001"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires network or application log evidence (EV-NET-001, EV-NET-003, EV-LOG-001).",
        )
    if "198.51.100.24" not in answer:
        return ValidationResult(
            False,
            "Validation failed: Submitted answer does not identify the external client IP address. "
            "Review connection telemetry in network or host logs.",
        )
    return ValidationResult(
        True,
        "Confirmed: External client 198.51.100.24 established session on port 7741.",
        finding="Attacker origin IP 198.51.100.24 verified",
    )


def _val_p04(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-NET-001", "EV-NET-003", "EV-LOG-001"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires network transcript or daemon log evidence (EV-NET-001, EV-LOG-001).",
        )
    ans_upper = answer.upper()
    if "READ_DIAG" not in ans_upper and "0X04" not in ans_upper and not re.search(r"\b4\b", answer):
        return ValidationResult(
            False,
            "Validation failed: Submitted answer does not identify the message type accepted after AUTH failure. "
            "Examine message frame sequence following Error 401.",
        )
    return ValidationResult(
        True,
        "Confirmed: Daemon state machine flaw permitted READ_DIAG (0x04) immediately following failed AUTH.",
        finding="Auth flaw confirmed: unauthenticated READ_DIAG processed following 401 error",
    )


def _val_p05(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-NET-002", "EV-NET-001", "EV-NET-003", "EV-LOG-001"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires tap metadata or host log evidence (EV-NET-002, EV-LOG-001).",
        )
    if not re.search(r"\b420\b", answer) and "7 MINUTE" not in answer.upper():
        return ValidationResult(
            False,
            "Validation failed: Submitted answer does not specify the correct time delta (in seconds) "
            "between network tap timestamps and host system logs.",
        )
    return ValidationResult(
        True,
        "Confirmed: Empirical timestamp difference between tap capture and host logs is exactly 420 seconds (7 minutes).",
        finding="Timestamp delta identified: 420 seconds (7 minutes)",
    )


def _val_p06(answer: str, evidence: list[str]) -> ValidationResult:
    if "EV-NET-002" not in evidence:
        return ValidationResult(
            False,
            "Submission requires optical tap metadata evidence (EV-NET-002).",
        )
    ans_lower = answer.lower()
    has_tap_drift = any(w in ans_lower for w in ("tap", "drift", "hardware", "rtc", "metadata"))
    has_correlation = any(w in ans_lower for w in ("paired", "events", "delta", "syn", "correlation", "invariant", "session", "constant"))
    if not (has_tap_drift and has_correlation):
        return ValidationResult(
            False,
            "Validation failed: Answer must explain how tap hardware RTC drift (documented in capture.meta) "
            "is independently corroborated by the invariant +420s delta across multiple paired session events.",
        )
    return ValidationResult(
        True,
        "Confirmed: Documented tap metadata drift (-420s) matches invariant +420s delta across all 4 paired session events, proving upstream hardware drift rather than host timestomping.",
        finding="Clock skew root cause proven: optical tap RTC drift corroborated across 4 paired session events",
    )


def _val_p07(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-NET-001", "EV-NET-003", "EV-LOG-001"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires network capture or transcript evidence (EV-NET-001, EV-NET-003).",
        )
    ans_lower = answer.lower()
    has_helper = "pulse-helper" in ans_lower
    has_ticket = "diag-tkt-7741-alpha" in ans_lower or "fraga" in ans_lower or "fragment" in ans_lower
    if not (has_helper and has_ticket):
        return ValidationResult(
            False,
            "Validation failed: Submitted answer must identify both the maintenance helper binary path "
            "and diagnostic ticket token leaked in the READ_DIAG payload.",
        )
    return ValidationResult(
        True,
        "Confirmed: READ_DIAG response leaked /usr/local/bin/pulse-helper, ticket DIAG-TKT-7741-ALPHA, and key fragment A.",
        finding="Diagnostic leak verified: leaked pulse-helper path and diagnostic ticket token",
    )


def _val_p08(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-SYS-001", "EV-SYS-003", "EV-CFG-002"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires user database or file permissions evidence (EV-SYS-001, EV-SYS-003).",
        )
    ans_lower = answer.lower()
    has_user = "svc-pulse" in ans_lower
    has_mode = "4750" in ans_lower or "setuid" in ans_lower
    if not (has_user and has_mode):
        return ValidationResult(
            False,
            "Validation failed: Answer must identify the service user account (svc-pulse) and the "
            "setuid permissions mode (4750) of pulse-helper.",
        )
    return ValidationResult(
        True,
        "Confirmed: PULSE runs under svc-pulse (UID 1002); pulse-helper is mode 4750 root:svc-pulse (setuid root).",
        finding="Service identity and DAC verified: svc-pulse (1002) with 4750 setuid helper",
    )


def _val_p09(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-SYS-003", "EV-CFG-001"}
    if not any(e in valid_ev for e in evidence):
        return ValidationResult(
            False,
            "Submission requires file permissions or helper configuration evidence (EV-SYS-003, EV-CFG-001).",
        )
    ans_lower = answer.lower()
    has_arg = "--archive-check" in ans_lower or "archive-check" in ans_lower
    has_op = any(w in ans_lower for w in ("system", "command injection", "shell", "injection"))
    if not (has_arg and has_op):
        return ValidationResult(
            False,
            "Validation failed: Answer must identify the command-line argument (--archive-check) and "
            "the unsafe execution mechanism (system() call without input validation).",
        )
    return ValidationResult(
        True,
        "Confirmed: pulse-helper unsafely formats --archive-check input into system() with setuid root privileges.",
        finding="Helper boundary flaw confirmed: command injection in --archive-check executed via system()",
    )


def _val_p10(answer: str, evidence: list[str]) -> ValidationResult:
    if "EV-DAT-001" not in evidence and "EV-DAT-002" not in evidence:
        return ValidationResult(
            False,
            "Submission requires encrypted vault or diagnostic ticket evidence (EV-DAT-001, EV-DAT-002).",
        )
    ans_upper = answer.upper()
    has_header = "MERIDIAN-AERO-VAULT" in ans_upper or "VAULT-V2.4" in ans_upper
    has_key = "FRAGB-SIG9902" in ans_upper or "MERIDIAN-VAULT-2024" in ans_upper
    if not (has_header and has_key):
        return ValidationResult(
            False,
            "Validation failed: Answer must state the decrypted vault plaintext header and the key derivation material.",
        )
    return ValidationResult(
        True,
        "Confirmed: Combined key unlocked research_vault.tar.gz.enc revealing header MERIDIAN-AERO-VAULT-v2.4.",
        finding="Cryptographic key recovered and research vault decrypted (header MERIDIAN-AERO-VAULT-v2.4)",
    )


def _val_p11(answer: str, evidence: list[str]) -> ValidationResult:
    if "EV-LOG-002" not in evidence:
        return ValidationResult(
            False,
            "Submission requires Linux audit log evidence (EV-LOG-002).",
        )
    ans_lower = answer.lower()
    has_serial = "894" in ans_lower
    has_user = "1001" in ans_lower or "rhea" in ans_lower
    if not (has_serial and has_user):
        return ValidationResult(
            False,
            "Validation failed: Answer must cite the specific audit event serial number (894) and the user ID reported.",
        )
    return ValidationResult(
        True,
        "Confirmed: Audit event 894 records archive command attributing execution to auid=1001 (rhea).",
        finding="Suspicious audit event 894 identified attributing archive command to rhea (auid 1001)",
    )


def _val_p12(answer: str, evidence: list[str]) -> ValidationResult:
    valid_ev = {"EV-LOG-003", "EV-LOG-004", "EV-USR-001"}
    if len(set(evidence).intersection(valid_ev)) < 2:
        return ValidationResult(
            False,
            "Submission requires at least two independent corroborating sources from: "
            "EV-LOG-003 (auth.log), EV-LOG-004 (wtmp.json), or EV-USR-001 (rhea_bash_history).",
        )
    ans_lower = answer.lower()
    has_auth = "auth" in ans_lower or "pam" in ans_lower
    has_session = "wtmp" in ans_lower or "session" in ans_lower or "pts" in ans_lower or "history" in ans_lower or "bash" in ans_lower
    if not (has_auth and has_session):
        return ValidationResult(
            False,
            "Validation failed: Answer must corroborate that user rhea had zero active PAM sessions in auth.log, "
            "zero terminal sessions in wtmp, and a clean bash history.",
        )
    return ValidationResult(
        True,
        "Confirmed: Multi-source corroboration establishes rhea had zero PAM logins, zero active terminals, and no archive commands in history.",
        finding="Rhea alibi corroborated: zero PAM logins, zero terminal sessions, and clean history",
    )


def _val_p13(answer: str, evidence: list[str]) -> ValidationResult:
    if "EV-LOG-002" not in evidence:
        return ValidationResult(
            False,
            "Submission requires Linux audit log evidence (EV-LOG-002).",
        )
    ans_lower = answer.lower()
    has_pid = "1418" in ans_lower
    has_ppid = "1412" in ans_lower or "svc-pulse" in ans_lower
    if not (has_pid and has_ppid):
        return ValidationResult(
            False,
            "Validation failed: Answer must cite the real PID (1418) and parent PPID (1412 / svc-pulse) "
            "from genuine kernel audit records.",
        )
    return ValidationResult(
        True,
        "Confirmed: Authentic kernel audit record (event 892) shows pulse-helper (PID 1418) was spawned by PULSE/1 (PPID 1412) under svc-pulse.",
        finding="Real process lineage proven: pulse-helper (PID 1418) spawned by PULSE daemon (PPID 1412)",
    )


def _val_p14(answer: str, evidence: list[str]) -> ValidationResult:
    if "EV-LOG-002" not in evidence:
        return ValidationResult(
            False,
            "Submission requires Linux audit log evidence (EV-LOG-002).",
        )
    ans_lower = answer.lower()
    has_orphan = any(w in ans_lower for w in ("orphan", "missing syscall", "no syscall", "proctitle", "companion", "single"))
    has_ses = "4294967295" in ans_lower or "unset" in ans_lower or "ses" in ans_lower or "append" in ans_lower or "injected" in ans_lower
    if not (has_orphan and has_ses):
        return ValidationResult(
            False,
            "Validation failed: Answer must identify the structural anomalies exposing audit tampering: "
            "orphan EXECVE record lacking atomic kernel SYSCALL companion, and unset session attribute (ses=4294967295).",
        )
    return ValidationResult(
        True,
        "Confirmed: Event 894 is an orphan EXECVE record missing companion kernel SYSCALL/PROCTITLE records with unset session ses=4294967295, proving out-of-band text injection.",
        finding="Tampering mechanics exposed: orphan EXECVE record lacking companion kernel SYSCALL and unset ses",
    )


def _val_p15(answer: str, evidence: list[str]) -> ValidationResult:
    ans_lower = answer.lower()
    has_entry = any(w in ans_lower for w in ("pulse", "7741", "198.51.100.24", "read_diag"))
    has_escalation = any(w in ans_lower for w in ("pulse-helper", "setuid", "archive-check", "injection"))
    has_clock = any(w in ans_lower for w in ("420", "tap", "drift", "offset", "rtc"))
    has_rhea = any(w in ans_lower for w in ("rhea", "framed", "orphan", "fabricat", "injected", "alibi", "exonerat"))

    if not (has_entry and has_escalation and has_clock and has_rhea):
        missing = []
        if not has_entry: missing.append("attacker entry point (PULSE/1 on 7741)")
        if not has_escalation: missing.append("privilege escalation path (setuid pulse-helper injection)")
        if not has_clock: missing.append("clock offset explanation (420s optical tap hardware drift)")
        if not has_rhea: missing.append("proof exonerating rhea (fabricated orphan audit record)")
        return ValidationResult(
            False,
            f"Validation failed: Incident verdict is incomplete. Missing coverage for: {', '.join(missing)}.",
        )

    return ValidationResult(
        True,
        "INCIDENT VERDICT VERIFIED: The comprehensive incident report successfully establishes all ground-truth facts: "
        "external PULSE/1 exploitation from 198.51.100.24, privilege escalation via setuid pulse-helper, benign 420s tap drift, "
        "and complete multi-source exoneration of rhea against the fabricated audit record.",
        finding="Final incident verdict approved: evidence-backed ground truth established",
    )


# -------------------------------------------------------------------------
# Objective Registry
# -------------------------------------------------------------------------

OBJECTIVES: list[Objective] = [
    Objective(
        id="P01",
        phase="Phase A: Initial Protocol Triage",
        title="Service Port Discovery",
        question="On which TCP port was the unauthenticated PULSE/1 service listening during the breach?",
        prerequisites=[],
        required_evidence_ids=["EV-CFG-001", "EV-SRV-001"],
        fact_supported="PULSE/1 daemon listening on TCP port 7741",
        validator=_val_p01,
        summary_template="Target service port: 7741",
    ),
    Objective(
        id="P02",
        phase="Phase A: Initial Protocol Triage",
        title="Protocol Wire Framing",
        question="What is the 4-byte magic identifier and byte layout of a PULSE/1 wire frame?",
        prerequisites=["P01"],
        required_evidence_ids=["EV-NET-001", "EV-NET-003"],
        fact_supported="PULSE/1 binary wire framing with magic identifier PULS",
        validator=_val_p02,
        summary_template="Protocol framing: magic PULS (0x50554c53)",
    ),
    Objective(
        id="P03",
        phase="Phase B: Timing Corroboration",
        title="Attacker IP & Session Sequence",
        question="What was the external IP address of the client that connected to the PULSE/1 daemon?",
        prerequisites=["P02"],
        required_evidence_ids=["EV-NET-001", "EV-NET-003", "EV-LOG-001"],
        fact_supported="External client 198.51.100.24 initiated session on port 7741",
        validator=_val_p03,
        summary_template="Attacker IP: 198.51.100.24",
    ),
    Objective(
        id="P04",
        phase="Phase C: Protocol & Privileged Helper",
        title="Authentication State Machine Flaw",
        question="Which message type was accepted and processed by the daemon immediately after emitting an authentication failure error?",
        prerequisites=["P03"],
        required_evidence_ids=["EV-NET-001", "EV-LOG-001"],
        fact_supported="State machine flaw processed unauthenticated READ_DIAG after 401 error",
        validator=_val_p04,
        summary_template="Auth state flaw: READ_DIAG (0x04) accepted without authentication",
    ),
    Objective(
        id="P05",
        phase="Phase B: Timing Corroboration",
        title="Timestamp Offset Identification",
        question="What is the precise time delta (in seconds) between network packet timestamps and host system logs?",
        prerequisites=["P03"],
        required_evidence_ids=["EV-NET-002", "EV-LOG-001"],
        fact_supported="Time delta between network tap and host clock is exactly 420 seconds",
        validator=_val_p05,
        summary_template="Clock delta: 420 seconds (7 minutes)",
    ),
    Objective(
        id="P06",
        phase="Phase B: Timing Corroboration",
        title="Skew Root Cause Proof",
        question="What evidence corroborates that the 420-second discrepancy is an upstream tap clock drift rather than host timestomping?",
        prerequisites=["P05"],
        required_evidence_ids=["EV-NET-002", "EV-LOG-001"],
        fact_supported="Documented optical tap RTC drift corroborated across 4 paired session events",
        validator=_val_p06,
        summary_template="Skew cause: optical tap RTC hardware drift (-420s)",
    ),
    Objective(
        id="P07",
        phase="Phase C: Protocol & Privileged Helper",
        title="Diagnostic Secret Leak",
        question="What sensitive configuration file path and diagnostic ticket token were returned in the unauthenticated READ_DIAG response?",
        prerequisites=["P04"],
        required_evidence_ids=["EV-NET-001", "EV-NET-003"],
        fact_supported="Leaked /usr/local/bin/pulse-helper path and diagnostic ticket token",
        validator=_val_p07,
        summary_template="Diagnostic leak: /usr/local/bin/pulse-helper and DIAG-TKT-7741-ALPHA",
    ),
    Objective(
        id="P08",
        phase="Phase C: Protocol & Privileged Helper",
        title="Service Footprint & Permissions",
        question="Under which Linux user account does the PULSE/1 daemon run, and what discretionary access permissions does it hold over /usr/local/bin/pulse-helper?",
        prerequisites=["P07"],
        required_evidence_ids=["EV-SYS-001", "EV-SYS-003"],
        fact_supported="Service user svc-pulse (UID 1002); helper is mode 4750 setuid root",
        validator=_val_p08,
        summary_template="Service identity: svc-pulse (1002) with 4750 setuid root helper",
    ),
    Objective(
        id="P09",
        phase="Phase C: Protocol & Privileged Helper",
        title="Privileged Helper Boundary Analysis",
        question="What exact command-line field and unsafe operation in /usr/local/bin/pulse-helper allowed svc-pulse to execute commands as root?",
        prerequisites=["P08"],
        required_evidence_ids=["EV-SYS-003", "EV-CFG-001"],
        fact_supported="Command injection in --archive-check argument executed via system() under setuid root",
        validator=_val_p09,
        summary_template="Privilege boundary: command injection in --archive-check via system()",
    ),
    Objective(
        id="P10",
        phase="Phase C: Protocol & Privileged Helper",
        title="Cryptographic Key Recovery",
        question="What was the decrypted plaintext header of the target research archive, and what key was used to unlock it?",
        prerequisites=["P07", "P09"],
        required_evidence_ids=["EV-DAT-001", "EV-DAT-002"],
        fact_supported="Recovered key unlocked archive revealing header MERIDIAN-AERO-VAULT-v2.4",
        validator=_val_p10,
        summary_template="Archive recovery: header MERIDIAN-AERO-VAULT-v2.4 unlocked with combined key",
    ),
    Objective(
        id="P11",
        phase="Phase D: Deception Analysis",
        title="Forged Audit Record Discovery",
        question="Which specific line/record in /var/log/audit/audit.log records the execution of the archive export command, and what user ID is reported?",
        prerequisites=["P01"],
        required_evidence_ids=["EV-LOG-002"],
        fact_supported="Event 894 records archive command attributed to auid=1001 (rhea)",
        validator=_val_p11,
        summary_template="Suspicious audit event: 894 framing rhea (auid 1001)",
    ),
    Objective(
        id="P12",
        phase="Phase D: Deception Analysis",
        title="User Rhea Alibi Corroboration",
        question="What evidence from PAM authentication logs, session databases, and shell histories proves user rhea was not active during the incident?",
        prerequisites=["P11"],
        required_evidence_ids=["EV-LOG-003", "EV-LOG-004", "EV-USR-001"],
        fact_supported="Multi-source proof: zero PAM logins, zero active terminals, clean bash history",
        validator=_val_p12,
        summary_template="Rhea alibi: zero PAM sessions in auth.log, zero wtmp terminals, clean history",
    ),
    Objective(
        id="P13",
        phase="Phase C: Protocol & Privileged Helper",
        title="Real Process Lineage",
        question="What were the real Process ID (PID) and Parent Process ID (PPID) of the archive export process, and which identity actually spawned it according to genuine kernel SYSCALL audit records?",
        prerequisites=["P09", "P11"],
        required_evidence_ids=["EV-LOG-002", "EV-SRV-001"],
        fact_supported="Authentic kernel event 892 shows pulse-helper (PID 1418) spawned by PID 1412 (svc-pulse)",
        validator=_val_p13,
        summary_template="Process lineage: PID 1418 spawned by PULSE daemon PPID 1412 under svc-pulse",
    ),
    Objective(
        id="P14",
        phase="Phase D: Deception Analysis",
        title="Tampering Mechanics",
        question="How was the audit record manipulated, and what structural anomalies expose the tampering?",
        prerequisites=["P11", "P12", "P13"],
        required_evidence_ids=["EV-LOG-002"],
        fact_supported="Orphan EXECVE record missing atomic kernel SYSCALL/PROCTITLE companion and unset ses=4294967295",
        validator=_val_p14,
        summary_template="Tampering mechanics: orphan EXECVE missing kernel companion records with unset ses",
    ),
    Objective(
        id="P15",
        phase="Phase E: Final Synthesis",
        title="Final Incident Verdict",
        question="Synthesize the comprehensive incident report establishing entry vector, privilege escalation, clock offset, and rhea exoneration.",
        prerequisites=["P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10", "P11", "P12", "P13", "P14"],
        required_evidence_ids=["EV-NET-001", "EV-LOG-001", "EV-LOG-002", "EV-SYS-003"],
        fact_supported="Comprehensive incident synthesis and evidence-backed verdict",
        validator=_val_p15,
        summary_template="Final incident verdict approved: evidence-backed ground truth established",
    ),
]

OBJECTIVES_BY_ID: dict[str, Objective] = {obj.id: obj for obj in OBJECTIVES}


def validate_submission(
    objective_id: str,
    answer: str,
    evidence_ids: list[str],
    tracker: ProgressTracker | None = None,
) -> ValidationResult:
    """Validate an investigator submission against scenario ground truth."""
    obj = OBJECTIVES_BY_ID.get(objective_id.upper())
    if not obj:
        return ValidationResult(False, f"Unknown objective ID: '{objective_id}'. Must be P01 through P15.")

    active_tracker = tracker or ProgressTracker()

    # Check prerequisites
    status = active_tracker.get_status(obj)
    if status == "LOCKED":
        unmet = [p for p in obj.prerequisites if not active_tracker.is_completed(p)]
        return ValidationResult(
            False,
            f"Objective {obj.id} is LOCKED. You must complete preceding objectives first: {', '.join(unmet)}.",
        )

    # Validate evidence identifiers format
    normalized_ev: list[str] = []
    for ev in evidence_ids:
        ev_clean = ev.strip().upper()
        if ev_clean in KNOWN_EVIDENCE_IDS:
            normalized_ev.append(ev_clean)

    # Execute deterministic validator
    result = obj.validator(answer.strip(), normalized_ev)
    if result.success and result.finding:
        active_tracker.mark_completed(obj.id, normalized_ev, result.finding)

    return result


def generate_final_report(tracker: ProgressTracker | None = None) -> str:
    """Generate the comprehensive Incident Investigation Verdict report."""
    active_tracker = tracker or ProgressTracker()
    data = active_tracker.load()
    completed = data.get("completed", {})

    lines = [
        "================================================================================",
        " MERIDIAN RESEARCH INCIDENT — FINAL INCIDENT VERDICT REPORT",
        " Classification: OFFICIAL FORENSIC SYNTHESIS (Offline Deterministic Verification)",
        f" Report Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "================================================================================",
        "",
        "## 1. Executive Summary",
        "Between 03:14:02 UTC and 03:22:05 UTC on 2026-09-14, an external threat actor",
        "leveraged an unauthenticated network vulnerability in the proprietary PULSE/1",
        "telemetry service running on host meridian-lab (10.0.4.15). The attacker achieved",
        "transient root execution via a command injection flaw in an internal setuid",
        "maintenance helper (/usr/local/bin/pulse-helper) and decrypted proprietary aerospace",
        "vault archives in /var/archive/meridian. To misdirect investigators, the adversary",
        "manually appended a fabricated audit record attributing the compromise to employee",
        "rhea (AUID 1001). Forensic cross-correlation refutes the framing and confirms",
        "that an observed 7-minute timestamp offset is attributable to upstream optical tap",
        "hardware clock drift.",
        "",
        "## 2. Core Forensic Findings & Ground Truth Corroboration",
        "",
        "1. Entry Point & Protocol Vulnerability:",
        "   - Target Service: PULSE/1 daemon listening on TCP port 7741.",
        "   - Attacker IP: 198.51.100.24 (RFC 5737 documentation prefix).",
        "   - Vulnerability: Protocol state machine defect accepted and processed READ_DIAG",
        "     queries following an Authentication Failure (401) response, leaking maintenance",
        "     helper paths and cryptographic key tokens.",
        "",
        "2. Privilege Escalation & Execution Boundary:",
        "   - Service User: svc-pulse (UID 1002, GID 1002).",
        "   - Privilege Escalation: /usr/local/bin/pulse-helper, mode 4750 (root:svc-pulse setuid).",
        "   - Flaw: Unsanitized --archive-check argument evaluated via system() under root privileges.",
        "   - Ground Truth Lineage: Genuine kernel syscall audit records (event 892) confirm child",
        "     PID 1418 was spawned directly by the PULSE daemon (PPID 1412) under svc-pulse.",
        "",
        "3. Resolution of the 7-Minute Clock Offset (Discrepancy 1):",
        "   - Observed Delta: Network tap frames lag host system logs by exactly 420 seconds.",
        "   - Root Cause: Upstream optical tap TAP-MERIDIAN-01 hardware RTC drift (-420s),",
        "     documented in tap control-plane metadata (capture.meta).",
        "   - Corroboration: The +420.0s offset is invariant across 4 independent paired session",
        "     milestones (SYN, AUTH, READ_DIAG, CLOSE), refuting hostile timestomping.",
        "",
        "4. Exoneration of Rhea & Forensic Tampering Analysis (Discrepancy 2):",
        "   - Fabricated Record: Event 894 in audit.log claiming rhea ran 'tar -czf'.",
        "   - Structural Anomalies: Event 894 is an orphan EXECVE record lacking atomic kernel",
        "     companion SYSCALL and PROCTITLE records with matching serial number, with unset ses.",
        "   - Corroborating Alibi: PAM auth.log records zero logins for rhea on the incident date;",
        "     wtmp confirms zero terminal allocations; .bash_history confirms no archive commands.",
        "   - True Perpetrator: Injected via transient root access from pulse-helper under svc-pulse.",
        "",
        "## 3. Verified Objectives Status",
    ]

    for obj in OBJECTIVES:
        is_done = obj.id in completed
        status_sym = "[X]" if is_done else "[ ]"
        finding = completed[obj.id].get("finding", "Incomplete") if is_done else "Incomplete"
        lines.append(f"  {status_sym} {obj.id}: {obj.title} — {finding}")

    lines.extend([
        "",
        "## 4. Final Verdict",
        "STATUS: CLOSED — ATTRIBUTED TO EXTERNAL NETWORK THREAT ACTOR (198.51.100.24).",
        "EMPLOYEE RHEA VANCE IS FULLY EXONERATED.",
        "================================================================================",
    ])

    return "\n".join(lines) + "\n"
