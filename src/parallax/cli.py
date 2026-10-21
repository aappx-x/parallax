"""Command-line interface for the PARALLAX investigation and objective validation harness."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from parallax.evidence import decrypt_vault
from parallax.objectives import (
    KNOWN_EVIDENCE_IDS,
    OBJECTIVES,
    OBJECTIVES_BY_ID,
    ProgressTracker,
    generate_final_report,
    validate_submission,
)


def _cmd_list(args: argparse.Namespace, tracker: ProgressTracker) -> int:
    """List all 15 investigation objectives, phases, and completion status."""
    print("================================================================================")
    print(" PARALLAX Investigation Objectives — Meridian Research Incident")
    print("================================================================================")
    print(f" {'ID':<5} {'Status':<11} {'Phase':<32} {'Title'}")
    print("-" * 80)

    for obj in OBJECTIVES:
        status = tracker.get_status(obj)
        status_display = {
            "COMPLETED": "[COMPLETED]",
            "UNLOCKED":  "[UNLOCKED] ",
            "LOCKED":    "[LOCKED]   ",
        }.get(status, status)
        print(f" {obj.id:<5} {status_display:<11} {obj.phase:<32} {obj.title}")

    data = tracker.load()
    completed_count = len(data.get("completed", {}))
    print("-" * 80)
    print(f"Progress: {completed_count}/{len(OBJECTIVES)} objectives completed.")
    if completed_count == len(OBJECTIVES):
        print("[+] Investigation complete! Run 'parallax report' to view final incident verdict.")
    else:
        print("[*] Use 'parallax inspect <ID>' or 'parallax submit <ID> --answer <ans>' to proceed.")
    return 0


def _cmd_inspect(args: argparse.Namespace, tracker: ProgressTracker) -> int:
    """Inspect detailed requirements for a specific objective."""
    obj_id = args.objective_id.upper()
    obj = OBJECTIVES_BY_ID.get(obj_id)
    if not obj:
        print(f"[-] Error: Unknown objective ID '{args.objective_id}'. Must be P01 through P15.")
        return 1

    status = tracker.get_status(obj)
    data = tracker.load()
    completed_info = data.get("completed", {}).get(obj.id)

    print("================================================================================")
    print(f" Objective {obj.id}: {obj.title} [{status}]")
    print("================================================================================")
    print(f" Phase:         {obj.phase}")
    print(f" Prerequisites: {', '.join(obj.prerequisites) if obj.prerequisites else 'None'}")
    print(f" Evidence IDs:  {', '.join(obj.required_evidence_ids)}")
    print(f" Fact Grounded: {obj.fact_supported}")
    print("")
    print(f" Question:")
    print(f"   {obj.question}")
    print("")

    if completed_info:
        print(f" Completed finding:")
        print(f"   {completed_info.get('finding')}")
        print(f" Associated evidence: {', '.join(completed_info.get('evidence_ids', []))}")
    elif status == "LOCKED":
        unmet = [p for p in obj.prerequisites if not tracker.is_completed(p)]
        print(f" [!] This objective is LOCKED. You must complete: {', '.join(unmet)} first.")
    else:
        print(" Submission format:")
        print(f"   parallax submit {obj.id} --evidence {obj.required_evidence_ids[0]} --answer \"<your finding>\"")
    return 0


def _cmd_submit(args: argparse.Namespace, tracker: ProgressTracker) -> int:
    """Submit finding and evidence for an objective."""
    obj_id = args.objective_id.upper()
    evidence_ids = args.evidence or []
    answer = args.answer or ""

    if not answer.strip():
        print("[-] Error: --answer is required. Provide your finding or response.")
        return 1

    res = validate_submission(
        objective_id=obj_id,
        answer=answer,
        evidence_ids=evidence_ids,
        tracker=tracker,
    )

    if res.success:
        print(f"[+] Objective {obj_id} COMPLETED!")
        print(f"    {res.message}")
        if res.finding:
            print(f"    Recorded finding: {res.finding}")
        return 0
    else:
        print(f"[-] Objective {obj_id} Submission Rejected:")
        print(f"    {res.message}")
        return 1


def _cmd_report(args: argparse.Namespace, tracker: ProgressTracker) -> int:
    """Print or export the final incident verdict report."""
    obj15 = OBJECTIVES_BY_ID["P15"]
    status = tracker.get_status(obj15)
    if status == "LOCKED":
        unmet = [p for p in obj15.prerequisites if not tracker.is_completed(p)]
        print(f"[-] Final Verdict is LOCKED.")
        print(f"    All 14 foundational objectives (P01–P14) must be completed before the final verdict unlocks.")
        print(f"    Incomplete objectives: {', '.join(unmet)}")
        return 1

    report = generate_final_report(tracker=tracker)
    if args.output:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report, encoding="utf-8")
        print(f"[+] Final incident verdict exported to: {out_p}")
    else:
        print(report)
    return 0


def _cmd_reset(args: argparse.Namespace, tracker: ProgressTracker) -> int:
    """Reset progress tracker state."""
    tracker.reset()
    print("[+] Investigation progress has been reset to initial state.")
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt an encrypted vault file using derived key material."""
    target_path = Path(args.file)
    if not target_path.is_file():
        print(f"[-] Error: File not found: {args.file}")
        return 1

    passphrase = args.key
    if not passphrase:
        print("[-] Error: --key is required to decrypt.")
        return 1

    try:
        data = target_path.read_bytes()
        plaintext = decrypt_vault(data, passphrase)
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        return 1

    if args.output:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(plaintext)
        print(f"[+] Decrypted archive written to: {out_p}")
    else:
        header_sample = plaintext[:200].decode("utf-8", errors="replace")
        print("[+] Decryption successful! Plaintext preview:")
        print(header_sample)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint dispatcher."""
    parser = argparse.ArgumentParser(
        prog="parallax",
        description="PARALLAX — The Evidence Is Lying: Terminal Investigation Harness",
    )
    parser.add_argument(
        "--progress-file",
        type=Path,
        default=None,
        help="Custom path to .progress.json tracking file",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # list / status
    p_list = subparsers.add_parser("list", aliases=["status"], help="List objectives and status")

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Inspect an objective's question and requirements")
    p_inspect.add_argument("objective_id", help="Objective ID (e.g. P01, P04)")

    # submit
    p_submit = subparsers.add_parser("submit", help="Submit answer and evidence for an objective")
    p_submit.add_argument("objective_id", help="Objective ID (e.g. P01, P04)")
    p_submit.add_argument("--evidence", "-e", nargs="+", help="Evidence IDs (e.g. EV-CFG-001)")
    p_submit.add_argument("--answer", "-a", required=True, help="Your answer or finding")

    # report
    p_report = subparsers.add_parser("report", help="Display or export final incident verdict")
    p_report.add_argument("--output", "-o", help="Optional output filepath for report")

    # reset
    p_reset = subparsers.add_parser("reset", help="Reset local investigation progress")

    # decrypt
    p_decrypt = subparsers.add_parser("decrypt", help="Decrypt an encrypted vault archive")
    p_decrypt.add_argument("file", help="Path to encrypted archive (.enc)")
    p_decrypt.add_argument("--key", "-k", required=True, help="Decryption key/passphrase")
    p_decrypt.add_argument("--output", "-o", help="Optional output path for decrypted file")

    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    tracker = ProgressTracker(progress_file=args.progress_file)

    if args.subcommand in ("list", "status"):
        return _cmd_list(args, tracker)
    elif args.subcommand == "inspect":
        return _cmd_inspect(args, tracker)
    elif args.subcommand == "submit":
        return _cmd_submit(args, tracker)
    elif args.subcommand == "report":
        return _cmd_report(args, tracker)
    elif args.subcommand == "reset":
        return _cmd_reset(args, tracker)
    elif args.subcommand == "decrypt":
        return _cmd_decrypt(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
