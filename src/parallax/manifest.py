"""Cryptographic evidence manifest and integrity verification utilities."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


def calculate_sha256(file_path: str | Path, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file in streaming chunks."""
    path = Path(file_path)
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_manifest(
    directory: str | Path,
    base_dir: str | Path | None = None,
    scenario_name: str = "Meridian Research Incident",
    metadata_lookup: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a structured manifest containing SHA-256 hashes and file metadata.

    Args:
        directory: Directory containing evidence artifacts to index.
        base_dir: Base directory used to calculate relative paths. Defaults to directory.
        scenario_name: Name of the scenario context.
        metadata_lookup: Optional mapping of relative file paths to extra artifact metadata.

    Returns:
        A dictionary containing manifest metadata and a list of artifact records.
    """
    scan_path = Path(directory).resolve()
    root_path = Path(base_dir).resolve() if base_dir else scan_path

    artifacts: list[dict[str, Any]] = []

    for file_path in sorted(scan_path.rglob("*")):
        if not file_path.is_file():
            continue
        # Skip hidden files and existing manifest files
        if file_path.name.startswith(".") or file_path.name in ("SHA256SUMS", "manifest.json"):
            continue

        rel_path = file_path.relative_to(root_path).as_posix()
        file_stat = file_path.stat()
        file_hash = calculate_sha256(file_path)

        entry: dict[str, Any] = {
            "path": rel_path,
            "sha256": file_hash,
            "size_bytes": file_stat.st_size,
            "modified_utc": datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc).isoformat(),
        }

        if metadata_lookup and rel_path in metadata_lookup:
            for key, val in metadata_lookup[rel_path].items():
                if key not in entry:
                    entry[key] = val

        artifacts.append(entry)

    return {
        "manifest_version": "1.0.0",
        "scenario": scenario_name,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "total_files": len(artifacts),
        "artifacts": artifacts,
    }


def write_manifests(
    scan_dir: str | Path,
    manifest_dir: str | Path,
    base_dir: str | Path | None = None,
    scenario_name: str = "Meridian Research Incident",
    metadata_lookup: dict[str, dict[str, Any]] | None = None,
) -> tuple[Path, Path]:
    """Generate and write SHA256SUMS and manifest.json to manifest_dir."""
    m_dir = Path(manifest_dir).resolve()
    m_dir.mkdir(parents=True, exist_ok=True)

    manifest_data = generate_manifest(
        directory=scan_dir,
        base_dir=base_dir,
        scenario_name=scenario_name,
        metadata_lookup=metadata_lookup,
    )

    sha256_path = m_dir / "SHA256SUMS"
    sha256_path.write_text(format_sha256sums(manifest_data), encoding="utf-8")

    json_path = m_dir / "manifest.json"
    json_path.write_text(json.dumps(manifest_data, indent=2) + "\n", encoding="utf-8")

    return sha256_path, json_path


def format_sha256sums(manifest_data: dict[str, Any]) -> str:
    """Format manifest artifacts as standard sha256sum lines (<hash>  <path>)."""
    lines: list[str] = []
    for artifact in manifest_data.get("artifacts", []):
        lines.append(f"{artifact['sha256']}  {artifact['path']}")
    return "\n".join(lines) + ("\n" if lines else "")


def parse_sha256sums(content: str) -> dict[str, str]:
    """Parse standard sha256sum lines into a {path: sha256} mapping."""
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            checksum, path = parts
            # Normalize path (handle standard " *" or "  " delimiters)
            path = path.lstrip("* ").strip()
            result[path] = checksum.lower()
    return result


def verify_manifest(
    manifest_data: dict[str, Any],
    base_dir: str | Path,
) -> tuple[bool, list[str]]:
    """Verify that all files in a manifest exist and match their recorded SHA-256 hashes.

    Returns:
        (is_valid, error_messages)
    """
    root_path = Path(base_dir).resolve()
    errors: list[str] = []

    artifacts = manifest_data.get("artifacts", [])
    if not isinstance(artifacts, list):
        return False, ["Invalid manifest structure: 'artifacts' must be a list"]

    for item in artifacts:
        rel_path = item.get("path")
        expected_hash = item.get("sha256")

        if not rel_path or not expected_hash:
            errors.append(f"Malformed artifact entry: {item}")
            continue

        target_file = root_path / rel_path
        if not target_file.is_file():
            errors.append(f"Missing file: {rel_path}")
            continue

        actual_hash = calculate_sha256(target_file)
        if actual_hash.lower() != expected_hash.lower():
            errors.append(
                f"Checksum mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
            )

    return (len(errors) == 0), errors


def verify_sha256sums(
    sha256sums_content: str,
    base_dir: str | Path,
) -> tuple[bool, list[str]]:
    """Verify files against standard sha256sum text content."""
    root_path = Path(base_dir).resolve()
    parsed = parse_sha256sums(sha256sums_content)
    errors: list[str] = []

    if not parsed:
        return True, []

    for rel_path, expected_hash in parsed.items():
        target_file = root_path / rel_path
        if not target_file.is_file():
            errors.append(f"Missing file: {rel_path}")
            continue

        actual_hash = calculate_sha256(target_file)
        if actual_hash.lower() != expected_hash.lower():
            errors.append(
                f"Checksum mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
            )

    return (len(errors) == 0), errors
