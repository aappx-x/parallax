"""Tests for evidence manifest generation and cryptographic verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

from parallax.manifest import (
    calculate_sha256,
    format_sha256sums,
    generate_manifest,
    parse_sha256sums,
    verify_manifest,
    verify_sha256sums,
)


def test_calculate_sha256(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.txt"
    content = b"PARALLAX synthetic evidence content\n"
    test_file.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    assert calculate_sha256(test_file) == expected


def test_generate_and_verify_manifest(tmp_path: Path) -> None:
    # Create sample directory structure
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    file_a = raw_dir / "evidence_a.log"
    file_b = raw_dir / "evidence_b.pcap"

    file_a.write_text("log line 1\nlog line 2\n")
    file_b.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")

    manifest = generate_manifest(tmp_path, base_dir=tmp_path)

    assert manifest["manifest_version"] == "1.0.0"
    assert manifest["total_files"] == 2
    assert "Z" in manifest["generated_utc"] or "+00:00" in manifest["generated_utc"]

    # Verify manifest passes
    is_valid, errors = verify_manifest(manifest, base_dir=tmp_path)
    assert is_valid is True
    assert errors == []


def test_verify_manifest_detects_tampering(tmp_path: Path) -> None:
    target_file = tmp_path / "artifact.dat"
    target_file.write_text("original content")

    manifest = generate_manifest(tmp_path, base_dir=tmp_path)
    assert verify_manifest(manifest, base_dir=tmp_path)[0] is True

    # Tamper with the artifact
    target_file.write_text("tampered content")

    is_valid, errors = verify_manifest(manifest, base_dir=tmp_path)
    assert is_valid is False
    assert len(errors) == 1
    assert "Checksum mismatch" in errors[0]


def test_verify_manifest_detects_missing_file(tmp_path: Path) -> None:
    target_file = tmp_path / "artifact.dat"
    target_file.write_text("original content")

    manifest = generate_manifest(tmp_path, base_dir=tmp_path)
    target_file.unlink()

    is_valid, errors = verify_manifest(manifest, base_dir=tmp_path)
    assert is_valid is False
    assert len(errors) == 1
    assert "Missing file" in errors[0]


def test_sha256sums_format_and_parse(tmp_path: Path) -> None:
    file_a = tmp_path / "net.pcap"
    file_b = tmp_path / "audit.log"
    file_a.write_bytes(b"packet data")
    file_b.write_text("audit record")

    manifest = generate_manifest(tmp_path, base_dir=tmp_path)
    sha_text = format_sha256sums(manifest)

    # Verify sha256sum format (<hash>  <path>)
    lines = [ln for ln in sha_text.splitlines() if ln.strip()]
    assert len(lines) == 2
    for line in lines:
        parts = line.split("  ")
        assert len(parts) == 2
        assert len(parts[0]) == 64

    # Test round trip parsing
    parsed = parse_sha256sums(sha_text)
    assert len(parsed) == 2
    assert "net.pcap" in parsed
    assert "audit.log" in parsed

    # Verify against disk
    is_valid, errors = verify_sha256sums(sha_text, base_dir=tmp_path)
    assert is_valid is True
    assert errors == []

    # Tamper with file
    file_a.write_bytes(b"tampered data")
    is_valid, errors = verify_sha256sums(sha_text, base_dir=tmp_path)
    assert is_valid is False
    assert len(errors) == 1
    assert "net.pcap" in errors[0]
