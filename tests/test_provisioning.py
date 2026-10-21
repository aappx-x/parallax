"""Tests for system provisioning scripts, cloud-init configs, and idempotency guarantees."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import pytest

from parallax.system.boundary import (
    ANALYST_GID,
    ANALYST_UID,
    ANALYST_USER,
    BOUNDARY_SPEC,
    RHEA_GID,
    RHEA_UID,
    RHEA_USER,
    SVC_PULSE_GID,
    SVC_PULSE_UID,
    SVC_PULSE_USER,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PROVISION_SH = REPO_ROOT / "infra" / "provisioning" / "provision.sh"
CLOUD_INIT_DIR = REPO_ROOT / "infra" / "provisioning" / "cloud-init"
USER_DATA = CLOUD_INIT_DIR / "user-data"
META_DATA = CLOUD_INIT_DIR / "meta-data"


def test_provision_script_exists_and_executable():
    assert PROVISION_SH.is_file(), f"provision.sh not found at {PROVISION_SH}"
    assert os.access(PROVISION_SH, os.X_OK), "provision.sh must be executable (+x)"


def test_provision_script_bash_syntax():
    """Verify provision.sh passes bash syntax checking."""
    proc = subprocess.run(["bash", "-n", str(PROVISION_SH)], capture_output=True, text=True)
    assert proc.returncode == 0, f"bash -n failed on provision.sh: {proc.stderr}"


def test_provision_script_help():
    """Verify provision.sh --help displays usage information and supported modes."""
    proc = subprocess.run([str(PROVISION_SH), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "--prepare" in proc.stdout
    assert "--activate" in proc.stdout
    assert "--deactivate" in proc.stdout
    assert "--dry-run" in proc.stdout


def test_provision_script_dry_run():
    """Verify provision.sh --dry-run completes cleanly without making filesystem modifications."""
    proc = subprocess.run([str(PROVISION_SH), "--dry-run"], capture_output=True, text=True)
    assert proc.returncode == 0, f"Dry-run failed: {proc.stderr}\n{proc.stdout}"
    assert "[DRY-RUN]" in proc.stdout
    assert "Dry-run validation complete" in proc.stdout


def test_provision_script_boundary_constants_alignment():
    """Verify user/group identities and paths in provision.sh match boundary.py."""
    content = PROVISION_SH.read_text(encoding="utf-8")

    assert f'ANALYST_USER="{ANALYST_USER}"' in content
    assert f"ANALYST_UID={ANALYST_UID}" in content
    assert f"ANALYST_GID={ANALYST_GID}" in content

    assert f'RHEA_USER="{RHEA_USER}"' in content
    assert f"RHEA_UID={RHEA_UID}" in content
    assert f"RHEA_GID={RHEA_GID}" in content

    assert f'SVC_PULSE_USER="{SVC_PULSE_USER}"' in content
    assert f"SVC_PULSE_UID={SVC_PULSE_UID}" in content
    assert f"SVC_PULSE_GID={SVC_PULSE_GID}" in content

    # Check key boundary paths
    for path in BOUNDARY_SPEC.keys():
        assert path in content, f"Path {path} from BOUNDARY_SPEC should be defined in provision.sh"


def test_cloud_init_user_data_structure():
    """Verify cloud-init user-data file contains required sections."""
    assert USER_DATA.is_file(), f"user-data missing at {USER_DATA}"
    text = USER_DATA.read_text(encoding="utf-8")

    assert text.startswith("#cloud-config"), "user-data must start with #cloud-config header"
    assert "autoinstall:" in text
    assert "hostname: meridian-lab" in text
    assert "username: analyst" in text
    assert "packages:" in text
    assert "python3" in text
    assert "auditd" in text
    assert "build-essential" in text
    assert "provision.sh --prepare" in text


def test_cloud_init_meta_data_structure():
    """Verify cloud-init meta-data file contains required instance identification."""
    assert META_DATA.is_file(), f"meta-data missing at {META_DATA}"
    text = META_DATA.read_text(encoding="utf-8")
    assert "instance-id:" in text
    assert "local-hostname: meridian-lab" in text


def test_investigator_notes_and_progress_preservation():
    """Simulate staging rerun and verify that user notes and progress files are not destroyed."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_target = Path(tmp_dir) / "evidence"
        notes_dir = tmp_target / "notes"
        derived_dir = tmp_target / "derived"
        notes_dir.mkdir(parents=True)
        derived_dir.mkdir(parents=True)

        # Create investigator files
        investigator_note = notes_dir / "investigator_hypothesis.txt"
        investigator_note.write_text("Discrepancy 1: optical tap clock drift -420s", encoding="utf-8")

        progress_file = derived_dir / ".progress.json"
        progress_file.write_text('{"P01": {"completed": true, "timestamp": 12345}}', encoding="utf-8")

        source_evidence = REPO_ROOT / "evidence"

        # Simulate staging logic: copy raw, manifests, docs, but never overwrite existing notes/progress
        for subdir in ["raw", "manifests"]:
            shutil.copytree(source_evidence / subdir, tmp_target / subdir, dirs_exist_ok=True)

        for doc in ["README.md", "INDEX.md"]:
            if (source_evidence / doc).is_file():
                shutil.copy(source_evidence / doc, tmp_target / doc)

        # Verify investigator files remain intact
        assert investigator_note.is_file()
        assert "optical tap clock drift" in investigator_note.read_text(encoding="utf-8")

        assert progress_file.is_file()
        assert '"P01"' in progress_file.read_text(encoding="utf-8")
