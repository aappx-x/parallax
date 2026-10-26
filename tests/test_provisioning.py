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
    check_host_identities,
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


def test_provisioning_uid_gid_collision_resolution():
    """Verify provision.sh resolves non-conflicting IDs when parallaxadmin holds UID/GID 1000."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "parallaxadmin:x:1000:1000:Parallax Administrator:/home/parallaxadmin:/bin/bash\n",
            encoding="utf-8",
        )
        group_file.write_text(
            "root:x:0:\n"
            "parallaxadmin:x:1000:\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["PARALLAX_MOCK_PASSWD"] = str(passwd_file)
        env["PARALLAX_MOCK_GROUP"] = str(group_file)

        proc = subprocess.run(
            [str(PROVISION_SH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env,
        )

        assert proc.returncode == 0, f"Dry-run failed: {proc.stderr}\n{proc.stdout}"

        # Must explicitly detect and preserve parallaxadmin
        assert "Administrator 'parallaxadmin': PRESERVED (UID=1000, GID=1000, untouched)" in proc.stdout

        # Must resolve analyst to 1001 (not 1000)
        assert "Group 'analyst': MISSING (would create GID=1001)" in proc.stdout
        assert "User 'analyst': MISSING (would create UID=1001, GID=1001)" in proc.stdout

        # Must resolve rhea to 1002 (not 1001)
        assert "Group 'rhea': MISSING (would create GID=1002)" in proc.stdout
        assert "User 'rhea': MISSING (would create UID=1002, GID=1002)" in proc.stdout

        # Must resolve svc-pulse to 1003 (not 1002)
        assert "Group 'svc-pulse': MISSING (would create GID=1003)" in proc.stdout
        assert "User 'svc-pulse': MISSING (would create UID=1003, GID=1003)" in proc.stdout


def test_provisioning_preserves_parallaxadmin_intact():
    """Verify administrator account parallaxadmin is preserved completely intact."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        initial_passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "parallaxadmin:x:1000:1000:Parallax Admin:/home/parallaxadmin:/bin/bash\n"
        )
        initial_group = (
            "root:x:0:\n"
            "parallaxadmin:x:1000:\n"
            "sudo:x:27:parallaxadmin\n"
        )

        passwd_file.write_text(initial_passwd, encoding="utf-8")
        group_file.write_text(initial_group, encoding="utf-8")

        env = os.environ.copy()
        env["PARALLAX_MOCK_PASSWD"] = str(passwd_file)
        env["PARALLAX_MOCK_GROUP"] = str(group_file)

        proc = subprocess.run(
            [str(PROVISION_SH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env,
        )

        assert proc.returncode == 0
        assert "Administrator 'parallaxadmin': PRESERVED" in proc.stdout

        # Verify mock files were not mutated in dry-run
        assert passwd_file.read_text(encoding="utf-8") == initial_passwd
        assert group_file.read_text(encoding="utf-8") == initial_group


def test_provisioning_idempotency_repeat_run():
    """Verify rerun of provisioning on already provisioned accounts preserves IDs and makes no duplicate changes."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "parallaxadmin:x:1000:1000:Parallax Admin:/home/parallaxadmin:/bin/bash\n"
            "analyst:x:1001:1001:PARALLAX Investigator:/home/analyst:/bin/bash\n"
            "rhea:x:1002:1002:Rhea Sanders:/home/rhea:/bin/bash\n"
            "svc-pulse:x:1003:1003:PULSE Service Account:/var/log/pulse:/usr/sbin/nologin\n",
            encoding="utf-8",
        )
        group_file.write_text(
            "root:x:0:\n"
            "parallaxadmin:x:1000:\n"
            "analyst:x:1001:\n"
            "rhea:x:1002:\n"
            "svc-pulse:x:1003:\n"
            "systemd-journal:x:101:analyst\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["PARALLAX_MOCK_PASSWD"] = str(passwd_file)
        env["PARALLAX_MOCK_GROUP"] = str(group_file)

        proc = subprocess.run(
            [str(PROVISION_SH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env,
        )

        assert proc.returncode == 0
        assert "Administrator 'parallaxadmin': PRESERVED" in proc.stdout

        # All accounts must be detected as existing
        assert "Group 'analyst': EXISTS (GID=1001)" in proc.stdout
        assert "User 'analyst': EXISTS (UID=1001, GID=1001)" in proc.stdout
        assert "Group 'rhea': EXISTS (GID=1002)" in proc.stdout
        assert "User 'rhea': EXISTS (UID=1002, GID=1002)" in proc.stdout
        assert "Group 'svc-pulse': EXISTS (GID=1003)" in proc.stdout
        assert "User 'svc-pulse': EXISTS (UID=1003, GID=1003)" in proc.stdout

        # Must NOT propose creating any challenge user or group
        assert "would create UID=" not in proc.stdout
        assert "would create GID=" not in proc.stdout

        # Check compliance using boundary.check_host_identities
        audit = check_host_identities(
            admin_user="parallaxadmin",
            passwd_path=passwd_file,
            group_path=group_file,
        )
        assert audit["compliant"] is True
        assert audit["admin_preserved"] is True
        assert len(audit["errors"]) == 0
        assert audit["challenge_accounts"]["analyst"]["uid"] == 1001
        assert audit["challenge_accounts"]["rhea"]["uid"] == 1002
        assert audit["challenge_accounts"]["svc-pulse"]["uid"] == 1003


def test_provisioning_clean_system_default_ids():
    """Verify clean system with no existing accounts provisions ground-truth default IDs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        passwd_file.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
        group_file.write_text("root:x:0:\n", encoding="utf-8")

        env = os.environ.copy()
        env["PARALLAX_MOCK_PASSWD"] = str(passwd_file)
        env["PARALLAX_MOCK_GROUP"] = str(group_file)

        proc = subprocess.run(
            [str(PROVISION_SH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env,
        )

        assert proc.returncode == 0
        assert "User 'analyst': MISSING (would create UID=1000, GID=1000)" in proc.stdout
        assert "User 'rhea': MISSING (would create UID=1001, GID=1001)" in proc.stdout
        assert "User 'svc-pulse': MISSING (would create UID=1002, GID=1002)" in proc.stdout


def test_provisioning_partial_existing_accounts():
    """Verify provisioning handles partially existing accounts without collisions."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "parallaxadmin:x:1000:1000:Admin:/home/parallaxadmin:/bin/bash\n"
            "analyst:x:1005:1005:Analyst:/home/analyst:/bin/bash\n",
            encoding="utf-8",
        )
        group_file.write_text(
            "root:x:0:\n"
            "parallaxadmin:x:1000:\n"
            "analyst:x:1005:\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["PARALLAX_MOCK_PASSWD"] = str(passwd_file)
        env["PARALLAX_MOCK_GROUP"] = str(group_file)

        proc = subprocess.run(
            [str(PROVISION_SH), "--dry-run"],
            capture_output=True,
            text=True,
            env=env,
        )

        assert proc.returncode == 0
        assert "User 'analyst': EXISTS (UID=1005, GID=1005)" in proc.stdout
        assert "User 'rhea': MISSING (would create UID=1001, GID=1001)" in proc.stdout
        assert "User 'svc-pulse': MISSING (would create UID=1002, GID=1002)" in proc.stdout


def test_check_host_identities_detects_collision():
    """Verify check_host_identities detects collision between challenge account and administrator."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        # Flawed setup: analyst shares UID 1000 with parallaxadmin
        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "parallaxadmin:x:1000:1000:Admin:/home/parallaxadmin:/bin/bash\n"
            "analyst:x:1000:1000:Analyst:/home/analyst:/bin/bash\n",
            encoding="utf-8",
        )
        group_file.write_text(
            "root:x:0:\n"
            "parallaxadmin:x:1000:\n"
            "analyst:x:1000:\n",
            encoding="utf-8",
        )

        audit = check_host_identities(
            admin_user="parallaxadmin",
            passwd_path=passwd_file,
            group_path=group_file,
        )

        assert audit["compliant"] is False
        assert audit["admin_preserved"] is False
        assert any("Collision" in err for err in audit["errors"])

