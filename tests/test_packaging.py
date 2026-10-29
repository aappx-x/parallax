"""Tests for appliance packaging scripts, UTM configurations, and VirtualBox OVF specifications."""

from __future__ import annotations

import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_SH = REPO_ROOT / "infra" / "packaging" / "package_appliance.sh"
UTM_PLIST = REPO_ROOT / "infra" / "vm" / "utm" / "config.plist"
VBOX_OVF = REPO_ROOT / "infra" / "vm" / "virtualbox" / "parallax-investigation.ovf"


def test_package_script_exists_and_executable():
    assert PACKAGE_SH.is_file(), f"package_appliance.sh not found at {PACKAGE_SH}"
    assert os.access(PACKAGE_SH, os.X_OK), "package_appliance.sh must be executable (+x)"


def test_package_script_bash_syntax():
    """Verify package_appliance.sh passes bash syntax checking."""
    proc = subprocess.run(["bash", "-n", str(PACKAGE_SH)], capture_output=True, text=True)
    assert proc.returncode == 0, f"bash -n failed on package_appliance.sh: {proc.stderr}"


def test_package_script_help():
    """Verify package_appliance.sh --help displays usage information."""
    proc = subprocess.run([str(PACKAGE_SH), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "--target" in proc.stdout
    assert "--output-dir" in proc.stdout


def test_utm_config_plist_structure():
    """Verify UTM config.plist is valid XML property list with expected ARM64 settings."""
    assert UTM_PLIST.is_file(), f"UTM config.plist missing at {UTM_PLIST}"
    content = UTM_PLIST.read_bytes()
    data = plistlib.loads(content)

    assert data.get("Backend") == "QEMU"
    assert "System" in data
    assert data["System"].get("Architecture") == "aarch64"
    assert data["System"].get("Memory", 0) >= 4096
    assert data["System"].get("UefiBoot") is True

    # Network configuration
    networks = data.get("Network", [])
    assert len(networks) > 0
    assert networks[0].get("Hardware") == "virtio-net-pci"
    assert networks[0].get("Mode") == "Shared"


def test_virtualbox_ovf_descriptor_structure():
    """Verify VirtualBox OVF descriptor contains standard OVF envelope and hardware items."""
    assert VBOX_OVF.is_file(), f"VirtualBox OVF descriptor missing at {VBOX_OVF}"

    tree = ET.parse(VBOX_OVF)
    root = tree.getroot()

    # Verify OVF envelope namespace
    assert "Envelope" in root.tag
    assert "http://schemas.dmtf.org/ovf/envelope/1" in root.tag

    # Verify Operating System section specifies Ubuntu_64
    ns = {
        "ovf": "http://schemas.dmtf.org/ovf/envelope/1",
        "rasd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData",
    }
    os_desc = root.find(".//ovf:OperatingSystemSection/ovf:Description", ns)
    assert os_desc is not None
    assert "Ubuntu_64" in (os_desc.text or "")

    # Verify virtual hardware section contains CPU and Memory
    items = root.findall(".//ovf:VirtualHardwareSection/ovf:Item", ns)
    resource_types = [item.find("rasd:ResourceType", ns) for item in items]
    resource_type_values = [r.text for r in resource_types if r is not None]

    assert "3" in resource_type_values  # CPU
    assert "4" in resource_type_values  # Memory
    assert "20" in resource_type_values or "5" in resource_type_values  # Disk controller (SATA / IDE)
    assert "17" in resource_type_values  # Hard disk
    assert "10" in resource_type_values  # Ethernet adapter


def test_packaging_template_mode():
    """Verify packaging script produces configuration templates when virtual disks are omitted."""
    import tarfile
    import zipfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        proc = subprocess.run(
            [str(PACKAGE_SH), "--target", "both", "--output-dir", tmp_dir],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"Template packaging failed:\n{proc.stderr}\n{proc.stdout}"

        utm_archive = Path(tmp_dir) / "PARALLAX-Ubuntu-24.04-ARM64-config.utm.zip"
        vbox_archive = Path(tmp_dir) / "PARALLAX-Ubuntu-24.04-x86_64-ovf-template.tar.gz"
        maintainer_guide = Path(tmp_dir) / "MAINTAINER_GUIDE.md"
        checksum_file = Path(tmp_dir) / "RELEASE_SHA256SUMS"

        assert utm_archive.is_file(), "UTM template archive missing"
        assert utm_archive.stat().st_size > 0

        assert vbox_archive.is_file(), "VirtualBox OVF template archive missing"
        assert vbox_archive.stat().st_size > 0

        # Maintainer documentation must be placed separately
        assert maintainer_guide.is_file(), "MAINTAINER_GUIDE.md missing from output"

        # Verify player documentation is included inside archives
        with zipfile.ZipFile(utm_archive) as zf:
            zip_names = zf.namelist()
            assert any("PLAYER_GUIDE.md" in n for n in zip_names), "PLAYER_GUIDE.md missing from UTM archive"
            assert any("README.txt" in n for n in zip_names), "README.txt missing from UTM archive"

        with tarfile.open(vbox_archive, "r:gz") as tf:
            tar_names = tf.getnames()
            assert any("PLAYER_GUIDE.md" in n for n in tar_names), "PLAYER_GUIDE.md missing from VBox template"
            assert any("README.txt" in n for n in tar_names), "README.txt missing from VBox template"

        assert checksum_file.is_file(), "RELEASE_SHA256SUMS file missing"
        checksum_text = checksum_file.read_text(encoding="utf-8")

        assert "PARALLAX-Ubuntu-24.04-ARM64-config.utm.zip" in checksum_text
        assert "PARALLAX-Ubuntu-24.04-x86_64-ovf-template.tar.gz" in checksum_text


def test_packaging_full_appliance_with_disks():
    """Verify packaging script produces complete bootable appliances when virtual disks are provided."""
    import zipfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fake_arm64_disk = tmp_path / "ubuntu-arm64.qcow2"
        fake_x86_disk = tmp_path / "ubuntu-x86.vmdk"
        fake_arm64_disk.write_bytes(b"mock_qcow2_content_for_test")
        fake_x86_disk.write_bytes(b"mock_vmdk_content_for_test")

        out_dir = tmp_path / "out"
        proc = subprocess.run(
            [
                str(PACKAGE_SH),
                "--target", "both",
                "--output-dir", str(out_dir),
                "--disk-arm64", str(fake_arm64_disk),
                "--disk-x86_64", str(fake_x86_disk),
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"Full packaging failed:\n{proc.stderr}\n{proc.stdout}"

        utm_appliance = out_dir / "PARALLAX-Ubuntu-24.04-ARM64.utm.zip"
        vbox_appliance = out_dir / "PARALLAX-Ubuntu-24.04-x86_64.ova"
        maintainer_guide = out_dir / "MAINTAINER_GUIDE.md"
        checksum_file = out_dir / "RELEASE_SHA256SUMS"

        assert utm_appliance.is_file(), "UTM complete appliance missing"
        assert vbox_appliance.is_file(), "VirtualBox complete appliance missing"
        assert maintainer_guide.is_file(), "Separate MAINTAINER_GUIDE.md missing from output"

        # Check UTM archive contains disk and documentation
        with zipfile.ZipFile(utm_appliance) as zf:
            names = zf.namelist()
            assert "PARALLAX-Ubuntu-24.04-ARM64.utm/Data/disk-arm64.qcow2" in names
            assert any("PLAYER_GUIDE.md" in n for n in names)
            assert any("README.txt" in n for n in names)

        # Check OVA archive contains the VMDK and .mf manifest
        proc_tar = subprocess.run(["tar", "-tf", str(vbox_appliance)], capture_output=True, text=True)
        assert proc_tar.returncode == 0
        assert "parallax-disk-x86_64.vmdk" in proc_tar.stdout
        assert "PARALLAX-Ubuntu-24.04-x86_64.mf" in proc_tar.stdout


def test_packaging_with_efi_vars():
    """Verify --efi-vars embeds efi_vars.fd into the UTM bundle Data directory."""
    import zipfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fake_arm64_disk = tmp_path / "ubuntu-arm64.qcow2"
        fake_efi_vars = tmp_path / "efi_vars.fd"
        fake_arm64_disk.write_bytes(b"mock_disk")
        fake_efi_vars.write_bytes(b"mock_efi_vars")

        out_dir = tmp_path / "out"
        proc = subprocess.run(
            [
                str(PACKAGE_SH),
                "--target", "utm",
                "--output-dir", str(out_dir),
                "--disk-arm64", str(fake_arm64_disk),
                "--efi-vars", str(fake_efi_vars),
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        utm_appliance = out_dir / "PARALLAX-Ubuntu-24.04-ARM64.utm.zip"
        assert utm_appliance.is_file()

        with zipfile.ZipFile(utm_appliance) as zf:
            assert "PARALLAX-Ubuntu-24.04-ARM64.utm/Data/efi_vars.fd" in zf.namelist()


def test_packaging_require_disks_flag():
    """Verify --require-disks aborts with error if disk paths are missing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        proc = subprocess.run(
            [str(PACKAGE_SH), "--target", "both", "--output-dir", tmp_dir, "--require-disks"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0
        assert "Missing required" in proc.stderr


def test_packaging_zip_python_fallback():
    """Verify package_appliance.sh falls back to python3 -m zipfile when zip binary is unavailable."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()

        real_which = shutil.which("which") or "/usr/bin/which"
        mock_which = fake_bin / "which"
        mock_which.write_text(
            f"#!/bin/bash\n"
            f"if [ \"$1\" = \"zip\" ]; then\n"
            f"    exit 1\n"
            f"fi\n"
            f"exec {real_which} \"$@\"\n"
        )
        mock_which.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"

        out_dir = tmp_path / "out"
        proc = subprocess.run(
            [str(PACKAGE_SH), "--target", "utm", "--output-dir", str(out_dir)],
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode == 0, f"Fallback packaging failed:\n{proc.stderr}\n{proc.stdout}"

        utm_archive = out_dir / "PARALLAX-Ubuntu-24.04-ARM64-config.utm.zip"
        assert utm_archive.is_file(), "UTM archive was not created via python3 zipfile fallback"
        assert utm_archive.stat().st_size > 0
        assert "using 'python3 -m zipfile'" in proc.stdout


def test_packaging_checksums_match():
    """Verify that RELEASE_SHA256SUMS accurately reflects generated archive checksums."""
    import hashlib

    with tempfile.TemporaryDirectory() as tmp_dir:
        proc = subprocess.run(
            [str(PACKAGE_SH), "--target", "both", "--output-dir", tmp_dir],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0

        checksum_file = Path(tmp_dir) / "RELEASE_SHA256SUMS"
        assert checksum_file.is_file()

        lines = [line.strip() for line in checksum_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert len(lines) >= 2

        for line in lines:
            expected_hash, filename = line.split("  ", 1)
            target_file = Path(tmp_dir) / filename
            assert target_file.is_file(), f"Checksum referenced missing file: {filename}"
            actual_hash = hashlib.sha256(target_file.read_bytes()).hexdigest()
            assert actual_hash == expected_hash, f"Hash mismatch for {filename}: expected {expected_hash}, got {actual_hash}"


def test_packaging_missing_prerequisite_tool_or_file():
    """Verify packaging script detects missing required repository files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a fake repo root without config.plist
        fake_repo = Path(tmp_dir) / "parallax"
        fake_repo.mkdir()
        fake_infra = fake_repo / "infra" / "packaging"
        fake_infra.mkdir(parents=True)
        shutil.copy(PACKAGE_SH, fake_infra / "package_appliance.sh")

        proc = subprocess.run(
            ["bash", str(fake_infra / "package_appliance.sh"), "--output-dir", str(fake_repo / "dist")],
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0
        assert "Missing required repository file" in proc.stderr


