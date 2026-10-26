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
    with tempfile.TemporaryDirectory() as tmp_dir:
        proc = subprocess.run(
            [str(PACKAGE_SH), "--target", "both", "--output-dir", tmp_dir],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"Template packaging failed:\n{proc.stderr}\n{proc.stdout}"

        utm_archive = Path(tmp_dir) / "PARALLAX-Ubuntu-24.04-ARM64-config.utm.zip"
        vbox_archive = Path(tmp_dir) / "PARALLAX-Ubuntu-24.04-x86_64-ovf-template.tar.gz"
        checksum_file = Path(tmp_dir) / "RELEASE_SHA256SUMS"

        assert utm_archive.is_file(), "UTM template archive missing"
        assert utm_archive.stat().st_size > 0

        assert vbox_archive.is_file(), "VirtualBox OVF template archive missing"
        assert vbox_archive.stat().st_size > 0

        assert checksum_file.is_file(), "RELEASE_SHA256SUMS file missing"
        checksum_text = checksum_file.read_text(encoding="utf-8")

        assert "PARALLAX-Ubuntu-24.04-ARM64-config.utm.zip" in checksum_text
        assert "PARALLAX-Ubuntu-24.04-x86_64-ovf-template.tar.gz" in checksum_text


def test_packaging_full_appliance_with_disks():
    """Verify packaging script produces complete bootable appliances when virtual disks are provided."""
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
        checksum_file = out_dir / "RELEASE_SHA256SUMS"

        assert utm_appliance.is_file(), "UTM complete appliance missing"
        assert vbox_appliance.is_file(), "VirtualBox complete appliance missing"

        # Check OVA archive contains the VMDK and .mf manifest
        proc_tar = subprocess.run(["tar", "-tf", str(vbox_appliance)], capture_output=True, text=True)
        assert proc_tar.returncode == 0
        assert "parallax-disk-x86_64.vmdk" in proc_tar.stdout
        assert "PARALLAX-Ubuntu-24.04-x86_64.mf" in proc_tar.stdout


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

