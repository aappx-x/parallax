#!/usr/bin/env bash
# ==============================================================================
# PARALLAX — Appliance Packaging Script
# Targets:
#   - UTM on Apple Silicon (Ubuntu Server 24.04 ARM64)
#   - Oracle VirtualBox on Windows (Ubuntu Server 24.04 x86-64)
#
# Sanitizes build directories, packages distribution bundles or configuration
# templates, and generates SHA-256 release checksums.
# ==============================================================================

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/dist"

TARGET="both" # utm, virtualbox, both
DO_CLEAN=1
VALIDATE_MANIFEST=1
REQUIRE_DISKS=0

DISK_ARM64=""
DISK_X86_64=""

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_notice() {
    echo -e "${CYAN}[NOTICE]${NC} $*"
}

usage() {
    cat <<EOF
PARALLAX — Investigation Appliance Packaging Tool

Usage:
  $(basename "$0") [OPTIONS]

Options:
  --target <target>       Packaging target: 'utm', 'virtualbox', or 'both' (default: both).
  --output-dir <path>     Directory to save release artifacts (default: ${OUTPUT_DIR}).
  --disk-arm64 <path>     Path to bootable Ubuntu ARM64 QCOW2 virtual disk.
  --disk-x86_64 <path>    Path to bootable Ubuntu x86-64 VMDK virtual disk.
  --require-disks         Fail if virtual disks are not provided (do not produce templates).
  --no-clean              Skip cleaning Python bytecode and test caches before packaging.
  --skip-manifest-check   Skip SHA-256 manifest validation before packaging.
  -h, --help              Show this help message.

Examples:
  ./package_appliance.sh --target utm
  ./package_appliance.sh --target both --disk-arm64 /path/to/arm64.qcow2
  ./package_appliance.sh --require-disks --disk-arm64 disk.qcow2 --disk-x86_64 disk.vmdk
EOF
    exit 0
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --disk-arm64)
            DISK_ARM64="$2"
            shift 2
            ;;
        --disk-x86_64)
            DISK_X86_64="$2"
            shift 2
            ;;
        --require-disks)
            REQUIRE_DISKS=1
            shift
            ;;
        --no-clean)
            DO_CLEAN=0
            shift
            ;;
        --skip-manifest-check)
            VALIDATE_MANIFEST=0
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ "${TARGET}" != "utm" && "${TARGET}" != "virtualbox" && "${TARGET}" != "both" ]]; then
    log_error "Invalid target '${TARGET}'. Must be 'utm', 'virtualbox', or 'both'."
    exit 1
fi

# Clean ephemeral caches and temporary files
clean_caches() {
    log_info "Sanitizing repository workspace..."
    find "${REPO_ROOT}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "${REPO_ROOT}" -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
    find "${REPO_ROOT}" -type f -name "*.pyc" -delete 2>/dev/null || true
    find "${REPO_ROOT}" -type f -name ".DS_Store" -delete 2>/dev/null || true
    log_success "Workspace sanitized (removed caches, pyc, and DS_Store)."
}

# Verify evidence manifest prior to packaging
verify_manifest() {
    log_info "Verifying evidence integrity against SHA-256 manifest..."
    if ! PYTHONPATH="${REPO_ROOT}/src" python3 -m parallax.manifest verify --root "${REPO_ROOT}/evidence" >/dev/null 2>&1; then
        log_error "Evidence integrity verification failed. Aborting packaging."
        exit 1
    fi
    log_success "Evidence integrity verified."
}

# Package UTM bundle for Apple Silicon
package_utm() {
    log_info "Packaging Target A: UTM on Apple Silicon (ARM64)..."

    local has_disk=0
    if [[ -n "${DISK_ARM64}" ]]; then
        if [[ ! -f "${DISK_ARM64}" ]]; then
            log_error "Specified ARM64 disk image does not exist: ${DISK_ARM64}"
            exit 1
        fi
        has_disk=1
    elif [[ "${REQUIRE_DISKS}" -eq 1 ]]; then
        log_error "Missing required ARM64 disk image (--disk-arm64) under --require-disks"
        exit 1
    fi

    local bundle_name
    local zip_name
    if [[ "${has_disk}" -eq 1 ]]; then
        bundle_name="PARALLAX-Ubuntu-24.04-ARM64.utm"
        zip_name="PARALLAX-Ubuntu-24.04-ARM64.utm.zip"
    else
        bundle_name="PARALLAX-Ubuntu-24.04-ARM64-config.utm"
        zip_name="PARALLAX-Ubuntu-24.04-ARM64-config.utm.zip"
    fi

    local utm_staging="${OUTPUT_DIR}/${bundle_name}"
    local utm_zip="${OUTPUT_DIR}/${zip_name}"

    rm -rf "${utm_staging}" "${utm_zip}"
    mkdir -p "${utm_staging}/Data"

    # Copy UTM hardware configuration
    cp "${REPO_ROOT}/infra/vm/utm/config.plist" "${utm_staging}/config.plist"

    if [[ "${has_disk}" -eq 1 ]]; then
        log_info "Embedding bootable disk image into UTM bundle: ${DISK_ARM64}"
        cp "${DISK_ARM64}" "${utm_staging}/Data/disk-arm64.qcow2"

        cat <<'README_UTM' > "${utm_staging}/README.txt"
PARALLAX — The Evidence Is Lying
Target: UTM on Apple Silicon (Ubuntu Server 24.04 LTS ARM64)
Package: Complete Bootable Virtual Appliance

Quick Start:
1. Drag and drop this 'PARALLAX-Ubuntu-24.04-ARM64.utm' bundle into UTM.
2. Select the VM and click the Play icon to boot.
3. Log in with:
   Username: analyst
   Password: analyst
4. Enter the investigation workspace:
   cd ~/parallax
   parallax status
   parallax inspect P01
README_UTM
    else
        log_notice "No ARM64 disk provided. Packaging VM configuration template only."
        cat <<'README_UTM_TPL' > "${utm_staging}/README.txt"
PARALLAX — The Evidence Is Lying
Target: UTM on Apple Silicon (Ubuntu Server 24.04 LTS ARM64)
Package: VM Hardware Configuration Template (Disk Not Included)

Notice:
This package contains the verified UTM hardware profile, UEFI settings, and network topology.
To assemble a complete bootable appliance:
1. Install Ubuntu Server 24.04 LTS ARM64.
2. Run provision.sh --prepare inside the guest.
3. Package using:
   ./infra/packaging/package_appliance.sh --disk-arm64 /path/to/disk-arm64.qcow2
README_UTM_TPL
    fi

    (cd "${OUTPUT_DIR}" && zip -q -r "$(basename "${utm_zip}")" "${bundle_name}")
    log_success "Created UTM release artifact: ${utm_zip}"
}

# Package VirtualBox appliance for Windows x86-64
package_virtualbox() {
    log_info "Packaging Target B: VirtualBox on Windows (x86-64)..."

    local has_disk=0
    if [[ -n "${DISK_X86_64}" ]]; then
        if [[ ! -f "${DISK_X86_64}" ]]; then
            log_error "Specified x86-64 disk image does not exist: ${DISK_X86_64}"
            exit 1
        fi
        has_disk=1
    elif [[ "${REQUIRE_DISKS}" -eq 1 ]]; then
        log_error "Missing required x86-64 disk image (--disk-x86_64) under --require-disks"
        exit 1
    fi

    local vbox_name="PARALLAX-Ubuntu-24.04-x86_64"

    if [[ "${has_disk}" -eq 1 ]]; then
        local vbox_staging="${OUTPUT_DIR}/${vbox_name}"
        local vbox_ova="${OUTPUT_DIR}/${vbox_name}.ova"

        rm -rf "${vbox_staging}" "${vbox_ova}"
        mkdir -p "${vbox_staging}"

        cp "${REPO_ROOT}/infra/vm/virtualbox/parallax-investigation.ovf" "${vbox_staging}/${vbox_name}.ovf"
        cp "${DISK_X86_64}" "${vbox_staging}/parallax-disk-x86_64.vmdk"

        # Generate standard OVF manifest (.mf)
        local ovf_sha vmdk_sha
        ovf_sha="$(shasum -a 256 "${vbox_staging}/${vbox_name}.ovf" | awk '{print $1}')"
        vmdk_sha="$(shasum -a 256 "${vbox_staging}/parallax-disk-x86_64.vmdk" | awk '{print $1}')"

        cat <<EOF > "${vbox_staging}/${vbox_name}.mf"
SHA256(${vbox_name}.ovf)= ${ovf_sha}
SHA256(parallax-disk-x86_64.vmdk)= ${vmdk_sha}
EOF

        cat <<'README_VBOX' > "${vbox_staging}/README.txt"
PARALLAX — The Evidence Is Lying
Target: Oracle VirtualBox on Windows PC (Ubuntu Server 24.04 LTS x86-64)
Package: Complete Bootable OVA Appliance

Quick Start:
1. Open Oracle VirtualBox 7.x on Windows.
2. Select File -> Import Appliance...
3. Select this OVA file and click Finish.
4. Start the VM.
5. Log in with:
   Username: analyst
   Password: analyst
6. Enter the investigation workspace:
   cd ~/parallax
   parallax status
   parallax inspect P01
README_VBOX

        # Create standard OVA tar archive in canonical order: .ovf, disk, .mf
        (cd "${vbox_staging}" && tar -cf "${vbox_ova}" "${vbox_name}.ovf" "parallax-disk-x86_64.vmdk" "${vbox_name}.mf" "README.txt")
        log_success "Created complete VirtualBox OVA appliance: ${vbox_ova}"
    else
        log_notice "No x86-64 VMDK disk provided. Packaging OVF specification template only."

        local tpl_staging="${OUTPUT_DIR}/${vbox_name}-ovf-template"
        local tpl_archive="${OUTPUT_DIR}/${vbox_name}-ovf-template.tar.gz"

        rm -rf "${tpl_staging}" "${tpl_archive}"
        mkdir -p "${tpl_staging}"

        cp "${REPO_ROOT}/infra/vm/virtualbox/parallax-investigation.ovf" "${tpl_staging}/${vbox_name}.ovf"

        cat <<'README_VBOX_TPL' > "${tpl_staging}/README.txt"
PARALLAX — The Evidence Is Lying
Target: Oracle VirtualBox on Windows PC (Ubuntu Server 24.04 LTS x86-64)
Package: OVF Specification Template (Disk Not Included)

Notice:
This archive contains the validated OVF 1.0 virtual appliance descriptor.
Because an OVA without its referenced disk (parallax-disk-x86_64.vmdk) is invalid and cannot be imported by VirtualBox, the specification is packaged as a standalone template.

To assemble the complete bootable .ova appliance:
1. Provision Ubuntu Server 24.04 LTS x86-64.
2. Export the virtual disk to VMDK format.
3. Package using:
   ./infra/packaging/package_appliance.sh --disk-x86_64 /path/to/parallax-disk-x86_64.vmdk
README_VBOX_TPL

        (cd "${OUTPUT_DIR}" && tar -czf "$(basename "${tpl_archive}")" "$(basename "${tpl_staging}")")
        log_success "Created VirtualBox OVF template: ${tpl_archive}"
    fi
}

# Generate release SHA-256 checksums
generate_checksums() {
    log_info "Generating release SHA-256 checksums..."
    local checksum_file="${OUTPUT_DIR}/RELEASE_SHA256SUMS"
    rm -f "${checksum_file}"

    (cd "${OUTPUT_DIR}" && find . -maxdepth 1 -type f \( -name "*.zip" -o -name "*.ova" -o -name "*.tar.gz" \) -print0 | sort -z | while IFS= read -r -d '' file; do
        shasum -a 256 "${file}" | sed 's|^\([0-9a-f]*\)  \./|\1  |'
    done > "${checksum_file}")

    log_success "Generated release checksums in ${checksum_file}:"
    cat "${checksum_file}"
}

main() {
    echo "======================================================================"
    echo " PARALLAX Investigation Appliance — Packaging Pipeline"
    echo " Target: ${TARGET}"
    echo " Output: ${OUTPUT_DIR}"
    echo "======================================================================"

    mkdir -p "${OUTPUT_DIR}"

    if [[ "${DO_CLEAN}" -eq 1 ]]; then
        clean_caches
    fi

    if [[ "${VALIDATE_MANIFEST}" -eq 1 ]]; then
        verify_manifest
    fi

    if [[ "${TARGET}" == "utm" || "${TARGET}" == "both" ]]; then
        package_utm
    fi

    if [[ "${TARGET}" == "virtualbox" || "${TARGET}" == "both" ]]; then
        package_virtualbox
    fi

    generate_checksums

    echo "======================================================================"
    log_success "Appliance packaging pipeline completed successfully."
    echo "======================================================================"
}

main "$@"
