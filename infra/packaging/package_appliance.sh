#!/usr/bin/env bash
# ==============================================================================
# PARALLAX — Appliance Packaging Script
# Targets:
#   - UTM on Apple Silicon (Ubuntu Server 24.04 ARM64)
#   - Oracle VirtualBox on Windows (Ubuntu Server 24.04 x86-64)
#
# Sanitizes build directories, packages distribution bundles, and generates
# SHA-256 release checksums.
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

usage() {
    cat <<EOF
PARALLAX — Investigation Appliance Packaging Tool

Usage:
  $(basename "$0") [OPTIONS]

Options:
  --target <target>       Packaging target: 'utm', 'virtualbox', or 'both' (default: both).
  --output-dir <path>     Directory to save release artifacts (default: ${OUTPUT_DIR}).
  --no-clean              Skip cleaning Python bytecode and test caches before packaging.
  --skip-manifest-check   Skip SHA-256 manifest validation before packaging.
  -h, --help              Show this help message.

Examples:
  ./package_appliance.sh --target utm
  ./package_appliance.sh --target virtualbox
  ./package_appliance.sh --output-dir ./releases
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

    local utm_bundle_name="PARALLAX-Ubuntu-24.04-ARM64.utm"
    local utm_staging="${OUTPUT_DIR}/${utm_bundle_name}"
    local utm_zip="${OUTPUT_DIR}/${utm_bundle_name}.zip"

    rm -rf "${utm_staging}" "${utm_zip}"
    mkdir -p "${utm_staging}/Data"

    # Copy UTM configuration
    cp "${REPO_ROOT}/infra/vm/utm/config.plist" "${utm_staging}/config.plist"

    # Include appliance README and player quickstart
    cat <<'README_UTM' > "${utm_staging}/README.txt"
PARALLAX — The Evidence Is Lying
Target: UTM on Apple Silicon (Ubuntu Server 24.04 LTS ARM64)

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

    # Compress the bundle into a distributable zip archive
    (cd "${OUTPUT_DIR}" && zip -q -r "$(basename "${utm_zip}")" "${utm_bundle_name}")
    log_success "Created UTM appliance bundle: ${utm_zip}"
}

# Package VirtualBox appliance for Windows x86-64
package_virtualbox() {
    log_info "Packaging Target B: VirtualBox on Windows (x86-64)..."

    local vbox_name="PARALLAX-Ubuntu-24.04-x86_64"
    local vbox_staging="${OUTPUT_DIR}/${vbox_name}"
    local vbox_ova="${OUTPUT_DIR}/${vbox_name}.ova"

    rm -rf "${vbox_staging}" "${vbox_ova}"
    mkdir -p "${vbox_staging}"

    # Copy OVF descriptor
    cp "${REPO_ROOT}/infra/vm/virtualbox/parallax-investigation.ovf" "${vbox_staging}/${vbox_name}.ovf"

    # Include appliance README and player quickstart
    cat <<'README_VBOX' > "${vbox_staging}/README.txt"
PARALLAX — The Evidence Is Lying
Target: Oracle VirtualBox on Windows PC (Ubuntu Server 24.04 LTS x86-64)

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

    # Create OVA tar archive (in OVF standard order: OVF first, then manifest)
    (cd "${vbox_staging}" && tar -cf "${vbox_ova}" "${vbox_name}.ovf" "README.txt")
    log_success "Created VirtualBox appliance: ${vbox_ova}"
}

# Generate release SHA-256 checksums
generate_checksums() {
    log_info "Generating release SHA-256 checksums..."
    local checksum_file="${OUTPUT_DIR}/RELEASE_SHA256SUMS"
    rm -f "${checksum_file}"

    (cd "${OUTPUT_DIR}" && find . -maxdepth 1 -type f ! -name "RELEASE_SHA256SUMS" -print0 | sort -z | while IFS= read -r -d '' file; do
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
