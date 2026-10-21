#!/usr/bin/env bash
# ==============================================================================
# PARALLAX — Automated System Provisioning Script
# Target: Ubuntu Server 24.04 LTS (Noble Numbat) [aarch64 / x86_64]
#
# Idempotent, safe-to-rerun setup for the PARALLAX investigation appliance.
# Enforces strict separation between safe preparation and scenario activation.
# ==============================================================================

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Ground Truth Identity Definitions (matches src/parallax/system/boundary.py)
ANALYST_USER="analyst"
ANALYST_UID=1000
ANALYST_GID=1000

RHEA_USER="rhea"
RHEA_UID=1001
RHEA_GID=1001

SVC_PULSE_USER="svc-pulse"
SVC_PULSE_UID=1002
SVC_PULSE_GID=1002

ROOT_USER="root"
ROOT_UID=0
ROOT_GID=0

# Security Boundary Paths
HELPER_BIN="/usr/local/bin/pulse-helper"
HELPER_FIXED_BIN="/usr/local/bin/pulse-helper-fixed"
ARCHIVE_DIR="/var/archive/meridian"
PULSE_CONF="/etc/pulse/pulse.conf"
PULSE_LOG_DIR="/var/log/pulse"
AUDIT_LOG_FILE="/var/log/audit/audit.log"
SYSTEMD_SERVICE="/etc/systemd/system/pulse.service"
AUDIT_RULES_FILE="/etc/audit/rules.d/pulse.rules"

# Script root and workspace
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Modes
MODE="prepare" # Default mode: prepare, activate, deactivate, dry-run, test
VERBOSE=0

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

log_dry_run() {
    echo -e "${CYAN}[DRY-RUN]${NC} $*"
}

usage() {
    cat <<EOF
PARALLAX — System Provisioning & Security Configuration Tool

Usage:
  $(basename "$0") [OPTIONS]

Modes:
  --prepare         (Default) Safely configure accounts, directories, dependencies,
                    stage evidence, and compile helpers without activating setuid or services.
  --activate        Activate scenario challenge: enable setuid bit (04750) on helper
                    and start/enable pulse.service. Run only inside isolated guest VM.
  --deactivate      Deactivate scenario challenge: revert helper to 0750 and stop pulse.service.
  --dry-run         Validate host OS, architecture, prerequisites, and configuration
  --validate        without modifying the filesystem or accounts.
  --test            Run complete PARALLAX offline test and verification suite.
  -h, --help        Show this help message.

Options:
  -v, --verbose     Enable verbose diagnostic output.

Examples:
  sudo ./provision.sh --prepare     # Safe base provisioning
  sudo ./provision.sh --activate    # Activate challenge in guest VM
  ./provision.sh --dry-run          # Inspect host readiness safely
EOF
    exit 0
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prepare)
            MODE="prepare"
            shift
            ;;
        --activate)
            MODE="activate"
            shift
            ;;
        --deactivate)
            MODE="deactivate"
            shift
            ;;
        --dry-run|--validate)
            MODE="dry-run"
            shift
            ;;
        --test)
            MODE="test"
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
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

# Check OS and Architecture
check_platform() {
    local os_type arch_type
    os_type="$(uname -s)"
    arch_type="$(uname -m)"

    log_info "Detecting host platform: OS=${os_type}, Arch=${arch_type}"

    if [[ "${os_type}" != "Linux" ]]; then
        if [[ "${MODE}" == "dry-run" || "${MODE}" == "test" ]]; then
            log_warn "Host OS is ${os_type} (expected Linux for live appliance deployment). Dry-run validation will evaluate available components."
        else
            log_error "Live provisioning must be executed on Linux (found: ${os_type})."
            exit 1
        fi
    fi

    if [[ "${arch_type}" != "aarch64" && "${arch_type}" != "arm64" && "${arch_type}" != "x86_64" && "${arch_type}" != "amd64" ]]; then
        log_error "Unsupported architecture: ${arch_type}. PARALLAX targets aarch64 (Apple Silicon UTM) or x86_64 (Windows VirtualBox)."
        exit 1
    fi

    if [[ -f "/etc/os-release" ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        log_info "Distribution: ${PRETTY_NAME:-Linux}"
        if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *"ubuntu"* && "${ID_LIKE:-}" != *"debian"* ]]; then
            log_warn "Distribution '${ID:-unknown}' is not Ubuntu. Provisioning is designed for Ubuntu Server 24.04 LTS."
        fi
    fi
}

# Require root for mutating actions
require_root() {
    if [[ "${MODE}" != "dry-run" && "${MODE}" != "test" ]]; then
        if [[ "$(id -u)" -ne 0 ]]; then
            log_error "Provisioning mode '${MODE}' requires root privileges. Please rerun with sudo."
            exit 1
        fi
    fi
}

# Install necessary packages
install_packages() {
    log_info "Checking and installing required system packages..."
    local pkgs=(
        python3
        python3-pip
        python3-venv
        build-essential
        auditd
        iproute2
        curl
        net-tools
        acl
    )

    if [[ "${MODE}" == "dry-run" ]]; then
        for pkg in "${pkgs[@]}"; do
            if which dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "ok installed"; then
                log_dry_run "Package '${pkg}': INSTALLED"
            else
                log_dry_run "Package '${pkg}': NOT INSTALLED (would install)"
            fi
        done
        return 0
    fi

    if which apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "${pkgs[@]}"
        log_success "System packages installed successfully."
    else
        log_warn "apt-get package manager not found. Assuming prerequisites are managed externally."
    fi
}

# Idempotent user and group configuration
configure_accounts() {
    log_info "Configuring lab user accounts and groups idempotently..."

    local users_and_groups=(
        "${ANALYST_USER}:${ANALYST_UID}:${ANALYST_GID}:PARALLAX Investigator:/home/analyst:/bin/bash"
        "${RHEA_USER}:${RHEA_UID}:${RHEA_GID}:Rhea Sanders:/home/rhea:/bin/bash"
        "${SVC_PULSE_USER}:${SVC_PULSE_UID}:${SVC_PULSE_GID}:PULSE Service Account:/var/log/pulse:/usr/sbin/nologin"
    )

    for entry in "${users_and_groups[@]}"; do
        IFS=":" read -r uname uid gid gecos home shell <<< "${entry}"

        if [[ "${MODE}" == "dry-run" ]]; then
            if getent group "${uname}" >/dev/null 2>&1; then
                local actual_gid
                actual_gid="$(getent group "${uname}" | cut -d: -f3)"
                log_dry_run "Group '${uname}': EXISTS (GID=${actual_gid}, expected=${gid})"
            else
                log_dry_run "Group '${uname}': MISSING (would create GID=${gid})"
            fi

            if id -u "${uname}" >/dev/null 2>&1; then
                local actual_uid actual_user_gid
                actual_uid="$(id -u "${uname}")"
                actual_user_gid="$(id -g "${uname}")"
                log_dry_run "User '${uname}': EXISTS (UID=${actual_uid}, GID=${actual_user_gid})"
            else
                log_dry_run "User '${uname}': MISSING (would create UID=${uid}, GID=${gid})"
            fi
            continue
        fi

        # Ensure group exists with expected GID
        if ! getent group "${uname}" >/dev/null 2>&1; then
            groupadd -g "${gid}" "${uname}" 2>/dev/null || groupadd "${uname}"
            log_success "Created group '${uname}' (GID ${gid})"
        fi

        # Ensure user exists with expected UID/GID
        if ! id -u "${uname}" >/dev/null 2>&1; then
            if [[ "${shell}" == "/usr/sbin/nologin" ]]; then
                useradd -u "${uid}" -g "${gid}" -r -s "${shell}" -d "${home}" -c "${gecos}" "${uname}"
            else
                useradd -u "${uid}" -g "${gid}" -m -s "${shell}" -d "${home}" -c "${gecos}" "${uname}"
                # Set default challenge password for player convenience
                echo "${uname}:${uname}" | chpasswd 2>/dev/null || true
            fi
            log_success "Created user '${uname}' (UID ${uid})"
        fi

        # Ensure analyst login password and shell are configured
        if [[ "${uname}" == "${ANALYST_USER}" ]]; then
            echo "${ANALYST_USER}:${ANALYST_USER}" | chpasswd 2>/dev/null || true
            usermod -U "${ANALYST_USER}" 2>/dev/null || true
            usermod -s /bin/bash "${ANALYST_USER}" 2>/dev/null || true
            log_success "Configured login credentials for '${ANALYST_USER}' (password: ${ANALYST_USER})"
        fi
    done

    # Add analyst to systemd-journal group for offline log examination
    if [[ "${MODE}" != "dry-run" ]]; then
        if getent group "systemd-journal" >/dev/null 2>&1; then
            usermod -a -G systemd-journal "${ANALYST_USER}" 2>/dev/null || true
            log_success "Added '${ANALYST_USER}' to 'systemd-journal' group"
        fi
    else
        log_dry_run "Group membership: '${ANALYST_USER}' -> 'systemd-journal' (would ensure membership)"
    fi
}

# Create required directories with explicit DAC permissions
configure_directories() {
    log_info "Configuring security boundary directories and ownership..."

    local dirs=(
        "/etc/pulse:0755:root:root"
        "/var/archive/meridian:0700:root:root"
        "/var/log/pulse:0750:${SVC_PULSE_USER}:${SVC_PULSE_USER}"
        "/var/log/audit:0750:root:root"
    )

    for item in "${dirs[@]}"; do
        IFS=":" read -r dpath dmode downer dgroup <<< "${item}"

        if [[ "${MODE}" == "dry-run" ]]; then
            if [[ -d "${dpath}" ]]; then
                log_dry_run "Directory '${dpath}': EXISTS (expected mode=${dmode}, owner=${downer}:${dgroup})"
            else
                log_dry_run "Directory '${dpath}': MISSING (would create mode=${dmode}, owner=${downer}:${dgroup})"
            fi
            continue
        fi

        mkdir -p "${dpath}"
        chmod "${dmode}" "${dpath}"
        chown "${downer}:${dgroup}" "${dpath}"
        log_success "Directory '${dpath}' configured (mode ${dmode}, owner ${downer}:${dgroup})"
    done
}

# Install application and CLI
install_application() {
    log_info "Installing PARALLAX application and CLI entrypoints..."

    local install_target="/opt/parallax"

    if [[ "${MODE}" == "dry-run" ]]; then
        log_dry_run "Application installation: source='${REPO_ROOT}', target='${install_target}'"
        log_dry_run "CLI link: /usr/local/bin/parallax -> ${install_target}"
        return 0
    fi

    # Copy or link repository to /opt/parallax if running from external workspace
    if [[ "${REPO_ROOT}" != "${install_target}" ]]; then
        mkdir -p "${install_target}"
        # Copy core files while preserving existing investigator progress if present
        if [[ -f "${install_target}/evidence/derived/.progress.json" ]]; then
            log_info "Preserving existing investigator progress at ${install_target}/evidence/derived/.progress.json"
            cp -n "${install_target}/evidence/derived/.progress.json" /tmp/.progress.json.bak || true
        fi

        # Sync repo files excluding git metadata and ephemeral caches
        tar -C "${REPO_ROOT}" \
            --exclude=".git" \
            --exclude=".pytest_cache" \
            --exclude="__pycache__" \
            --exclude="*.pyc" \
            -cf - . | tar -C "${install_target}" -xf -

        if [[ -f "/tmp/.progress.json.bak" ]]; then
            mv /tmp/.progress.json.bak "${install_target}/evidence/derived/.progress.json"
        fi
    fi

    # Create global CLI wrapper in /usr/local/bin/parallax
    cat <<'WRAPPER' > /usr/local/bin/parallax
#!/usr/bin/env bash
export PYTHONPATH="/opt/parallax/src:${PYTHONPATH:-}"
exec /usr/bin/python3 -m parallax "$@"
WRAPPER
    chmod 0755 /usr/local/bin/parallax
    log_success "Installed global CLI wrapper: /usr/local/bin/parallax"
}

# Stage synthetic evidence and preserve investigator notes
stage_evidence() {
    log_info "Staging synthetic evidence artifacts..."

    local target_evidence="/home/${ANALYST_USER}/evidence"
    local source_evidence="${REPO_ROOT}/evidence"

    if [[ "${MODE}" == "dry-run" ]]; then
        log_dry_run "Evidence staging: source='${source_evidence}', target='${target_evidence}'"
        log_dry_run "Preservation: existing notes/ and derived/ in target will NEVER be overwritten."
        return 0
    fi

    mkdir -p "${target_evidence}"

    # Copy manifests, raw evidence, and documentation
    for subdir in raw manifests; do
        if [[ -d "${source_evidence}/${subdir}" ]]; then
            mkdir -p "${target_evidence}/${subdir}"
            cp -R "${source_evidence}/${subdir}/"* "${target_evidence}/${subdir}/"
        fi
    done

    # Copy top-level evidence documentation
    for doc in README.md INDEX.md; do
        if [[ -f "${source_evidence}/${doc}" ]]; then
            cp "${source_evidence}/${doc}" "${target_evidence}/"
        fi
    done

    # Ensure notes and derived directories exist without overwriting existing investigator data
    mkdir -p "${target_evidence}/notes" "${target_evidence}/derived"

    # Stage live scenario artifacts in system paths
    if [[ -f "${source_evidence}/raw/data/research_vault.tar.gz.enc" ]]; then
        cp "${source_evidence}/raw/data/research_vault.tar.gz.enc" "${ARCHIVE_DIR}/"
        chmod 0600 "${ARCHIVE_DIR}/research_vault.tar.gz.enc"
        chown root:root "${ARCHIVE_DIR}/research_vault.tar.gz.enc"
    fi

    if [[ -f "${source_evidence}/raw/data/diag_ticket" ]]; then
        cp "${source_evidence}/raw/data/diag_ticket" "${ARCHIVE_DIR}/"
        chmod 0600 "${ARCHIVE_DIR}/diag_ticket"
        chown root:root "${ARCHIVE_DIR}/diag_ticket"
    fi

    if [[ -f "${source_evidence}/raw/system/pulse.conf" ]]; then
        cp "${source_evidence}/raw/system/pulse.conf" "${PULSE_CONF}"
        chmod 0644 "${PULSE_CONF}"
        chown root:root "${PULSE_CONF}"
    fi

    # Set appropriate ownership for analyst workspace
    if id -u "${ANALYST_USER}" >/dev/null 2>&1; then
        chown -R "${ANALYST_USER}:${ANALYST_USER}" "${target_evidence}"
    fi

    log_success "Staged synthetic evidence in ${target_evidence} and system paths."
}

# Validate evidence checksums against SHA-256 manifest
validate_evidence_checksums() {
    log_info "Validating evidence checksums against manifest..."

    local python_bin="python3"
    local manifest_dir="${REPO_ROOT}/evidence/manifests"

    if [[ -f "${manifest_dir}/SHA256SUMS" ]]; then
        if [[ "${MODE}" == "dry-run" ]]; then
            log_dry_run "Evidence manifest: ${manifest_dir}/SHA256SUMS present."
        fi

        # Run verification using parallax manifest module
        if PYTHONPATH="${REPO_ROOT}/src" "${python_bin}" -m parallax.manifest verify --root "${REPO_ROOT}/evidence" >/dev/null 2>&1; then
            log_success "All evidence artifacts verified against SHA-256 manifest."
        else
            log_error "Evidence integrity verification failed!"
            return 1
        fi
    fi
}

# Compile pulse-helper in both vulnerable and hardened modes
compile_helpers() {
    log_info "Compiling PULSE/1 maintenance helper binaries..."

    local c_src="${REPO_ROOT}/src/helper/pulse-helper.c"
    if [[ ! -f "${c_src}" ]]; then
        log_error "C source file not found at ${c_src}"
        return 1
    fi

    local cc="gcc"
    if ! which "${cc}" >/dev/null 2>&1; then
        cc="cc"
        if ! which "${cc}" >/dev/null 2>&1; then
            log_warn "No C compiler found in PATH. Helper compilation skipped."
            return 0
        fi
    fi

    if [[ "${MODE}" == "dry-run" ]]; then
        log_dry_run "Compiler: ${cc}"
        log_dry_run "Target 1 (vulnerable): ${HELPER_BIN} (mode 0750 in prepare, 04750 in activate)"
        log_dry_run "Target 2 (hardened):   ${HELPER_FIXED_BIN} (mode 0750)"
        return 0
    fi

    # Build vulnerable mode
    "${cc}" -Wall -Wextra -O2 -std=c99 -o "${HELPER_BIN}" "${c_src}"
    # Build hardened mode
    "${cc}" -Wall -Wextra -O2 -std=c99 -DFIXED_MODE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o "${HELPER_FIXED_BIN}" "${c_src}"

    # Both binaries owned by root:svc-pulse
    chown "root:${SVC_PULSE_USER}" "${HELPER_BIN}" "${HELPER_FIXED_BIN}"

    # Default safe permissions: 0750 (NO setuid bit during safe preparation)
    chmod 0750 "${HELPER_BIN}" "${HELPER_FIXED_BIN}"
    log_success "Compiled helpers: ${HELPER_BIN} and ${HELPER_FIXED_BIN} (safe mode 0750)"
}

# Configure systemd service and auditd rules
configure_service_and_audit() {
    log_info "Configuring systemd service unit and auditd rules..."

    local svc_src="${REPO_ROOT}/src/parallax/system/pulse.service"
    local rules_src="${REPO_ROOT}/src/parallax/system/audit.rules"

    if [[ "${MODE}" == "dry-run" ]]; then
        log_dry_run "Systemd unit: ${svc_src} -> ${SYSTEMD_SERVICE}"
        log_dry_run "Audit rules:  ${rules_src} -> ${AUDIT_RULES_FILE}"
        return 0
    fi

    if [[ -f "${svc_src}" ]]; then
        cp "${svc_src}" "${SYSTEMD_SERVICE}"
        chmod 0644 "${SYSTEMD_SERVICE}"
        chown root:root "${SYSTEMD_SERVICE}"
        if which systemctl >/dev/null 2>&1; then
            systemctl daemon-reload 2>/dev/null || true
            # In prepare mode, service is kept disabled/stopped
            systemctl disable --now pulse.service 2>/dev/null || true
        fi
        log_success "Configured systemd service unit at ${SYSTEMD_SERVICE}"
    fi

    if [[ -f "${rules_src}" ]]; then
        mkdir -p "$(dirname "${AUDIT_RULES_FILE}")"
        cp "${rules_src}" "${AUDIT_RULES_FILE}"
        chmod 0640 "${AUDIT_RULES_FILE}"
        chown root:root "${AUDIT_RULES_FILE}"
        log_success "Configured audit rules at ${AUDIT_RULES_FILE}"
    fi
}

# Activate scenario challenge (opt-in explicit activation)
activate_challenge() {
    log_info "ACTIVATING scenario challenge (isolated guest deployment only)..."

    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "Challenge activation can only be executed on a dedicated Linux guest VM."
        exit 1
    fi

    if [[ ! -f "${HELPER_BIN}" ]]; then
        log_error "Helper binary ${HELPER_BIN} not found. Run --prepare first."
        exit 1
    fi

    # Set setuid-root bit on helper for svc-pulse group (4750)
    chmod 4750 "${HELPER_BIN}"
    chown "root:${SVC_PULSE_USER}" "${HELPER_BIN}"
    log_success "Setuid-root bit enabled on ${HELPER_BIN} (mode 04750, root:${SVC_PULSE_USER})"

    # Start and enable pulse systemd service
    if which systemctl >/dev/null 2>&1; then
        systemctl enable --now pulse.service 2>/dev/null || true
        log_success "Started and enabled pulse.service"
    fi

    # Load audit rules if auditctl available
    if which augenrules >/dev/null 2>&1; then
        augenrules --load 2>/dev/null || true
        log_success "Loaded audit rules with augenrules"
    elif which auditctl >/dev/null 2>&1; then
        auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || true
        log_success "Loaded audit rules with auditctl"
    fi

    log_success "PARALLAX challenge ACTIVATED. Investigator account '${ANALYST_USER}' ready."
}

# Deactivate scenario challenge (revert to safe state)
deactivate_challenge() {
    log_info "Deactivating scenario challenge..."

    # Revert helper to non-setuid
    if [[ -f "${HELPER_BIN}" ]]; then
        chmod 0750 "${HELPER_BIN}"
        log_success "Reverted ${HELPER_BIN} to non-setuid mode (0750)"
    fi

    # Stop and disable pulse systemd service
    if which systemctl >/dev/null 2>&1; then
        systemctl disable --now pulse.service 2>/dev/null || true
        log_success "Stopped and disabled pulse.service"
    fi

    log_success "PARALLAX challenge DEACTIVATED."
}

# Run test suite
run_tests() {
    log_info "Running PARALLAX test suite and verification..."
    cd "${REPO_ROOT}"
    PYTHONPATH="${REPO_ROOT}/src" python3 -m parallax.verify
    PYTHONPATH="${REPO_ROOT}/src" python3 -m pytest -v
}

# Main execution dispatcher
main() {
    echo "======================================================================"
    echo " PARALLAX Investigation Appliance — Provisioning & Control"
    echo " Mode: ${MODE}"
    echo "======================================================================"

    check_platform

    case "${MODE}" in
        dry-run)
            log_info "Executing dry-run validation (no filesystem mutations)..."
            install_packages
            configure_accounts
            configure_directories
            install_application
            stage_evidence
            validate_evidence_checksums
            compile_helpers
            configure_service_and_audit
            log_success "Dry-run validation complete. System is ready for provisioning."
            ;;
        prepare)
            require_root
            install_packages
            configure_accounts
            configure_directories
            install_application
            stage_evidence
            validate_evidence_checksums
            compile_helpers
            configure_service_and_audit
            echo ""
            log_success "Safe preparation complete!"
            log_info "Helper is compiled in safe mode 0750 (setuid NOT active)."
            log_info "To activate challenge in dedicated VM: sudo $(basename "$0") --activate"
            ;;
        activate)
            require_root
            activate_challenge
            ;;
        deactivate)
            require_root
            deactivate_challenge
            ;;
        test)
            run_tests
            ;;
    esac
}

main "$@"
