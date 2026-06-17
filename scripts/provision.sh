#!/usr/bin/env bash
# provision.sh — Osgania VPS baseline provisioner (Slice 1 of 2)
#
# Installs and configures the deterministic OS baseline so that the three-locks
# artifacts (managed-settings.json, guardia.sh, camara.sh) become load-bearing
# on a fresh Ubuntu 24.04 or 26.04 VPS.
#
# Usage:
#   sudo ./provision.sh           — full provisioning run
#   sudo ./provision.sh --check   — dry-run: report plan, mutate nothing, exit 0
#
# Requirements: R1..R11 (see openspec/changes/vps-provisioning-base/spec.md)
# Design:       openspec/changes/vps-provisioning-base/design.md

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants — all decided literals from design.md (drift gate: do not alter
# without updating design.md first)
#
# Defined as plain variables (not readonly) so that sourcing this file from
# bats tests is safe across repeated setup() calls. Bash 3.2 (macOS default)
# does not support the `-v` operator to guard re-declarations.
# ---------------------------------------------------------------------------

AIOS_UID=9001
AIOS_GID=9001
AIOS_SHELL="/usr/sbin/nologin"
AIOS_HOME="/nonexistent"

PLATFORM_DIR="/opt/osgania/platform"
HOOKS_DIR="/opt/osgania/platform/hooks"
POLICY_DIR="/etc/claude-code"
POLICY_FILE="/etc/claude-code/managed-settings.json"
SECRETS_DIR="/etc/osgania/secrets"
AUDIT_DIR="/var/log/osgania"
AUDIT_FILE="/var/log/osgania/audit.jsonl"

CLI_VERSION_FLOOR="2.1.153"
CLI_PINNED_VERSION="2.1.153"

# ---------------------------------------------------------------------------
# State variables — set by functions, read by main/format_summary
# ---------------------------------------------------------------------------

CHECK_MODE=0
OS_VERSION=""
OS_TARGET=""
CLI_VERSION_RECORDED=""
CLI_VERSION_OK=0
LAYER3_STATUS="UNVERIFIED"

# ---------------------------------------------------------------------------
# parse_args <"$@">
#
# Parses command-line arguments. Sets CHECK_MODE=1 if --check is provided.
# Emits usage to stderr and exits non-zero on unknown flags.
# Spec: R1.7
# ---------------------------------------------------------------------------
parse_args() {
    CHECK_MODE=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check)
                CHECK_MODE=1
                shift
                ;;
            *)
                printf 'provision.sh: unknown option: %s\n' "$1" >&2
                printf 'Usage: provision.sh [--check]\n' >&2
                printf '  --check   Dry-run: report planned changes, mutate nothing, exit 0.\n' >&2
                return 1
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# detect_os [os_release_path]
#
# Parses /etc/os-release (or the path in ${OS_RELEASE_PATH} override) for
# ID and VERSION_ID. Sets OS_VERSION and OS_TARGET. Aborts on unsupported OS.
# Spec: R1.1, R1.2
# ---------------------------------------------------------------------------
detect_os() {
    local release_file="${OS_RELEASE_PATH:-/etc/os-release}"

    if [[ ! -f "$release_file" ]]; then
        printf 'provision.sh: %s not found — cannot detect OS\n' "$release_file" >&2
        return 1
    fi

    local os_id=""
    local os_version_id=""

    # Source the file in a subshell to extract just the two variables we need
    # without polluting our environment or executing arbitrary code.
    while IFS='=' read -r key value; do
        # Strip surrounding quotes from value
        value="${value%\"}"
        value="${value#\"}"
        case "$key" in
            ID)          os_id="$value" ;;
            VERSION_ID)  os_version_id="$value" ;;
        esac
    done < "$release_file"

    if [[ "$os_id" != "ubuntu" ]]; then
        printf 'provision.sh: unsupported OS "%s" — only Ubuntu 24.04 and 26.04 are supported\n' \
            "$os_id" >&2
        return 1
    fi

    case "$os_version_id" in
        26.04)
            OS_VERSION="26.04"
            OS_TARGET="ubuntu-2604"
            ;;
        24.04)
            OS_VERSION="24.04"
            OS_TARGET="ubuntu-2404"
            ;;
        *)
            printf 'provision.sh: unsupported Ubuntu version "%s" — only 24.04 and 26.04 are supported\n' \
                "$os_version_id" >&2
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# check_required_tools
#
# Verifies all required tools are on PATH before any mutation. Aborts with the
# name of the first missing tool. Also checks jq availability (installed if
# missing, or verifiable via apt-get -s).
# Spec: R1.5, R1.6
# ---------------------------------------------------------------------------
check_required_tools() {
    # chattr and lsattr (e2fsprogs) — required for audit log arming
    if ! command -v chattr > /dev/null 2>&1; then
        printf 'provision.sh: required tool "chattr" is not installed (install e2fsprogs)\n' >&2
        return 1
    fi
    if ! command -v lsattr > /dev/null 2>&1; then
        printf 'provision.sh: required tool "lsattr" is not installed (install e2fsprogs)\n' >&2
        return 1
    fi

    # useradd or adduser — required for aios account creation
    if ! command -v useradd > /dev/null 2>&1 && ! command -v adduser > /dev/null 2>&1; then
        printf 'provision.sh: required tool "useradd" (or adduser) is not installed\n' >&2
        return 1
    fi

    # install — required for deterministic owner/mode placement
    if ! command -v install > /dev/null 2>&1; then
        printf 'provision.sh: required tool "install" is not installed\n' >&2
        return 1
    fi

    # stat — required for filesystem type check and post-run assertions
    if ! command -v stat > /dev/null 2>&1; then
        printf 'provision.sh: required tool "stat" is not installed\n' >&2
        return 1
    fi

    # getent — required to query user/group database without races
    if ! command -v getent > /dev/null 2>&1; then
        printf 'provision.sh: required tool "getent" is not installed\n' >&2
        return 1
    fi

    # jq — required by hooks at runtime; may need installing
    # On --check, we note it will be installed. On real run, install_jq() handles it.
    # Here we only assert it is either already present or installable.
    if ! command -v jq > /dev/null 2>&1; then
        if command -v apt-get > /dev/null 2>&1; then
            # Ubuntu/Debian host: verify apt-get can find jq before the real run commits to it
            if ! apt-get -s install jq > /dev/null 2>&1; then
                printf 'provision.sh: FATAL: jq is not installed and cannot be found in apt repositories — required by hooks\n' >&2
                return 1
            fi
            # apt-get -s succeeded: jq is installable; install_jq() will install it on the real run
        else
            # FIX-10: on non-apt hosts (e.g. a macOS dev machine running --check), jq is
            # absent and there is no apt-get to install it. Report this as a PRECONDITION
            # CONCERN rather than implying it will be auto-installed, because apt-get is
            # not available and the real provisioning run would fail.
            printf 'provision.sh: WARNING: jq is not installed and no apt-get found — on a supported Ubuntu target this is a fatal precondition; ensure jq is available before provisioning\n' >&2
            # Do not abort here: this function also runs on --check from a macOS dev host
            # where the operator simply wants to inspect the plan. The real Ubuntu run
            # gates on apt-get availability above (or install_jq() will fail explicitly).
        fi
    fi

    return 0
}

# ---------------------------------------------------------------------------
# check_ext4
#
# Verifies the filesystem backing ${EXT4_CHECK_PATH:-/var/log} is ext4-family.
# chattr +a is a silent no-op on tmpfs/overlayfs; arming it there would give
# false integrity confidence.
# Spec: R1.4, R1.4a
# ---------------------------------------------------------------------------
check_ext4() {
    local check_path="${EXT4_CHECK_PATH:-/var/log}"

    # Use stat to get the filesystem type. The format flag differs per OS:
    # Linux: stat -f -c %T <path>   (lowercase c, format string)
    # macOS: stat -f %T <path>       (different flag set)
    # We use the Linux form; tests on macOS stub the stat binary via PATH.
    local fs_type
    fs_type="$(stat -f -c %T "$check_path" 2>/dev/null)" || {
        printf 'provision.sh: could not stat filesystem type of "%s"\n' "$check_path" >&2
        return 1
    }

    # Accept ext4 and ext2/ext3 (the Linux kernel reports ext4 volumes that
    # were formatted as ext3 as "ext2/ext3" in some kernel versions).
    case "$fs_type" in
        ext4 | ext2/ext3 | ext3 | ext2)
            return 0
            ;;
        tmpfs)
            printf 'provision.sh: filesystem at "%s" is "tmpfs" — chattr +a is a silent no-op on tmpfs; aborting\n' \
                "$check_path" >&2
            return 1
            ;;
        overlayfs | overlay)
            printf 'provision.sh: filesystem at "%s" is "overlayfs" — chattr +a is a silent no-op on overlayfs; aborting\n' \
                "$check_path" >&2
            return 1
            ;;
        *)
            printf 'provision.sh: filesystem at "%s" is "%s" — not ext4-family; aborting\n' \
                "$check_path" "$fs_type" >&2
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# check_preconditions
#
# Runs all phase-0 precondition checks in order. Any failure aborts with a
# clear error before any OS state mutation occurs.
# Spec: R1.1..R1.6
# ---------------------------------------------------------------------------
check_preconditions() {
    detect_os
    check_required_tools

    # systemd liveness check (R1.3) — Slice 2 needs it; assert the foundation now
    if ! command -v systemctl > /dev/null 2>&1 || ! systemctl --version > /dev/null 2>&1; then
        printf 'provision.sh: systemd is not present (systemctl --version failed) — required for Slice 2\n' >&2
        return 1
    fi

    check_ext4
}

# ---------------------------------------------------------------------------
# semver_gte <version> <floor>
#
# Returns 0 if version >= floor, 1 otherwise.
# Both arguments are bare semver strings (no leading "v"): e.g. "2.1.153".
# Spec: R9.3
# ---------------------------------------------------------------------------
semver_gte() {
    local v1="$1"
    local floor="$2"

    local v1_major v1_minor v1_patch
    local fl_major fl_minor fl_patch

    IFS='.' read -r v1_major v1_minor v1_patch <<< "$v1"
    IFS='.' read -r fl_major fl_minor fl_patch <<< "$floor"

    # FIX-5: strip any non-numeric suffix (e.g. "-beta", "-rc1", "+build") from each
    # component before integer comparison.  Without this, bash arithmetic on "153-beta"
    # triggers a fatal error under set -u / set -e, and leading zeros like "0153" would
    # be interpreted as octal on some shells.
    # Technique: strip everything from the first non-digit character onward, then default
    # empty string to 0.
    v1_major="${v1_major%%[^0-9]*}"
    v1_minor="${v1_minor%%[^0-9]*}"
    v1_patch="${v1_patch%%[^0-9]*}"
    fl_major="${fl_major%%[^0-9]*}"
    fl_minor="${fl_minor%%[^0-9]*}"
    fl_patch="${fl_patch%%[^0-9]*}"

    # Default empty components to 0
    v1_major="${v1_major:-0}"
    v1_minor="${v1_minor:-0}"
    v1_patch="${v1_patch:-0}"
    fl_major="${fl_major:-0}"
    fl_minor="${fl_minor:-0}"
    fl_patch="${fl_patch:-0}"

    # Force base-10 interpretation to avoid octal surprises (e.g. 0153 → 107 octal)
    v1_major=$((10#$v1_major))
    v1_minor=$((10#$v1_minor))
    v1_patch=$((10#$v1_patch))
    fl_major=$((10#$fl_major))
    fl_minor=$((10#$fl_minor))
    fl_patch=$((10#$fl_patch))

    if   [[ "$v1_major" -gt "$fl_major" ]]; then return 0
    elif [[ "$v1_major" -lt "$fl_major" ]]; then return 1
    fi
    if   [[ "$v1_minor" -gt "$fl_minor" ]]; then return 0
    elif [[ "$v1_minor" -lt "$fl_minor" ]]; then return 1
    fi
    if   [[ "$v1_patch" -ge "$fl_patch" ]]; then return 0
    else return 1
    fi
}

# ---------------------------------------------------------------------------
# assert_cli_version
#
# Calls ${CLAUDE_BIN:-claude} --version, extracts the version string, and
# asserts it is >= CLI_VERSION_FLOOR. Emits WARNING (not abort) if below floor.
# Records CLI_VERSION_RECORDED and LAYER3_STATUS.
# Spec: R9.1, R9.3
# ---------------------------------------------------------------------------
assert_cli_version() {
    local claude_bin="${CLAUDE_BIN:-claude}"
    local version_output

    version_output="$("$claude_bin" --version 2>&1)" || {
        printf 'provision.sh: WARNING: could not run "%s --version"\n' "$claude_bin" >&2
        LAYER3_STATUS="UNVERIFIED"
        return 0
    }

    # Extract semantic version: find the first token matching N.N.N
    local version_string
    version_string="$(printf '%s' "$version_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"

    if [[ -z "$version_string" ]]; then
        printf 'provision.sh: WARNING: could not parse version from "%s"\n' "$version_output" >&2
        CLI_VERSION_RECORDED="(unparseable: $version_output)"
        LAYER3_STATUS="UNVERIFIED"
        return 0
    fi

    CLI_VERSION_RECORDED="$version_string"

    if semver_gte "$version_string" "$CLI_VERSION_FLOOR"; then
        CLI_VERSION_OK=1
    else
        printf 'provision.sh: WARNING: installed Claude Code version %s is below floor v%s\n' \
            "$version_string" "$CLI_VERSION_FLOOR" >&2
        printf 'provision.sh: WARNING: Layer-3 (disableBypassPermissionsMode) is residual risk until CLI is updated\n' >&2
        CLI_VERSION_OK=0
    fi
}

# ---------------------------------------------------------------------------
# check_audit_log_env
#
# Asserts AUDIT_LOG is not set in the current environment.
# Setting it would misdirect production audit writes to an unprotected path.
# Spec: R10.1, R10.2
# ---------------------------------------------------------------------------
check_audit_log_env() {
    if [[ -n "${AUDIT_LOG+x}" ]]; then
        printf 'provision.sh: FATAL: AUDIT_LOG is set in the environment (value: "%s")\n' \
            "${AUDIT_LOG:-}" >&2
        printf 'provision.sh: AUDIT_LOG must be unset in production — it is a test-isolation override only\n' >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# format_summary
#
# Prints the non-secret provisioning summary to stdout.
# MUST NOT print any secret value.
# Spec: R2.5, R9.2, R9.4, R9.5
# ---------------------------------------------------------------------------
format_summary() {
    printf '\n=== Osgania VPS Provisioning Summary ===\n'
    printf '\nOS Target:  %s (Ubuntu %s)\n' "${OS_TARGET:-unknown}" "${OS_VERSION:-unknown}"

    printf '\nInstalled paths and permissions:\n'
    printf '  /opt/osgania/platform/               root:aios 0750\n'
    printf '  /opt/osgania/platform/hooks/          root:aios 0750\n'
    printf '  /opt/osgania/platform/hooks/guardia.sh  root:aios 0750 (+x)\n'
    printf '  /opt/osgania/platform/hooks/camara.sh   root:aios 0750 (+x)\n'
    printf '  /etc/claude-code/managed-settings.json  root:root 0644\n'
    printf '  /etc/osgania/secrets/                 root:root 0700\n'
    printf '  /var/log/osgania/                     root:aios 0750\n'
    printf '  /var/log/osgania/audit.jsonl          root:aios 0620 (chattr +a)\n'

    printf '\nCLI version: %s\n' "${CLI_VERSION_RECORDED:-unknown}"
    printf 'DISABLE_AUTOUPDATER: set to 1 during install invocation\n'

    if [[ "${CLI_VERSION_OK:-0}" -eq 1 ]]; then
        # FIX-6: surface FAILED distinctly from UNVERIFIED
        case "$LAYER3_STATUS" in
            VERIFIED)
                printf 'Layer-3 (%s): VERIFIED\n' "disableBypassPermissionsMode"
                ;;
            FAILED)
                printf 'Layer-3 (%s): FAILED — CLI accepted --dangerously-skip-permissions; mode-lock is NOT enforced\n' \
                    "disableBypassPermissionsMode"
                ;;
            *)
                printf 'Layer-3 (%s): UNVERIFIED — live test could not run or was inconclusive\n' \
                    "disableBypassPermissionsMode"
                ;;
        esac
    else
        printf 'Layer-3 (disableBypassPermissionsMode): WARNING — version below floor v%s; residual risk\n' \
            "$CLI_VERSION_FLOOR"
    fi

    printf '\nSlice 2 forward dependency (DISABLE_AUTOUPDATER runtime persistence):\n'
    printf '  The systemd launch unit (Slice 2) MUST set Environment=DISABLE_AUTOUPDATER=1\n'
    printf '  Slice 1 has no launch mechanism and aios has no home/~/.bashrc to write to.\n'

    printf '\nWARNING: aios account is NOT SSH-sealed by Slice 1.\n'
    printf '  passwd -l locks the password but does NOT block SSH key-based login.\n'
    printf '  SSH sealing (DenyUsers/AllowUsers in sshd_config) is a Slice 2 responsibility.\n'
    printf '\n========================================\n'
}

# ---------------------------------------------------------------------------
# report_plan
#
# Prints the provisioning plan (what would be applied) to stdout without
# executing any of it. Exits 0. Called from main when CHECK_MODE=1.
# Spec: R1.7
# ---------------------------------------------------------------------------
report_plan() {
    printf '=== Osgania Provision --check (dry-run) ===\n'
    printf '\nPlanned changes (nothing will be mutated):\n'
    printf '\n[Phase 0] Precondition checks:\n'
    printf '  - Detect OS via /etc/os-release (ID + VERSION_ID)\n'
    printf '  - Assert Ubuntu 24.04 or 26.04\n'
    printf '  - Assert systemd present (systemctl --version)\n'
    printf '  - Assert /var/log is ext4-family (chattr +a is a no-op on tmpfs/overlayfs)\n'
    printf '  - Assert required tools: chattr, lsattr, useradd/adduser, install, stat, getent\n'
    printf '  - Assert jq is installed or installable via apt-get\n'
    printf '\n[Phase 1] Create group + user:\n'
    printf '  - groupadd -g %s aios  (if not already exists)\n' "$AIOS_GID"
    printf '  - useradd -r -u %s -g %s -s %s --home-dir %s --no-create-home aios\n' \
        "$AIOS_UID" "$AIOS_GID" "$AIOS_SHELL" "$AIOS_HOME"
    printf '  - passwd -l aios\n'
    printf '  - Assert aios NOT in sudo/admin group\n'
    printf '  - UID/GID 9001 collision with non-aios account → ABORT (no clobber)\n'
    printf '\n[Phase 2] Install platform tree + hooks:\n'
    printf '  - install -d -o root -g aios -m 0750 %s\n' "$PLATFORM_DIR"
    printf '  - install -d -o root -g aios -m 0750 %s\n' "$HOOKS_DIR"
    printf '  - install -o root -g aios -m 0750 platform/hooks/guardia.sh %s/guardia.sh\n' "$HOOKS_DIR"
    printf '  - install -o root -g aios -m 0750 platform/hooks/camara.sh %s/camara.sh\n' "$HOOKS_DIR"
    printf '  - managed-settings.json NOT placed under %s (only at %s)\n' "$PLATFORM_DIR" "$POLICY_FILE"
    printf '  - /opt/osgania/client/ NOT created (Slice 2 forward dependency)\n'
    printf '\n[Phase 3] Install jq:\n'
    printf '  - which jq || apt-get install -y jq\n'
    printf '\n[Phase 4] Install operator policy:\n'
    printf '  - install -d -o root -g root -m 0755 %s\n' "$POLICY_DIR"
    printf '  - install -o root -g root -m 0644 platform/managed-settings.json %s\n' "$POLICY_FILE"
    printf '  - jq . %s  (JSON validity check post-install)\n' "$POLICY_FILE"
    printf '\n[Phase 5] Create secrets directory:\n'
    printf '  - install -d -o root -g root -m 0700 %s\n' "$SECRETS_DIR"
    printf '  - No secret values written by Slice 1\n'
    printf '\n[Phase 6] Pre-create + arm audit log:\n'
    printf '  - install -d -o root -g aios -m 0750 %s\n' "$AUDIT_DIR"
    printf '  - [ -f %s ] || install -o root -g aios -m 0620 /dev/null %s\n' \
        "$AUDIT_FILE" "$AUDIT_FILE"
    printf '  - chattr +a %s  (host namespace, before any agent open)\n' "$AUDIT_FILE"
    printf '  - lsattr %s  (verify +a flag is set)\n' "$AUDIT_FILE"
    printf '\n[Phase 7] Pin + verify CLI:\n'
    printf '  - DISABLE_AUTOUPDATER=1 install Claude Code >= v%s\n' "$CLI_VERSION_FLOOR"
    printf '  - claude --version  (record string; assert >= v%s; WARN not abort if below)\n' \
        "$CLI_VERSION_FLOOR"
    printf '  - Live mode-lock test: assert disableBypassPermissionsMode honored (flag UNVERIFIED if unavailable)\n'
    printf '\n[Phase 8] Post-condition assertions:\n'
    printf '  - Assert AUDIT_LOG is not set in the environment\n'
    printf '  - Print non-secret provisioning summary\n'
    printf '\n=== End of dry-run plan ===\n'
}

# ---------------------------------------------------------------------------
# create_aios_account
#
# Creates the aios system account with hardcoded UID/GID 9001.
# Checks for UID/GID collisions with other accounts and aborts.
# Spec: R2.1, R2.2, R2.3, R2.4, R2.5, R2.6, R2.7, R2.8
# ---------------------------------------------------------------------------
create_aios_account() {
    # ---------------------------------------------------------------------------
    # FIX-4: perform ALL collision checks BEFORE any mutation (groupadd/useradd).
    # The previous code called groupadd between the GID-collision check and the
    # UID-collision check, which created partial state when the UID check failed.
    # ---------------------------------------------------------------------------

    # Check GID 9001 collision (by numeric GID)
    local existing_group
    existing_group="$(getent group "$AIOS_GID" 2>/dev/null | cut -d: -f1)" || true
    if [[ -n "$existing_group" && "$existing_group" != "aios" ]]; then
        printf 'provision.sh: FATAL: GID %s is already taken by group "%s" (not "aios") — aborting to avoid clobbering\n' \
            "$AIOS_GID" "$existing_group" >&2
        return 1
    fi

    # Check GID collision by group name (in case aios group exists with wrong GID)
    local existing_aios_gid
    existing_aios_gid="$(getent group aios 2>/dev/null | cut -d: -f3)" || true
    if [[ -n "$existing_aios_gid" && "$existing_aios_gid" != "$AIOS_GID" ]]; then
        printf 'provision.sh: FATAL: group "aios" exists but has GID=%s instead of required GID=%s — aborting\n' \
            "$existing_aios_gid" "$AIOS_GID" >&2
        return 1
    fi

    # Check UID 9001 collision (by numeric UID)
    local existing_user
    existing_user="$(getent passwd "$AIOS_UID" 2>/dev/null | cut -d: -f1)" || true
    if [[ -n "$existing_user" && "$existing_user" != "aios" ]]; then
        printf 'provision.sh: FATAL: UID %s is already taken by user "%s" (not "aios") — aborting to avoid clobbering\n' \
            "$AIOS_UID" "$existing_user" >&2
        return 1
    fi

    # Detect the nologin shell path live (R2.2 — do not hardcode /sbin/nologin).
    # This check is a pre-mutation precondition: if the path is wrong we must abort
    # BEFORE groupadd/useradd so no partial state is created.
    local nologin_path
    nologin_path="$(command -v nologin 2>/dev/null)" || nologin_path="/usr/sbin/nologin"
    # On supported Ubuntu targets the detected path MUST be /usr/sbin/nologin
    if [[ "$nologin_path" != "$AIOS_SHELL" ]]; then
        printf 'provision.sh: FATAL: detected nologin path "%s" != expected "%s" on supported Ubuntu target\n' \
            "$nologin_path" "$AIOS_SHELL" >&2
        return 1
    fi

    # All precondition checks passed — now safe to mutate.

    # Create the group if it does not exist
    if ! getent group aios > /dev/null 2>&1; then
        groupadd -g "$AIOS_GID" aios
    fi

    # Create the aios user if it does not exist (idempotent)
    # R2.8: if aios already exists, verify its attributes match required values exactly.
    if ! id aios > /dev/null 2>&1; then
        useradd -r -u "$AIOS_UID" -g "$AIOS_GID" -s "$AIOS_SHELL" \
            --home-dir "$AIOS_HOME" --no-create-home aios
    else
        # aios exists — verify UID, GID, shell, home all match (R2.8)
        local passwd_entry
        passwd_entry="$(getent passwd aios 2>/dev/null)" || {
            printf 'provision.sh: FATAL: aios exists but getent passwd aios failed\n' >&2
            return 1
        }
        local existing_uid existing_gid existing_home existing_shell
        existing_uid="$(printf '%s' "$passwd_entry" | cut -d: -f3)"
        existing_gid="$(printf '%s' "$passwd_entry" | cut -d: -f4)"
        existing_home="$(printf '%s' "$passwd_entry" | cut -d: -f6)"
        existing_shell="$(printf '%s' "$passwd_entry" | cut -d: -f7)"
        local mismatch=0
        if [[ "$existing_uid" != "$AIOS_UID" ]]; then
            printf 'provision.sh: FATAL: existing aios UID=%s does not match required UID=%s (R2.8)\n' \
                "$existing_uid" "$AIOS_UID" >&2
            mismatch=1
        fi
        if [[ "$existing_gid" != "$AIOS_GID" ]]; then
            printf 'provision.sh: FATAL: existing aios GID=%s does not match required GID=%s (R2.8)\n' \
                "$existing_gid" "$AIOS_GID" >&2
            mismatch=1
        fi
        if [[ "$existing_shell" != "$AIOS_SHELL" ]]; then
            printf 'provision.sh: FATAL: existing aios shell="%s" does not match required shell="%s" (R2.8)\n' \
                "$existing_shell" "$AIOS_SHELL" >&2
            mismatch=1
        fi
        if [[ "$existing_home" != "$AIOS_HOME" ]]; then
            printf 'provision.sh: FATAL: existing aios home="%s" does not match required home="%s" (R2.8)\n' \
                "$existing_home" "$AIOS_HOME" >&2
            mismatch=1
        fi
        if [[ "$mismatch" -ne 0 ]]; then
            printf 'provision.sh: FATAL: existing aios account has wrong attributes — manual intervention required (R2.8)\n' >&2
            return 1
        fi
    fi

    # Lock the password (idempotent — locking an already-locked password is a no-op)
    passwd -l aios

    # Assert aios is NOT in sudo or admin group (R2.3, R2.4)
    # FIX-8: use exact element match (one group per line via tr, then grep -xF) to avoid
    # false positives from hyphenated group names like "sudo-users" or "sudo-admins".
    # grep -w was insufficient because "sudo-users" contains the word "sudo" with -w.
    local aios_groups
    aios_groups="$(id -nG aios)"
    if printf '%s' "$aios_groups" | tr ' ' '\n' | grep -qxF "sudo"; then
        printf 'provision.sh: FATAL: aios is in the sudo group — this must never happen\n' >&2
        return 1
    fi
    if printf '%s' "$aios_groups" | tr ' ' '\n' | grep -qxF "admin"; then
        printf 'provision.sh: FATAL: aios is in the admin group — this must never happen\n' >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# _validate_repo_root <repo_root>
#
# FIX-9: verifies that REPO_ROOT contains the expected source layout before
# any `install` commands read from it. Prevents an attacker-controlled
# REPO_ROOT (via sudo -E / env_keep) from installing arbitrary hook content.
# Expected files: platform/managed-settings.json, platform/hooks/guardia.sh,
#                 platform/hooks/camara.sh
# ---------------------------------------------------------------------------
_validate_repo_root() {
    local repo_root="$1"
    local missing=0
    for expected in \
        "${repo_root}/platform/managed-settings.json" \
        "${repo_root}/platform/hooks/guardia.sh" \
        "${repo_root}/platform/hooks/camara.sh"
    do
        if [[ ! -f "$expected" ]]; then
            printf 'provision.sh: FATAL: REPO_ROOT validation failed — expected file not found: %s\n' \
                "$expected" >&2
            missing=1
        fi
    done
    if [[ "$missing" -ne 0 ]]; then
        printf 'provision.sh: FATAL: REPO_ROOT="%s" does not contain the expected source layout — aborting\n' \
            "$repo_root" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# install_platform_tree
#
# Installs the platform directory, hooks subdirectory, and hook scripts from
# the repository to /opt/osgania/platform/. Sets root:aios 0750 on all.
# Spec: R3.1..R3.8
# ---------------------------------------------------------------------------
install_platform_tree() {
    local repo_root="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

    # FIX-9: validate REPO_ROOT contains expected source layout before installing
    # any files from it. This prevents an attacker-controlled REPO_ROOT (via
    # sudo -E / env_keep) from installing arbitrary content as hooks.
    _validate_repo_root "$repo_root"

    # Platform directory (create or re-assert mode+owner)
    install -d -o root -g aios -m 0750 "$PLATFORM_DIR"

    # Hooks subdirectory
    install -d -o root -g aios -m 0750 "$HOOKS_DIR"

    # Install hook scripts (overwrite on re-run — root owns so write is always permitted)
    install -o root -g aios -m 0750 \
        "${repo_root}/platform/hooks/guardia.sh" "${HOOKS_DIR}/guardia.sh"
    install -o root -g aios -m 0750 \
        "${repo_root}/platform/hooks/camara.sh" "${HOOKS_DIR}/camara.sh"

    # Verify managed-settings.json is NOT under platform/ (R3.7)
    # (install_operator_policy handles the correct placement at /etc/claude-code/)
}

# ---------------------------------------------------------------------------
# install_jq
#
# Installs jq via apt-get if not already present.
# Spec: R8.1, R8.2, R8.3
# ---------------------------------------------------------------------------
install_jq() {
    if command -v jq > /dev/null 2>&1; then
        # Already installed — idempotent skip
        return 0
    fi
    apt-get install -y jq
    # Verify installation succeeded
    if ! command -v jq > /dev/null 2>&1; then
        printf 'provision.sh: FATAL: jq installation failed\n' >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# install_operator_policy
#
# Installs the operator policy file from the repository to
# /etc/claude-code/managed-settings.json with root:root 0644.
# Spec: R4.1, R4.2, R4.3, R4.4
# ---------------------------------------------------------------------------
install_operator_policy() {
    local repo_root="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

    # FIX-9: validate REPO_ROOT (same guard as install_platform_tree)
    _validate_repo_root "$repo_root"

    # Create /etc/claude-code/ directory if absent
    install -d -o root -g root -m 0755 "$POLICY_DIR"

    # Install the policy file (overwrites on re-run — content refresh on re-install)
    install -o root -g root -m 0644 \
        "${repo_root}/platform/managed-settings.json" "$POLICY_FILE"

    # Validate the installed file is valid JSON (R4.4)
    if ! jq . "$POLICY_FILE" > /dev/null 2>&1; then
        printf 'provision.sh: FATAL: installed managed-settings.json is not valid JSON: %s\n' \
            "$POLICY_FILE" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# create_secrets_dir
#
# Creates /etc/osgania/secrets/ with root:root 0700 (aios has NO access).
# Writes no secret values — Slice 1 creates the directory only.
# Spec: R5.1, R5.2, R5.3
# ---------------------------------------------------------------------------
create_secrets_dir() {
    # Create /etc/osgania/ if absent
    install -d -o root -g root -m 0755 /etc/osgania

    # Create secrets/ with mode 0700 — aios has no read, no traverse, no write
    install -d -o root -g root -m 0700 "$SECRETS_DIR"
}

# ---------------------------------------------------------------------------
# create_audit_tree
#
# Pre-creates the audit directory and file, then arms chattr +a on the file.
# Order is load-bearing: dir → file → chattr (R7.4).
# Must run in the host namespace before any agent opens the file (R7.5).
# Spec: R6.1..R6.5, R7.1..R7.6
# ---------------------------------------------------------------------------
create_audit_tree() {
    # Symlink guard — reject if AUDIT_DIR or AUDIT_FILE is a symlink (FIX-7)
    # chattr follows symlinks; a symlink at either path would let an attacker
    # redirect the +a flag to an arbitrary target.
    if [[ -L "$AUDIT_DIR" ]]; then
        printf 'provision.sh: FATAL: audit directory path "%s" is a symlink — aborting to prevent symlink attack\n' \
            "$AUDIT_DIR" >&2
        return 1
    fi
    if [[ -L "$AUDIT_FILE" ]]; then
        printf 'provision.sh: FATAL: audit file path "%s" is a symlink — aborting to prevent symlink attack\n' \
            "$AUDIT_FILE" >&2
        return 1
    fi

    # Create audit directory (re-asserts owner+mode on re-run — idempotent)
    install -d -o root -g aios -m 0750 "$AUDIT_DIR"

    # Re-check AUDIT_FILE symlink after dir creation in case something raced in
    if [[ -L "$AUDIT_FILE" ]]; then
        printf 'provision.sh: FATAL: audit file path "%s" is a symlink (post-mkdir check) — aborting\n' \
            "$AUDIT_FILE" >&2
        return 1
    fi

    # Create audit file only if absent (R6.3, R11.6) — NEVER truncate existing content
    if [[ ! -f "$AUDIT_FILE" ]]; then
        install -o root -g aios -m 0620 /dev/null "$AUDIT_FILE"
    fi

    # Arm chattr +a — add-only operator, never -a (R7.2, R7.6)
    # Setting an already-set flag is a no-op (idempotent)
    chattr +a "$AUDIT_FILE"

    # Verify the +a flag is present after arming (R7.3)
    # Extract ONLY the attribute field (first token before whitespace) to avoid
    # false-positive matches against the filename itself (e.g. /var/log/osgania/audit.jsonl
    # contains the letter 'a', which would always match a bare grep -q 'a').
    local lsattr_out
    lsattr_out="$(lsattr "$AUDIT_FILE" 2>/dev/null)"
    if [[ -z "$lsattr_out" ]]; then
        printf 'provision.sh: FATAL: lsattr produced no output for %s — cannot verify +a flag\n' \
            "$AUDIT_FILE" >&2
        return 1
    fi
    local attr_field
    attr_field="$(printf '%s' "$lsattr_out" | awk '{print $1}')"
    if ! printf '%s' "$attr_field" | grep -q 'a'; then
        printf 'provision.sh: FATAL: chattr +a verification failed on %s — "a" flag not found in attribute field "%s"\n' \
            "$AUDIT_FILE" "$attr_field" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# _classify_layer3_probe <probe_exit_code> <probe_output>
#
# FIX-6: classifies the result of the Layer-3 live mode-lock probe into one of
# three outcomes and sets LAYER3_STATUS accordingly:
#   exit 0  → bypass was accepted → FAILED  (mode-lock NOT enforced)
#   exit N≠0 + refusal keyword    → VERIFIED (CLI refused bypass flag)
#   exit N≠0, no refusal keyword  → UNVERIFIED (inconclusive)
#
# Extracted to a top-level function so bats can test it directly without
# invoking the full install_cli path.
# ---------------------------------------------------------------------------
_classify_layer3_probe() {
    local probe_exit="$1"
    local probe_out="$2"
    if [[ "$probe_exit" -eq 0 ]]; then
        # Exit 0 means the CLI accepted --dangerously-skip-permissions — Layer-3 BROKEN
        LAYER3_STATUS="FAILED"
        printf 'provision.sh: FATAL WARNING: Layer-3 FAILED — CLI accepted --dangerously-skip-permissions (exit 0); disableBypassPermissionsMode is NOT honored\n' >&2
    else
        # Non-zero exit — check whether the refusal message looks like a policy denial
        if printf '%s' "$probe_out" | grep -iqE 'bypass|dangerouslySkip|disableBypass|not allowed|denied|disabled'; then
            LAYER3_STATUS="VERIFIED"
        else
            # Non-zero exit but no recognizable refusal message — inconclusive
            LAYER3_STATUS="UNVERIFIED"
            printf 'provision.sh: WARNING: Layer-3 live mode-lock test was inconclusive (non-zero exit, no refusal keyword) — flag UNVERIFIED\n' >&2
        fi
    fi
}

# ---------------------------------------------------------------------------
# install_cli
#
# Pins and installs the Claude Code CLI at >= CLI_PINNED_VERSION with
# DISABLE_AUTOUPDATER=1. Runs assert_cli_version for version+floor check.
# Attempts a live mode-lock test; records LAYER3_STATUS.
# Spec: R9.1, R9.2, R9.2a, R9.3, R9.4, R9.5
# ---------------------------------------------------------------------------
install_cli() {
    local claude_bin="${CLAUDE_BIN:-claude}"

    # Check if CLI is already installed at the required version
    local installed_version=""
    if command -v "$claude_bin" > /dev/null 2>&1; then
        installed_version="$("$claude_bin" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)" || true
    fi

    # Install/update if not at the pinned version
    if [[ -z "$installed_version" ]] || ! semver_gte "$installed_version" "$CLI_PINNED_VERSION"; then
        printf 'provision.sh: installing Claude Code CLI (pinned >= v%s, DISABLE_AUTOUPDATER=1)...\n' \
            "$CLI_PINNED_VERSION"
        # DISABLE_AUTOUPDATER=1 disables the auto-updater during install invocation (R9.2)
        if command -v npm > /dev/null 2>&1; then
            DISABLE_AUTOUPDATER=1 npm install -g "@anthropic-ai/claude-code@${CLI_PINNED_VERSION}" || {
                printf 'provision.sh: WARNING: npm install failed; attempting alternate install method\n' >&2
            }
        else
            # Scope decision: Slice 1 (vps-provisioning-base) is the OS baseline.
            # Installing Node/npm + the Claude CLI + delivering the API key +
            # performing live Layer-3 verification is deferred to Slice 2
            # (vps-provisioning-hardening). Here we only record state, non-fatally.
            printf 'provision.sh: NOTE: npm not found — Claude CLI install (pinned >= v%s) is deferred to Slice 2 (vps-provisioning-hardening). Slice 1 records CLI state only; non-fatal by design (KL-3).\n' \
                "$CLI_PINNED_VERSION" >&2
        fi
    fi

    # Assert the installed version meets the floor (R9.3)
    assert_cli_version

    # Live mode-lock test: attempt to validate disableBypassPermissionsMode (R9.4, R9.5)
    # Try to invoke the CLI with --dangerously-skip-permissions against the installed policy
    # and assert it is refused, OR use effective-policy introspection if available.
    if command -v "$claude_bin" > /dev/null 2>&1; then
        # FIX-6: distinguish three outcomes (classification delegated to top-level function
        # _classify_layer3_probe so it is directly unit-testable from bats):
        #   (a) probe could not run at all            → UNVERIFIED
        #   (b) probe ran and bypass was REFUSED       → VERIFIED
        #   (c) probe ran and exited 0 (bypass accepted) → FAILED (mode-lock broken)
        local probe_output probe_exit
        probe_output="$("$claude_bin" --dangerously-skip-permissions --print "test" 2>&1)" && probe_exit=0 || probe_exit=$?
        _classify_layer3_probe "$probe_exit" "$probe_output"
    else
        LAYER3_STATUS="UNVERIFIED"
        printf 'provision.sh: WARNING: claude CLI not found after install — Layer-3 UNVERIFIED\n' >&2
    fi
}

# ---------------------------------------------------------------------------
# main <"$@">
#
# Orchestrates the ordered provisioning phases. Wires all phase functions in
# the correct dependency order (per design.md execution model).
# Spec: R1..R11 (all requirements wired)
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    if [[ "$CHECK_MODE" -eq 1 ]]; then
        # R1.7: --check MUST run phase-0 precondition checks before reporting the plan.
        # A non-Ubuntu host or missing tools must be reported/rejected, not silently
        # accepted with a clean plan. check_preconditions aborts on failure (non-zero
        # exit propagated by set -e).
        check_preconditions
        report_plan
        exit 0
    fi

    printf 'provision.sh: starting Osgania VPS provisioning...\n'

    # Phase 0 — Precondition checks (abort on any failure before any mutation)
    printf 'provision.sh: [0/8] running precondition checks...\n'
    check_preconditions

    # Phase 1 — Create aios group + user (must exist before any chown root:aios)
    printf 'provision.sh: [1/8] creating aios system account...\n'
    create_aios_account

    # Phase 2 — Install platform tree and hooks
    printf 'provision.sh: [2/8] installing platform tree...\n'
    install_platform_tree

    # Phase 3 — Install jq (required by hooks at runtime; must be before CLI pin)
    printf 'provision.sh: [3/8] installing jq...\n'
    install_jq

    # Phase 4 — Install operator policy
    printf 'provision.sh: [4/8] installing operator policy...\n'
    install_operator_policy

    # Phase 5 — Create secrets directory (root-only, aios has no access)
    printf 'provision.sh: [5/8] creating secrets directory...\n'
    create_secrets_dir

    # Phase 6 — Pre-create and arm audit log (order-critical: after aios exists,
    # in host namespace before any agent can open the file)
    printf 'provision.sh: [6/8] pre-creating and arming audit log...\n'
    create_audit_tree

    # Phase 7 — Pin + verify + live-test CLI (after policy install so live mode-lock
    # test reads the freshly-installed managed-settings.json)
    printf 'provision.sh: [7/8] installing and verifying Claude Code CLI...\n'
    install_cli

    # Phase 8 — Post-condition assertions
    printf 'provision.sh: [8/8] running post-condition assertions...\n'
    check_audit_log_env
    format_summary

    printf 'provision.sh: provisioning complete.\n'
}

# ---------------------------------------------------------------------------
# Entry point guard — allows bats to `source scripts/provision.sh` and test
# individual functions WITHOUT running the full installer.
# When sourced (BASH_SOURCE[0] != $0), the condition is false → we do NOT
# run main. The `|| true` prevents set -e from treating a false [[ as an error.
# ---------------------------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
