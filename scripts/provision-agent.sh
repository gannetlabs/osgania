#!/usr/bin/env bash
# provision-agent.sh — Osgania 2a agent provisioner
#
# Installs the Node/CLI runtime, hardened systemd launch unit, file-based
# API-key delivery, and performs a live Layer-3 mode-lock probe.
# Runs AFTER provision.sh (Slice 1) on a Slice-1-provisioned Ubuntu 24.04/26.04 box.
#
# Usage:
#   sudo ./provision-agent.sh           — full provisioning run
#   sudo ./provision-agent.sh --check   — dry-run: report plan, mutate nothing, exit 0
#
# Spec: HA-01..HA-14 (see openspec/changes/vps-provisioning-hardening-2a/spec.md)
# Design: openspec/changes/vps-provisioning-hardening-2a/design.md (ADR-1..ADR-5)

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants — all decided literals from design.md (drift gate)
# Defined as plain variables (not readonly) so sourcing from bats is safe
# across repeated setup() calls.
# ---------------------------------------------------------------------------

AGENT_CLI_PINNED_VERSION="2.1.153"
AGENT_CLI_VERSION_FLOOR="2.1.153"
AGENT_NODE_VERSION_FLOOR=18

# AGENT_POLICY_FILE is resolved at runtime via MANAGED_SETTINGS_PATH to allow test overrides
# Post-pivot (ADR-6): the launch WRAPPER replaces the obsolete apiKeyHelper.
AGENT_WRAPPER_INSTALLED="/opt/osgania/platform/bin/agent-run.sh"
AGENT_CLIENT_WORKSPACE="/opt/osgania/client"
AGENT_STATE_DIR="/var/lib/osgania-agent"
AGENT_SECRETS_KEY="/etc/osgania/secrets/anthropic-api-key"
AGENT_SERVICE_UNIT="/etc/systemd/system/osgania-agent.service"
AGENT_TIMER_UNIT="/etc/systemd/system/osgania-agent.timer"

# ---------------------------------------------------------------------------
# State variables — set by functions, read by main/print_summary
# ---------------------------------------------------------------------------

CHECK_MODE=0
AGENT_CLI_VERSION_RECORDED=""
AGENT_PROBE_STATUS="UNVERIFIED"

# ---------------------------------------------------------------------------
# semver_major <version_string>
#
# Extracts the major version number from a semver string (strips leading "v").
# Prints the integer to stdout. Returns 0.
# ---------------------------------------------------------------------------
semver_major() {
    local v="${1#v}"
    local major
    major="${v%%.*}"
    major="${major%%[^0-9]*}"
    printf '%s' "${major:-0}"
}

# ---------------------------------------------------------------------------
# semver_gte <version> <floor>
#
# Returns 0 if version >= floor, 1 otherwise.
# Both arguments are bare semver strings (no leading "v"): e.g. "2.1.153".
# Mirrors the implementation in provision.sh for consistency.
# ---------------------------------------------------------------------------
semver_gte() {
    local v1="$1"
    local floor="$2"

    local v1_major v1_minor v1_patch
    local fl_major fl_minor fl_patch

    IFS='.' read -r v1_major v1_minor v1_patch <<< "$v1"
    IFS='.' read -r fl_major fl_minor fl_patch <<< "$floor"

    v1_major="${v1_major%%[^0-9]*}"
    v1_minor="${v1_minor%%[^0-9]*}"
    v1_patch="${v1_patch%%[^0-9]*}"
    fl_major="${fl_major%%[^0-9]*}"
    fl_minor="${fl_minor%%[^0-9]*}"
    fl_patch="${fl_patch%%[^0-9]*}"

    v1_major="${v1_major:-0}"
    v1_minor="${v1_minor:-0}"
    v1_patch="${v1_patch:-0}"
    fl_major="${fl_major:-0}"
    fl_minor="${fl_minor:-0}"
    fl_patch="${fl_patch:-0}"

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
# parse_args <"$@">
#
# Sets CHECK_MODE=1 if --check is provided. Errors on unknown flags.
# Spec: HA-01.4
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
                printf 'provision-agent.sh: unknown option: %s\n' "$1" >&2
                printf 'Usage: provision-agent.sh [--check]\n' >&2
                return 1
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# check_preconditions
#
# Verifies Slice-1 end-state before any mutation:
#   - aios account with UID/GID 9001
#   - managed-settings.json exists and is valid JSON
#   - audit log has chattr +a flag
#   - systemd is present
# Spec: HA-01.1, HA-01.2, HA-01.3
# ---------------------------------------------------------------------------
check_preconditions() {
    # Check aios account (UID/GID 9001)
    local passwd_entry
    if ! passwd_entry="$(getent passwd aios 2>/dev/null)"; then
        printf 'provision-agent.sh: PRECONDITION FAILED: aios account is absent (Slice-1 required)\n' >&2
        return 1
    fi
    local uid gid
    uid="$(printf '%s' "$passwd_entry" | cut -d: -f3)"
    gid="$(printf '%s' "$passwd_entry" | cut -d: -f4)"
    if [[ "$uid" != "9001" ]]; then
        printf 'provision-agent.sh: PRECONDITION FAILED: aios UID=%s, expected 9001\n' "$uid" >&2
        return 1
    fi
    if [[ "$gid" != "9001" ]]; then
        printf 'provision-agent.sh: PRECONDITION FAILED: aios GID=%s, expected 9001\n' "$gid" >&2
        return 1
    fi

    # Check managed-settings.json
    local policy_file="${MANAGED_SETTINGS_PATH:-/etc/claude-code/managed-settings.json}"
    if [[ ! -f "$policy_file" ]]; then
        printf 'provision-agent.sh: PRECONDITION FAILED: managed-settings.json absent at %s\n' "$policy_file" >&2
        return 1
    fi
    if ! jq . "$policy_file" > /dev/null 2>&1; then
        printf 'provision-agent.sh: PRECONDITION FAILED: managed-settings.json is not valid JSON: %s\n' "$policy_file" >&2
        return 1
    fi

    # Check audit log +a flag
    local audit_file="/var/log/osgania/audit.jsonl"
    if [[ ! -f "$audit_file" ]]; then
        printf 'provision-agent.sh: PRECONDITION FAILED: audit log absent at %s (Slice-1 required)\n' "$audit_file" >&2
        return 1
    fi
    local lsattr_out attr_field
    lsattr_out="$(lsattr "$audit_file" 2>/dev/null)" || {
        printf 'provision-agent.sh: PRECONDITION FAILED: lsattr failed on %s — cannot verify +a flag\n' "$audit_file" >&2
        return 1
    }
    attr_field="$(printf '%s' "$lsattr_out" | awk '{print $1}')"
    if ! printf '%s' "$attr_field" | grep -q 'a'; then
        printf 'provision-agent.sh: PRECONDITION FAILED: audit log +a flag not set on %s — Slice-1 required\n' "$audit_file" >&2
        return 1
    fi

    # Check systemd present (HA-01.3)
    if ! command -v systemctl > /dev/null 2>&1 || ! systemctl --version > /dev/null 2>&1; then
        printf 'provision-agent.sh: PRECONDITION FAILED: systemd is not present (systemctl --version failed)\n' >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# report_plan
#
# Prints the provisioning plan (dry-run) without executing anything.
# Does NOT invoke claude, npm, apt, or any network operation.
# Spec: HA-01.4, HA-01-S3
# ---------------------------------------------------------------------------
report_plan() {
    printf '=== provision-agent.sh --check (dry-run) ===\n'
    printf '\nPlanned changes (nothing will be mutated):\n'
    printf '\n[Step 0] Precondition checks (already verified above):\n'
    printf '  - aios UID/GID 9001 present\n'
    printf '  - %s valid JSON\n' "${MANAGED_SETTINGS_PATH:-/etc/claude-code/managed-settings.json}"
    printf '  - /var/log/osgania/audit.jsonl has chattr +a\n'
    printf '  - systemd present\n'
    printf '\n[Step 1] Node.js runtime (>= 18):\n'
    printf '  - Check node --version; if >= 18, skip; else install NodeSource 20.x\n'
    printf '  - apt-mark hold nodejs npm\n'
    printf '\n[Step 2] Claude Code CLI (pinned @anthropic-ai/claude-code@%s):\n' \
        "$AGENT_CLI_PINNED_VERSION"
    printf '  - Check claude --version; if >= %s, skip npm install\n' "$AGENT_CLI_PINNED_VERSION"
    printf '  - Else: npm install -g @anthropic-ai/claude-code@%s\n' "$AGENT_CLI_PINNED_VERSION"
    printf '\n[Step 3] Client workspace:\n'
    printf '  - install -d -o aios -g aios -m 0700 %s\n' "$AGENT_CLIENT_WORKSPACE"
    printf '\n[Step 4] Launch wrapper install:\n'
    printf '  - install -o root -g root -m 0755 platform/bin/agent-run.sh %s\n' \
        "$AGENT_WRAPPER_INSTALLED"
    printf '  - Lint the wrapper: execs /usr/bin/claude "$@", contains no --bare\n'
    printf '\n[Step 5] managed-settings.json verify (READ-ONLY — no write, post-pivot):\n'
    printf '  - Validate JSON; assert R9-R12 structural invariant present + unchanged\n'
    printf '  - 2a adds NO apiKeyHelper key and writes NOTHING to the policy\n'
    printf '\n[Step 6] systemd units:\n'
    printf '  - Write osgania-agent.service to %s\n' "$AGENT_SERVICE_UNIT"
    printf '  - Assert --bare guard (unit + wrapper) and forbidden-token guard\n'
    printf '  - Write osgania-agent.timer to %s\n' "$AGENT_TIMER_UNIT"
    printf '  - systemctl daemon-reload\n'
    printf '  - systemctl enable osgania-agent.timer (probe runs BEFORE enabling; no --now race)\n'
    printf '\n[Step 7] Defense-in-depth probe:\n'
    printf '  - (NOT executed in --check mode — pure plan output only)\n'
    printf '\n[Step 8] Summary:\n'
    printf '  - Print non-secret summary (version, paths, defense-in-depth status)\n'
    printf '  - Assert AUDIT_LOG is not set\n'
    printf '\n=== End of dry-run plan ===\n'
}

# ---------------------------------------------------------------------------
# install_node
#
# Ensures Node.js >= 18 is present. If already installed at >= 18, skips.
# If absent or < 18, installs NodeSource 20.x LTS. Always runs apt-mark hold.
# Spec: HA-02.1, HA-02.2, HA-02.3, HA-02.4
# ---------------------------------------------------------------------------
install_node() {
    local node_bin="${NODE_BIN:-node}"
    local installed_major=0

    if command -v "$node_bin" > /dev/null 2>&1; then
        local raw_version
        raw_version="$("$node_bin" --version 2>/dev/null)" || raw_version=""
        # Strip leading "v" and extract major
        local ver="${raw_version#v}"
        installed_major="$(semver_major "$ver")"
    fi

    if [[ "$installed_major" -ge "$AGENT_NODE_VERSION_FLOOR" ]]; then
        printf 'provision-agent.sh: Node already >= %s (found v%s), skipping install\n' \
            "$AGENT_NODE_VERSION_FLOOR" "$installed_major"
    else
        printf 'provision-agent.sh: Node < %s or absent (found major=%s), installing NodeSource 20.x...\n' \
            "$AGENT_NODE_VERSION_FLOOR" "$installed_major"
        # Install NodeSource 20.x.
        # PROVISION_TEST_ALLOW_MUTATION=1 allows a test-only URL override via NODESOURCE_URL
        # (URL only — never an arbitrary command) to inject a stub without using eval.
        if [[ -n "${PROVISION_TEST_ALLOW_MUTATION:-}" && -n "${NODESOURCE_URL:-}" ]]; then
            curl -fsSL "${NODESOURCE_URL}" | bash -
        else
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        fi
        apt-get install -y nodejs
    fi

    # Always hold — add-only, idempotent (HA-02.3)
    apt-mark hold nodejs npm
}

# ---------------------------------------------------------------------------
# install_cli
#
# Pins the Claude Code CLI at AGENT_CLI_PINNED_VERSION. If already at that
# version or higher, skips. Records the installed version for print_summary.
# Spec: HA-03.1, HA-03.2, HA-03.3, HA-03.4
# ---------------------------------------------------------------------------
install_cli() {
    local claude_bin="${CLAUDE_BIN:-claude}"
    local installed_version=""

    if command -v "$claude_bin" > /dev/null 2>&1; then
        # Extract the version anchored to the trailing "(Claude Code)" marker.
        # Real output is "X.Y.Z (Claude Code)"; anchoring to the marker matches the
        # real format AND avoids matching IPs / other N.N.N strings in the output.
        installed_version="$("$claude_bin" --version 2>&1 \
            | grep -oiE '[0-9]+\.[0-9]+\.[0-9]+[[:space:]]*\(claude code\)' \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
            | head -n 1)" || installed_version=""
    fi

    if [[ -n "$installed_version" ]] && semver_gte "$installed_version" "$AGENT_CLI_PINNED_VERSION"; then
        printf 'provision-agent.sh: CLI already at pin %s, skipping npm install\n' "$installed_version"
        AGENT_CLI_VERSION_RECORDED="$installed_version"
    else
        printf 'provision-agent.sh: installing Claude Code CLI pinned at %s...\n' "$AGENT_CLI_PINNED_VERSION"
        local npm_bin="${NPM_BIN:-npm}"
        "$npm_bin" install -g "@anthropic-ai/claude-code@${AGENT_CLI_PINNED_VERSION}"

        # Re-verify after install (same anchored extraction)
        local post_version=""
        if command -v "$claude_bin" > /dev/null 2>&1; then
            post_version="$("$claude_bin" --version 2>&1 \
                | grep -oiE '[0-9]+\.[0-9]+\.[0-9]+[[:space:]]*\(claude code\)' \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
                | head -n 1)" || post_version=""
        fi
        if [[ -z "$post_version" ]] || ! semver_gte "$post_version" "$AGENT_CLI_VERSION_FLOOR"; then
            printf 'provision-agent.sh: FATAL: CLI version after install (%s) is below floor %s\n' \
                "${post_version:-unknown}" "$AGENT_CLI_VERSION_FLOOR" >&2
            return 1
        fi
        AGENT_CLI_VERSION_RECORDED="$post_version"
    fi
}

# ---------------------------------------------------------------------------
# create_workspace
#
# Creates /opt/osgania/client/ as aios:aios 0700. Idempotent.
# Spec: HA-04.1, HA-04.2
# ---------------------------------------------------------------------------
create_workspace() {
    install -d -o aios -g aios -m 0700 "$AGENT_CLIENT_WORKSPACE"
}

# ---------------------------------------------------------------------------
# _assert_wrapper_invariant <wrapper_src>
#
# Load-bearing --bare guard on the WRAPPER (spec HA-05.4 / HA-06.2): the wrapper
# MUST exec /usr/bin/claude "$@" and MUST NOT contain a --bare token. Aborts if
# violated. Mirrors the unit-string guard in build_service_unit.
# ---------------------------------------------------------------------------
_assert_wrapper_invariant() {
    local src="$1"
    if printf '%s' "$(cat "$src")" | grep -qiE '(^|[[:space:]])(-bare|--bare)([[:space:]]|$)'; then
        printf 'provision-agent.sh: INVARIANT ABORT: wrapper %s contains a --bare token — refusing to install\n' "$src" >&2
        return 1
    fi
    if ! grep -qE '^[[:space:]]*exec[[:space:]]+/usr/bin/claude[[:space:]]+"\$@"[[:space:]]*$' "$src"; then
        printf 'provision-agent.sh: INVARIANT ABORT: wrapper %s does not exec /usr/bin/claude "$@" — refusing to install\n' "$src" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# install_wrapper
#
# Installs platform/bin/agent-run.sh (the ANTHROPIC_API_KEY launch wrapper, ADR-6)
# as root:root 0755, after linting the --bare / exec invariant.
# Spec: HA-05.1, HA-05.2, HA-05.4
# ---------------------------------------------------------------------------
install_wrapper() {
    # Resolve repo root from BASH_SOURCE (canonical path).
    # REPO_ROOT env override is accepted ONLY when PROVISION_TEST_ALLOW_MUTATION=1
    # is explicitly set, preventing supply-chain injection in production runs.
    local canonical_root
    canonical_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    local repo_root
    if [[ -n "${PROVISION_TEST_ALLOW_MUTATION:-}" && -n "${REPO_ROOT:-}" ]]; then
        repo_root="$REPO_ROOT"
    else
        repo_root="$canonical_root"
    fi
    local src="${repo_root}/platform/bin/agent-run.sh"
    if [[ ! -f "$src" ]]; then
        printf 'provision-agent.sh: FATAL: source launch wrapper not found: %s\n' "$src" >&2
        return 1
    fi
    _assert_wrapper_invariant "$src" || return 1
    # Ensure parent directory exists
    install -d -o root -g root -m 0755 "$(dirname "$AGENT_WRAPPER_INSTALLED")"
    install -o root -g root -m 0755 "$src" "$AGENT_WRAPPER_INSTALLED"
    # Pivot cleanup (ADR-6, HA-05.1c): remove the obsolete pre-pivot apiKeyHelper
    # if an in-place upgrade left it behind. The post-pivot launch path is the
    # wrapper ONLY; a lingering anthropic-key.sh is dead code the deployment must
    # not carry (HA-05-S1). No-op on a fresh box (never installed post-pivot).
    rm -f "$(dirname "$AGENT_WRAPPER_INSTALLED")/anthropic-key.sh"
}

# ---------------------------------------------------------------------------
# verify_managed_settings <settings_file>
#
# POST-PIVOT (ADR-1 superseded by ADR-6): 2a no longer modifies managed-settings.
# This is a READ-ONLY verification — validate JSON and assert the R9-R12
# structural invariant is present and intact. It writes NOTHING (no apiKeyHelper
# upsert, no jq write), so the live policy is byte-identical before and after.
# Spec: HA-05.3, HA-05.5, HA-05.6, HA-05.7
# ---------------------------------------------------------------------------
verify_managed_settings() {
    local settings_file="$1"

    if [[ ! -f "$settings_file" ]]; then
        printf 'provision-agent.sh: FATAL: settings file not found: %s\n' "$settings_file" >&2
        return 1
    fi

    # Validate JSON (read-only)
    if ! jq . "$settings_file" > /dev/null 2>&1; then
        printf 'provision-agent.sh: FATAL: managed-settings.json is not valid JSON: %s\n' "$settings_file" >&2
        return 1
    fi

    # Assert R9-R12 structural invariant present + intact (read-only, no write)
    _assert_r9_r12_invariant "$settings_file" || return 1
}

# ---------------------------------------------------------------------------
# _assert_r9_r12_invariant <json_file>
#
# Asserts all R9-R12 structural keys are present and correct in the given JSON
# file. Aborts with a named failed assertion if any check fails.
# Spec: HA-05.6
# ---------------------------------------------------------------------------
_assert_r9_r12_invariant() {
    local f="$1"

    # Check permissions.deny has exactly 6 entries
    local deny_count
    deny_count="$(jq '.permissions.deny | length' "$f" 2>/dev/null)" || deny_count=0
    if [[ "$deny_count" != "6" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: permissions.deny length=%s, expected 6\n' \
            "$deny_count" >&2
        return 1
    fi

    # Check each required deny entry
    local -a required_denies=(
        'Bash(sudo *)'
        'Bash(curl *)'
        'Bash(wget *)'
        'Read(/etc/osgania/secrets/**)'
        'Edit(/opt/osgania/platform/**)'
        'Write(/opt/osgania/platform/**)'
    )
    local entry
    for entry in "${required_denies[@]}"; do
        if ! jq -e --arg e "$entry" '.permissions.deny | index($e) != null' "$f" > /dev/null 2>&1; then
            printf 'provision-agent.sh: INVARIANT FAILED: missing deny entry: %s\n' "$entry" >&2
            return 1
        fi
    done

    # Check permissions.allow == []
    local allow_count
    allow_count="$(jq '.permissions.allow | length' "$f" 2>/dev/null)" || allow_count=1
    if [[ "$allow_count" != "0" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: permissions.allow is not empty (length=%s)\n' \
            "$allow_count" >&2
        return 1
    fi

    # Check permissions.defaultMode == "default"
    local default_mode
    default_mode="$(jq -r '.permissions.defaultMode' "$f" 2>/dev/null)" || default_mode=""
    if [[ "$default_mode" != "default" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: permissions.defaultMode="%s", expected "default"\n' \
            "$default_mode" >&2
        return 1
    fi

    # Check permissions.disableBypassPermissionsMode == "disable"
    local bypass_mode
    bypass_mode="$(jq -r '.permissions.disableBypassPermissionsMode' "$f" 2>/dev/null)" || bypass_mode=""
    if [[ "$bypass_mode" != "disable" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: disableBypassPermissionsMode="%s", expected "disable"\n' \
            "$bypass_mode" >&2
        return 1
    fi

    # Check allowManagedHooksOnly == true
    local hooks_only
    hooks_only="$(jq -r '.allowManagedHooksOnly' "$f" 2>/dev/null)" || hooks_only=""
    if [[ "$hooks_only" != "true" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: allowManagedHooksOnly="%s", expected "true"\n' \
            "$hooks_only" >&2
        return 1
    fi

    # Check hooks top-level keys — only PreToolUse and PostToolUse are permitted (no extra hook types)
    local hook_keys
    hook_keys="$(jq -r '.hooks | keys | sort | @json' "$f" 2>/dev/null)" || hook_keys="null"
    if [[ "$hook_keys" != '["PostToolUse","PreToolUse"]' ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: .hooks keys=%s, expected exactly ["PostToolUse","PreToolUse"]\n' \
            "$hook_keys" >&2
        return 1
    fi

    # Check PreToolUse: exactly ONE matcher entry (Bash), with exactly ONE hooks entry (guardia)
    local pre_len
    pre_len="$(jq '.hooks.PreToolUse | length' "$f" 2>/dev/null)" || pre_len=0
    if [[ "$pre_len" != "1" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: .hooks.PreToolUse length=%s, expected 1\n' "$pre_len" >&2
        return 1
    fi
    local pre_matcher
    pre_matcher="$(jq -r '.hooks.PreToolUse[0].matcher' "$f" 2>/dev/null)" || pre_matcher=""
    if [[ "$pre_matcher" != "Bash" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: PreToolUse[0].matcher="%s", expected "Bash"\n' "$pre_matcher" >&2
        return 1
    fi
    local pre_hooks_len
    pre_hooks_len="$(jq '.hooks.PreToolUse[0].hooks | length' "$f" 2>/dev/null)" || pre_hooks_len=0
    if [[ "$pre_hooks_len" != "1" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: PreToolUse[0].hooks length=%s, expected exactly 1 (guardia)\n' \
            "$pre_hooks_len" >&2
        return 1
    fi
    local guardia_present
    guardia_present="$(jq -r '
        .hooks.PreToolUse[0].hooks[0]
        | select(.command == "/opt/osgania/platform/hooks/guardia.sh" and .timeout == 10)
        | "found"
    ' "$f" 2>/dev/null)" || guardia_present=""
    if [[ "$guardia_present" != "found" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: guardia PreToolUse hook (Bash, timeout 10) not found\n' >&2
        return 1
    fi

    # Check PostToolUse: exactly ONE matcher entry (*), with exactly ONE hooks entry (camara)
    local post_len
    post_len="$(jq '.hooks.PostToolUse | length' "$f" 2>/dev/null)" || post_len=0
    if [[ "$post_len" != "1" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: .hooks.PostToolUse length=%s, expected 1\n' "$post_len" >&2
        return 1
    fi
    local post_matcher
    post_matcher="$(jq -r '.hooks.PostToolUse[0].matcher' "$f" 2>/dev/null)" || post_matcher=""
    if [[ "$post_matcher" != "*" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: PostToolUse[0].matcher="%s", expected "*"\n' "$post_matcher" >&2
        return 1
    fi
    local post_hooks_len
    post_hooks_len="$(jq '.hooks.PostToolUse[0].hooks | length' "$f" 2>/dev/null)" || post_hooks_len=0
    if [[ "$post_hooks_len" != "1" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: PostToolUse[0].hooks length=%s, expected exactly 1 (camara)\n' \
            "$post_hooks_len" >&2
        return 1
    fi
    local camara_present
    camara_present="$(jq -r '
        .hooks.PostToolUse[0].hooks[0]
        | select(.command == "/opt/osgania/platform/hooks/camara.sh" and .timeout == 10)
        | "found"
    ' "$f" 2>/dev/null)" || camara_present=""
    if [[ "$camara_present" != "found" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: camara PostToolUse hook (*, timeout 10) not found\n' >&2
        return 1
    fi

    # Check for security-weakening top-level keys — only known keys are permitted
    local top_level_keys
    top_level_keys="$(jq -r '[keys[] | select(. != "permissions" and . != "allowManagedHooksOnly" and . != "hooks" and . != "apiKeyHelper")] | sort | @json' "$f" 2>/dev/null)" || top_level_keys="null"
    if [[ "$top_level_keys" != "[]" ]]; then
        printf 'provision-agent.sh: INVARIANT FAILED: unexpected top-level keys in managed-settings: %s\n' \
            "$top_level_keys" >&2
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------------
# build_service_unit
#
# Returns the exact osgania-agent.service unit file content as a heredoc.
# Asserts --bare guard and forbidden-token guard before returning.
# Spec: HA-06.1, HA-06.2, HA-06.3
# ---------------------------------------------------------------------------
build_service_unit() {
    local unit_content
    unit_content="$(cat <<'UNIT_EOF'
[Unit]
Description=OSGANIA client agent (headless Claude Code run)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=aios
Group=aios
WorkingDirectory=/opt/osgania/client
StateDirectory=osgania-agent
StateDirectoryMode=0700
Environment=DISABLE_AUTOUPDATER=1
Environment=HOME=%S/osgania-agent
Environment=XDG_CONFIG_HOME=%S/osgania-agent
Environment=XDG_CACHE_HOME=%S/osgania-agent
Environment=XDG_DATA_HOME=%S/osgania-agent
Environment=XDG_STATE_HOME=%S/osgania-agent
LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key
UnsetEnvironment=ANTHROPIC_AUTH_TOKEN
ExecStart=/opt/osgania/platform/bin/agent-run.sh -p
ProtectSystem=strict
ReadWritePaths=/opt/osgania/client /var/log/osgania
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
LimitCORE=0
SystemCallFilter=~@reboot @swap @mount @clock @debug @module @raw-io @obsolete
UNIT_EOF
)"

    # --bare guard (HA-06.2) — load-bearing security assertion.
    # Case-insensitive to catch --BARE, -bare, and other capitalisation variants.
    if printf '%s' "$unit_content" | grep -qiE '(^|[[:space:]])(-bare|--bare)([[:space:]]|$)'; then
        printf 'provision-agent.sh: INVARIANT ABORT: assembled service unit contains --bare token — refusing to write\n' >&2
        return 1
    fi
    # Positive assertion: ExecStart must be exactly the wrapper "-p" invocation (ADR-3 amended)
    local execstart_line
    execstart_line="$(printf '%s' "$unit_content" | grep '^ExecStart=' || true)"
    if [[ "$execstart_line" != "ExecStart=/opt/osgania/platform/bin/agent-run.sh -p" ]]; then
        printf 'provision-agent.sh: INVARIANT ABORT: ExecStart line is "%s", expected exactly "ExecStart=/opt/osgania/platform/bin/agent-run.sh -p"\n' \
            "$execstart_line" >&2
        return 1
    fi

    # Forbidden-token guard (HA-06.3) — load-bearing security assertion
    if printf '%s' "$unit_content" | grep -q 'MemoryDenyWriteExecute'; then
        printf 'provision-agent.sh: INVARIANT ABORT: assembled service unit contains MemoryDenyWriteExecute — refusing to write\n' >&2
        return 1
    fi
    # AUDIT_LOG= is forbidden anywhere in the unit (the unit must never set this var)
    if printf '%s' "$unit_content" | grep -q 'AUDIT_LOG='; then
        printf 'provision-agent.sh: INVARIANT ABORT: assembled service unit contains AUDIT_LOG= — refusing to write\n' >&2
        return 1
    fi
    # Environment=ANTHROPIC_API_KEY is forbidden as a directive that SETS the variable.
    # Note: UnsetEnvironment=ANTHROPIC_API_KEY is ALLOWED (it scrubs the var, not sets it).
    # We match Environment=ANTHROPIC_API_KEY at the start of a line to avoid false positives
    # from the UnsetEnvironment directive that legitimately references the same var name.
    if printf '%s' "$unit_content" | grep -q '^Environment=ANTHROPIC_API_KEY'; then
        printf 'provision-agent.sh: INVARIANT ABORT: assembled service unit contains Environment=ANTHROPIC_API_KEY directive — refusing to write\n' >&2
        return 1
    fi

    printf '%s\n' "$unit_content"
}

# ---------------------------------------------------------------------------
# build_timer_unit
#
# Returns the osgania-agent.timer unit file content.
# Spec: HA-07.1, HA-07.2
# ---------------------------------------------------------------------------
build_timer_unit() {
    cat <<'TIMER_EOF'
[Unit]
Description=OSGANIA agent cadence (PLACEHOLDER — autonomy-ladder owns the real schedule)

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
TIMER_EOF
}

# ---------------------------------------------------------------------------
# write_units
#
# Writes the service and timer unit files to /etc/systemd/system/ atomically,
# runs daemon-reload, and enables the timer.
# Spec: HA-06.1, HA-06.5, HA-06.6, HA-07.3
# ---------------------------------------------------------------------------
write_units() {
    local service_content
    local timer_content
    service_content="$(build_service_unit)"
    timer_content="$(build_timer_unit)"

    # Write service unit atomically
    local tmp_service tmp_timer
    tmp_service="$(mktemp)"
    printf '%s\n' "$service_content" > "$tmp_service"
    mv "$tmp_service" "$AGENT_SERVICE_UNIT"

    # Write timer unit atomically
    tmp_timer="$(mktemp)"
    printf '%s\n' "$timer_content" > "$tmp_timer"
    mv "$tmp_timer" "$AGENT_TIMER_UNIT"

    # Reload only — the timer is enabled AFTER the probe (SC-2), never with --now.
    systemctl daemon-reload
}

# ---------------------------------------------------------------------------
# enable_timer
#
# Enables the timer WITHOUT --now (SC-2), AFTER the defense-in-depth probe, so
# the probe's claude invocation never races a Persistent=true immediate service
# trigger over the shared /var/lib/osgania-agent tree. Idempotent. The service
# is NOT separately enabled or started during provisioning.
# Spec: HA-06.6, HA-07.3
# ---------------------------------------------------------------------------
enable_timer() {
    systemctl enable osgania-agent.timer
}

# ---------------------------------------------------------------------------
# _classify_bypass_probe <permission_mode>
#
# Pure classifier for the Layer-3 bypass-neutralization oracle (host-safe
# testable). The managed-settings `disableBypassPermissionsMode: "disable"`
# forces the CLI to IGNORE --dangerously-skip-permissions: the stream-json init
# event then reports permissionMode="default" (NOT "bypassPermissions"). Because
# the agent therefore CANNOT enter bypass mode, no Bash tool runs without an
# approval that does not exist in headless `-p` — so the forbidden command can
# never execute (guardia is the second, denylist layer behind that). Sets
# AGENT_PROBE_STATUS and returns 1 ONLY for FAILED. Deterministic,
# model-independent, sandbox-independent (Phase-4: the old two-marker oracle
# could NEVER reach VERIFIED on CLI 2.1.153 — bypass-disabled defers the liveness
# command too, and the model refuses the exfil-shaped prompt).
#   bypassPermissions        → FAILED   (the managed disable did NOT take effect)
#   default/plan/acceptEdits → VERIFIED (bypass neutralized; agent cannot skip perms)
#   <empty>/unknown          → UNVERIFIED (no init event — auth/CLI issue)
# Spec: HA-09.2, HA-09.3
# ---------------------------------------------------------------------------
_classify_bypass_probe() {
    local mode="$1"
    case "$mode" in
        bypassPermissions)
            AGENT_PROBE_STATUS="FAILED"
            return 1
            ;;
        default | plan | acceptEdits)
            AGENT_PROBE_STATUS="VERIFIED"
            ;;
        *)
            AGENT_PROBE_STATUS="UNVERIFIED"
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# run_defense_in_depth_probe
#
# Final active step (ADR-5 amended, Phase-4): proves the Layer-3 OUTER wall holds
# — managed-settings `disableBypassPermissionsMode: "disable"` NEUTRALIZES
# --dangerously-skip-permissions, so the agent stays in permissionMode="default"
# and CANNOT run any Bash tool without an approval that headless `-p` lacks. The
# oracle is the stream-json `init` event's permissionMode (deterministic):
#   permissionMode default/plan/acceptEdits → VERIFIED (bypass neutralized)
#   permissionMode "bypassPermissions"      → FAILED   (managed disable not in effect) → exit non-zero
#   no init event (auth/CLI issue)          → UNVERIFIED (residual, not fatal)
# This replaces the old two-marker oracle, which could NEVER reach VERIFIED on CLI
# 2.1.153: bypass-disabled defers the benign liveness command too, and the model
# refuses the exfil-shaped prompt. guardia's denylist (the inner layer) is verified
# independently by the host-safe guardia.bats matchers.
# Spec: HA-09.1, HA-09.2, HA-09.3, HA-09.4
# ---------------------------------------------------------------------------
run_defense_in_depth_probe() {
    local wrapper="$AGENT_WRAPPER_INSTALLED"
    local claude_bin="${CLAUDE_BIN:-claude}"

    if [[ ! -f "$AGENT_SECRETS_KEY" ]]; then
        AGENT_PROBE_STATUS="UNVERIFIED"
        printf 'provision-agent.sh: Defense-in-depth: UNVERIFIED (key absent at %s — probe could not run)\n' \
            "$AGENT_SECRETS_KEY"
        return 0
    fi
    if ! command -v "$claude_bin" > /dev/null 2>&1; then
        AGENT_PROBE_STATUS="UNVERIFIED"
        printf 'provision-agent.sh: Defense-in-depth: UNVERIFIED (claude CLI not installed — probe could not run)\n'
        return 0
    fi
    if [[ ! -x "$wrapper" ]]; then
        AGENT_PROBE_STATUS="UNVERIFIED"
        printf 'provision-agent.sh: Defense-in-depth: UNVERIFIED (launch wrapper not installed at %s — probe could not run)\n' "$wrapper"
        return 0
    fi

    install -d -o aios -g aios -m 0700 "$AGENT_STATE_DIR"

    # Deliver the key the way the systemd unit does: a private creds dir readable
    # only by aios, mirroring LoadCredential. The wrapper reads $CREDENTIALS_DIRECTORY
    # and exports ANTHROPIC_API_KEY — the production auth path.
    local creds_dir
    creds_dir="$(mktemp -d)"
    cp "$AGENT_SECRETS_KEY" "${creds_dir}/anthropic-api-key"
    chown -R aios:aios "$creds_dir"
    chmod 0700 "$creds_dir"
    chmod 0400 "${creds_dir}/anthropic-api-key"

    # Capture the stream-json init event under --dangerously-skip-permissions and
    # read permissionMode. The benign prompt needs no tool use (the oracle is the
    # init event, not the agent's actions), so model refusal / the CLI bash sandbox
    # / headless permission-deferral cannot confound it. Best-effort; the oracle is
    # the parsed permissionMode, not the exit code.
    local out permission_mode
    out="$(runuser -u aios -- env -i \
        HOME="$AGENT_STATE_DIR" \
        XDG_CONFIG_HOME="$AGENT_STATE_DIR" \
        XDG_CACHE_HOME="$AGENT_STATE_DIR" \
        XDG_DATA_HOME="$AGENT_STATE_DIR" \
        XDG_STATE_HOME="$AGENT_STATE_DIR" \
        CREDENTIALS_DIRECTORY="$creds_dir" \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        "$wrapper" -p --output-format stream-json --verbose --dangerously-skip-permissions 'Reply with the single word: ok' < /dev/null 2> /dev/null || true)"
    rm -rf "$creds_dir"

    permission_mode="$(printf '%s' "$out" | jq -rs '.[] | select(.type == "system" and .subtype == "init") | .permissionMode' 2> /dev/null | head -1)"

    if ! _classify_bypass_probe "$permission_mode"; then
        printf 'provision-agent.sh: Defense-in-depth: FAILED — the CLI honored --dangerously-skip-permissions (permissionMode=%s); managed disableBypassPermissionsMode is NOT in effect (Layer-3 outer wall broken)\n' "$permission_mode" >&2
        return 1
    fi
    if [[ "$AGENT_PROBE_STATUS" == "VERIFIED" ]]; then
        printf 'provision-agent.sh: Defense-in-depth: VERIFIED (--dangerously-skip-permissions neutralized by managed-settings; permissionMode=%s — the agent cannot bypass permissions, so no Bash tool runs without approval)\n' "$permission_mode"
    else
        printf 'provision-agent.sh: Defense-in-depth: UNVERIFIED (no stream-json init event — auth/CLI issue; probe inconclusive)\n'
    fi
}

# ---------------------------------------------------------------------------
# print_summary
#
# Prints the non-secret provisioning summary. Asserts AUDIT_LOG is not set.
# Spec: HA-03.4, HA-08.6, HA-11.1
# ---------------------------------------------------------------------------
print_summary() {
    # Assert AUDIT_LOG is not set (mirrors base R10.2)
    if [[ -n "${AUDIT_LOG+x}" ]]; then
        printf 'provision-agent.sh: FATAL: AUDIT_LOG is set in the environment — must be unset in production\n' >&2
        return 1
    fi

    printf '\n=== Osgania Agent Provisioning Summary (2a) ===\n'
    printf '\nInstalled components:\n'
    printf '  Node.js:       >= 18\n'
    printf '  Claude Code:   %s\n' "${AGENT_CLI_VERSION_RECORDED:-unknown}"
    printf '  CLI pin:       @anthropic-ai/claude-code@%s\n' "$AGENT_CLI_PINNED_VERSION"
    printf '  Client dir:    %s (aios:aios 0700)\n' "$AGENT_CLIENT_WORKSPACE"
    printf '  Launch wrapper:%s (root:root 0755)\n' "$AGENT_WRAPPER_INSTALLED"
    printf '  Service unit:  %s\n' "$AGENT_SERVICE_UNIT"
    printf '  Timer unit:    %s\n' "$AGENT_TIMER_UNIT"
    printf '\nDefense-in-depth probe (bypass neutralization under --dangerously-skip-permissions):\n'
    case "$AGENT_PROBE_STATUS" in
        VERIFIED)
            printf '  Defense-in-depth: VERIFIED (managed disableBypassPermissionsMode neutralized the bypass flag; permissionMode stayed default — no Bash tool runs without approval)\n'
            ;;
        FAILED)
            printf '  Defense-in-depth: FAILED — the CLI honored --dangerously-skip-permissions (permissionMode=bypassPermissions); managed disableBypassPermissionsMode is NOT in effect (hard finding)\n'
            ;;
        *)
            printf '  Defense-in-depth: UNVERIFIED (key absent, CLI/wrapper missing, or no stream-json init event — residual risk)\n'
            ;;
    esac
    printf '\nNote: API key delivery is via ANTHROPIC_API_KEY set by the wrapper from the LoadCredential tmpfs (ADR-6)\n'
    printf 'Note: AUDIT_LOG is not set (confirmed)\n'
    printf '\n========================================\n'
}

# ---------------------------------------------------------------------------
# main <"$@">
#
# Orchestrates the ordered provisioning phases (steps 0-8 per design).
# Spec: HA-14.1, HA-14.3
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # Step 0: Precondition checks (always run, including in --check mode)
    printf 'provision-agent.sh: [0/8] running precondition checks...\n'
    check_preconditions

    if [[ "$CHECK_MODE" -eq 1 ]]; then
        report_plan
        exit 0
    fi

    printf 'provision-agent.sh: starting Osgania 2a agent provisioning...\n'

    # Step 1: Node.js runtime
    printf 'provision-agent.sh: [1/8] ensuring Node.js >= 18...\n'
    install_node

    # Step 2: Claude Code CLI pin
    printf 'provision-agent.sh: [2/8] installing Claude Code CLI at pin %s...\n' \
        "$AGENT_CLI_PINNED_VERSION"
    install_cli

    # Step 3: Client workspace
    printf 'provision-agent.sh: [3/8] creating client workspace...\n'
    create_workspace

    # Step 4: Launch wrapper install (post-pivot: replaces the apiKeyHelper)
    printf 'provision-agent.sh: [4/8] installing launch wrapper (agent-run.sh)...\n'
    install_wrapper

    # Step 5: managed-settings.json read-only verify (post-pivot: NO write)
    printf 'provision-agent.sh: [5/8] verifying managed-settings.json (read-only, R9-R12 intact)...\n'
    local policy_file="${MANAGED_SETTINGS_PATH:-/etc/claude-code/managed-settings.json}"
    verify_managed_settings "$policy_file"

    # Step 6: Write systemd units (write + daemon-reload only; enable AFTER the probe — SC-2)
    printf 'provision-agent.sh: [6/8] writing systemd units...\n'
    write_units

    # Step 7: Defense-in-depth probe (final active step; runs BEFORE the timer is enabled)
    printf 'provision-agent.sh: [7/8] running defense-in-depth probe...\n'
    run_defense_in_depth_probe

    # Step 7.5: Enable the timer WITHOUT --now (after the probe, to avoid the race — SC-2)
    printf 'provision-agent.sh: [7.5/8] enabling timer (no --now)...\n'
    enable_timer

    # Step 8: Summary
    printf 'provision-agent.sh: [8/8] printing summary...\n'
    print_summary

    printf 'provision-agent.sh: 2a provisioning complete.\n'
}

# ---------------------------------------------------------------------------
# Entry point guard — allows bats to `source scripts/provision-agent.sh` and
# test individual functions WITHOUT running the full installer.
# ---------------------------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
