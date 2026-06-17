#!/usr/bin/env bash
# test_helper.bash — shared bats test helper for platform-security-core hooks
#
# Installed versions (as of 2026-06-14):
#   bats-core  1.13.0
#   sc (linter) 0.11.0

# ---------------------------------------------------------------------------
# N1 TRUNCATION RULE — single authoritative definition
#
# The tool_input_summary field for a Bash command is truncated to exactly
# 512 bytes of UTF-8 content (measured on the raw command bytes BEFORE jq
# encoding). When truncation occurs the 512-byte content is followed by the
# marker: …[truncated]
#
#   "…"         = Unicode U+2026 HORIZONTAL ELLIPSIS = 3 bytes in UTF-8
#   "[truncated]" = 11 bytes in ASCII
#   Total marker byte length: 14 bytes
#
# Maximum byte length of tool_input_summary VALUE (unescaped): 526 bytes
#   (512 content bytes + 14 marker bytes)
#
# The truncation cut MUST NOT land in the middle of a multi-byte UTF-8
# sequence. Implementation: head -c 512 on the raw command string, then
# append the marker, then pass to jq for encoding.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# N2 ATOMICITY CAP — single authoritative definition
#
# A single `printf '%s\n' "$record" >> "$AUDIT_LOG"` append is atomic for
# writes below PIPE_BUF (4096 bytes on Linux). To guarantee this:
#
#   session_id  capped at 128 bytes (truncated silently, no marker)
#   tool_name   capped at  64 bytes (truncated silently, no marker)
#
# Combined worst-case audit line: 526 + 128 + 64 + ~135 overhead = ~853 bytes
# Well under PIPE_BUF(4096). The atomicity claim in the spec is therefore
# NOT overstated when these caps are enforced.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AUDIT_LOG temp-file convention
#
# Tests that exercise camara.sh MUST use setup_audit_log / teardown_audit_log
# (or BATS_TMPDIR-scoped temp file pattern) so they never touch the production
# log path /var/log/osgania/audit.jsonl.
#
# camara.sh reads AUDIT_LOG from the environment. Exporting AUDIT_LOG before
# invoking camara.sh redirects all audit writes to the test temp file.
#
# Future camara tests: use the helpers below in bats setup()/teardown().
# ---------------------------------------------------------------------------

# send_stdin_to_hook <json_string> <hook_path>
#
# Pipes the JSON string to the hook script via STDIN and captures:
#   HOOK_OUTPUT  — combined stdout of the hook
#   HOOK_STATUS  — exit code of the hook
#
# Usage:
#   send_stdin_to_hook '{"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s1"}' \
#       platform/hooks/guardia.sh
#   assert_equal "$HOOK_STATUS" "0"
send_stdin_to_hook() {
    local json="$1"
    local hook="$2"
    # shellcheck disable=SC2034
    HOOK_OUTPUT="$(printf '%s' "$json" | "$hook" 2>/dev/null)"
    # shellcheck disable=SC2034
    HOOK_STATUS="$?"
}

# send_stdin_to_hook_with_stderr <json_string> <hook_path>
#
# Like send_stdin_to_hook but also captures stderr separately.
#   HOOK_OUTPUT  — stdout
#   HOOK_STDERR  — stderr
#   HOOK_STATUS  — exit code
send_stdin_to_hook_with_stderr() {
    local json="$1"
    local hook="$2"
    local stderr_tmp
    stderr_tmp="$(mktemp)"
    # shellcheck disable=SC2034
    HOOK_OUTPUT="$(printf '%s' "$json" | "$hook" 2>"$stderr_tmp")"
    # shellcheck disable=SC2034
    HOOK_STATUS="$?"
    # shellcheck disable=SC2034
    HOOK_STDERR="$(cat "$stderr_tmp")"
    rm -f "$stderr_tmp"
}

# setup_audit_log
#
# Creates a BATS_TMPDIR-scoped temp file and exports AUDIT_LOG pointing to it.
# Call this in bats setup() for camara test files.
setup_audit_log() {
    AUDIT_LOG="$(mktemp "${BATS_TMPDIR}/camara_audit_XXXXXX.jsonl")"
    export AUDIT_LOG
}

# teardown_audit_log
#
# Unsets AUDIT_LOG and removes the temp file.
# Call this in bats teardown() for camara test files.
teardown_audit_log() {
    if [[ -n "${AUDIT_LOG:-}" && -f "$AUDIT_LOG" ]]; then
        rm -f "$AUDIT_LOG"
    fi
    unset AUDIT_LOG
}

# count_audit_lines
#
# Counts non-empty lines in $AUDIT_LOG.
# Prints the count to stdout (always a single integer, even when file is empty).
count_audit_lines() {
    # grep -c returns exit 1 when there are no matches AND still prints "0",
    # so we must not use || here (that would append a second "0"). Instead,
    # capture stdout and suppress the non-zero exit with `|| true`.
    grep -c . "$AUDIT_LOG" 2>/dev/null || true
    # If the file is missing or truly empty, grep outputs nothing; print 0.
    # Handled above: grep always prints a count line on success or failure.
    # The `|| true` keeps pipefail from aborting, and grep still prints "0".
}

# parse_audit_last_line [-r] [jq_filter]
#
# Reads the last non-empty line of $AUDIT_LOG and pipes it through jq -e.
# Accepts an optional -r flag (raw output) before the filter.
# If jq_filter is omitted, '.' is used.
# Returns the jq exit code.
# Output is written to stdout.
parse_audit_last_line() {
    local raw_flag=""
    local filter="."
    if [[ "${1:-}" == "-r" ]]; then
        raw_flag="-r"
        filter="${2:-.}"
    elif [[ $# -gt 0 ]]; then
        filter="$1"
    fi
    # shellcheck disable=SC2086
    tail -n 1 "$AUDIT_LOG" | jq -e $raw_flag "$filter"
}

# assert_decision <expected_decision> <hook_output>
#
# Asserts that HOOK_OUTPUT contains permissionDecision == expected_decision.
# Uses jq to parse; fails the test if not found.
assert_decision() {
    local expected="$1"
    local output="$2"
    local actual
    actual="$(printf '%s' "$output" | jq -r '.hookSpecificOutput.permissionDecision' 2>/dev/null)"
    if [[ "$actual" != "$expected" ]]; then
        echo "Expected permissionDecision='$expected', got='$actual'"
        echo "Hook output: $output"
        return 1
    fi
}

# assert_reason_contains <substring> <hook_output>
#
# Asserts that permissionDecisionReason in HOOK_OUTPUT contains the substring.
assert_reason_contains() {
    local substring="$1"
    local output="$2"
    local reason
    reason="$(printf '%s' "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason' 2>/dev/null)"
    if [[ "$reason" != *"$substring"* ]]; then
        echo "Expected reason to contain '$substring', got: '$reason'"
        echo "Hook output: $output"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# skip_unless_linux_root_mutation
#
# Guard for bats tests that require real Linux root + a disposable ext4 target.
# These tests mutate OS state (useradd, chattr, stat perms, lsattr) and MUST
# NOT run on a developer macOS machine or any non-disposable system.
#
# Usage (in @test body, as the very first statement):
#   skip_unless_linux_root_mutation
#
# The test will be skipped (not failed) unless ALL three conditions hold:
#   1. Running on Linux (uname == "Linux")
#   2. Running as root (EUID == 0)
#   3. PROVISION_TEST_ALLOW_MUTATION=1 is explicitly set in the environment
#
# To run these tests on a disposable Ubuntu 24.04/26.04 VM or container:
#   sudo PROVISION_TEST_ALLOW_MUTATION=1 bats tests/
#
# The container MUST have --cap-add LINUX_IMMUTABLE on an ext4 volume (NOT
# the default overlayfs — chattr +a is a silent no-op on overlayfs, making
# PV-13, PV-27 meaningless).
# ---------------------------------------------------------------------------
skip_unless_linux_root_mutation() {
    if [[ "$(uname)" != "Linux" || "$EUID" -ne 0 || "${PROVISION_TEST_ALLOW_MUTATION:-0}" != "1" ]]; then
        skip "requires Linux root + PROVISION_TEST_ALLOW_MUTATION=1"
    fi
}

# ---------------------------------------------------------------------------
# deprovision_aios_state
#
# Removes ALL OS state a provision.sh run creates, so a mutating test can start
# from a clean slate. provision.sh mutates real, persistent OS state (the aios
# user/group, /opt/osgania, /etc/osgania, the managed-settings policy, and the
# chattr +a audit log). bats has no rollback for that, so without an explicit
# reset the mutating tests pollute each other — e.g. PV-01 leaves aios holding
# UID/GID 9001, which makes the PV-03/PV-04 collision setup impossible (the
# colliding account cannot claim an already-taken 9001).
#
# Only safe on a disposable Linux box. Callers MUST run
# skip_unless_linux_root_mutation first (so we already know we are Linux + root
# with mutation explicitly allowed). Every step is best-effort.
# ---------------------------------------------------------------------------
deprovision_aios_state() {
    # The audit log is chattr +a — clear the append-only attribute before rm.
    chattr -a /var/log/osgania/audit.jsonl 2>/dev/null || true
    rm -rf /var/log/osgania /opt/osgania /etc/osgania 2>/dev/null || true
    rm -f /etc/claude-code/managed-settings.json 2>/dev/null || true
    userdel aios 2>/dev/null || true
    groupdel aios 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# skip_unless_live_key
#
# Guard for bats tests that require a real Anthropic API key at the secrets
# path AND LIVE_KEY_AVAILABLE=1 is set in the environment.
#
# Usage (in @test body, as the very first statement):
#   skip_unless_live_key
#
# The test will be skipped unless ALL conditions hold:
#   1. Running on Linux as root with PROVISION_TEST_ALLOW_MUTATION=1 (Linux-root gate)
#   2. LIVE_KEY_AVAILABLE=1 is set in the environment
#   3. /etc/osgania/secrets/anthropic-api-key exists and is a regular file
#
# To run these tests:
#   sudo PROVISION_TEST_ALLOW_MUTATION=1 LIVE_KEY_AVAILABLE=1 bats tests/
# ---------------------------------------------------------------------------
skip_unless_live_key() {
    if [[ "$(uname)" != "Linux" || "$EUID" -ne 0 || "${PROVISION_TEST_ALLOW_MUTATION:-0}" != "1" ]]; then
        skip "requires Linux root + PROVISION_TEST_ALLOW_MUTATION=1 (live-key tier)"
    fi
    if [[ "${LIVE_KEY_AVAILABLE:-0}" != "1" ]]; then
        skip "requires live API key at /etc/osgania/secrets/anthropic-api-key (UNVERIFIED)"
    fi
    if [[ ! -f /etc/osgania/secrets/anthropic-api-key ]]; then
        skip "requires live API key at /etc/osgania/secrets/anthropic-api-key (UNVERIFIED)"
    fi
}

# ---------------------------------------------------------------------------
# deprovision_agent_state
#
# Best-effort teardown of 2a state: uninstall Claude CLI, disable/remove systemd
# units, remove installed files. MUST be called only after skip_unless_linux_root_mutation
# to ensure we are on a disposable Linux box with root access.
# Satisfies: test isolation for HA-10-S1, HA-10-S2 idempotency tests.
# ---------------------------------------------------------------------------
deprovision_agent_state() {
    # Disable and stop systemd units before removing files
    systemctl disable --now osgania-agent.timer osgania-agent.service 2>/dev/null || true
    # Remove unit files and reload
    rm -f /etc/systemd/system/osgania-agent.service \
          /etc/systemd/system/osgania-agent.timer 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    # Uninstall the global CLI
    npm uninstall -g @anthropic-ai/claude-code 2>/dev/null || true
    # Remove the client workspace and the launch wrapper
    rm -rf /opt/osgania/client 2>/dev/null || true
    rm -f /opt/osgania/platform/bin/agent-run.sh 2>/dev/null || true
    # Post-pivot (ADR-6): 2a no longer modifies managed-settings.json, so there
    # is no apiKeyHelper key to strip on teardown. Leave the policy untouched.
}

# ---------------------------------------------------------------------------
# load_managed_settings_fixture
#
# Copies platform/managed-settings.json (the Slice-1 template in the repo) into
# a temp file under BATS_TMPDIR and exports MANAGED_SETTINGS_FIXTURE pointing to
# it. Callable from HOST-SAFE tests without touching the live box file.
# Satisfies: HA-05-S2, HA-05-S3, HA-05-S4.
#
# Usage:
#   load_managed_settings_fixture    # in test setup or at top of @test body
#   # Then use "$MANAGED_SETTINGS_FIXTURE" instead of the real settings path
# ---------------------------------------------------------------------------
load_managed_settings_fixture() {
    local repo_root
    # Resolve repo root relative to this helper file (tests/ -> parent)
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    local src="${repo_root}/platform/managed-settings.json"
    if [[ ! -f "$src" ]]; then
        echo "load_managed_settings_fixture: source not found: $src" >&2
        return 1
    fi
    MANAGED_SETTINGS_FIXTURE="${BATS_TMPDIR}/managed-settings-fixture.json"
    cp "$src" "$MANAGED_SETTINGS_FIXTURE"
    export MANAGED_SETTINGS_FIXTURE
}
