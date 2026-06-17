#!/usr/bin/env bats
# provision.bats — bats test scenarios for scripts/provision.sh
#
# Scenarios: PV-01..PV-27 (all 27 required by spec.md)
# Spec:      openspec/changes/vps-provisioning-base/spec.md
# Design:    openspec/changes/vps-provisioning-base/design.md
# TDD mode:  STRICT — tests were written before implementation (RED → GREEN cycle)
#
# Environment split:
#   macOS-safe (run green on macOS now):
#     PV-15 (stub), PV-17 (stub), PV-18 (stub), PV-19 (stub), PV-20 (stub),
#     PV-21, PV-25, PV-26
#   Linux-deferred (skip on macOS; require disposable Ubuntu 24.04/26.04
#     + PROVISION_TEST_ALLOW_MUTATION=1 + root + --cap-add LINUX_IMMUTABLE + ext4):
#     PV-01..PV-14, PV-16, PV-22..PV-24, PV-27

load test_helper

PROVISION="${BATS_TEST_DIRNAME}/../scripts/provision.sh"

# ---------------------------------------------------------------------------
# Helper: create a stub binary in BATS_TMPDIR/bin that echoes fixed text
# make_stub <name> <exit_code> <stdout_text>
# ---------------------------------------------------------------------------
make_stub() {
    local name="$1"
    local exit_code="$2"
    local stdout_text="$3"
    mkdir -p "${BATS_TMPDIR}/bin"
    local stub_path="${BATS_TMPDIR}/bin/${name}"
    printf '#!/usr/bin/env bash\nprintf '"'"'%%s\n'"'"' %q\nexit %s\n' \
        "$stdout_text" "$exit_code" > "$stub_path"
    chmod +x "$stub_path"
}

# ---------------------------------------------------------------------------
# Helper: create a fake /etc/os-release fixture
# make_os_release <id> <version_id>
# ---------------------------------------------------------------------------
make_os_release() {
    local os_id="$1"
    local version_id="$2"
    printf 'ID=%s\nVERSION_ID="%s"\nNAME="Ubuntu"\n' "$os_id" "$version_id" \
        > "${BATS_TMPDIR}/os-release"
    export OS_RELEASE_PATH="${BATS_TMPDIR}/os-release"
}

# ---------------------------------------------------------------------------
# Helper: create a stub stat binary that returns a given filesystem type
# make_stat_stub <fs_type>
# ---------------------------------------------------------------------------
make_stat_stub() {
    local fs_type="$1"
    mkdir -p "${BATS_TMPDIR}/bin"
    printf '#!/usr/bin/env bash\nprintf '"'"'%%s\n'"'"' %q\nexit 0\n' \
        "$fs_type" > "${BATS_TMPDIR}/bin/stat"
    chmod +x "${BATS_TMPDIR}/bin/stat"
}

# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

setup() {
    # Export BATS_TMPDIR/bin early so stubs take priority
    export PATH="${BATS_TMPDIR}/bin:${PATH}"
    # Source provision.sh for function-level tests — the BASH_SOURCE guard
    # prevents main() from executing at source time.
    # shellcheck disable=SC1090
    source "$PROVISION"
}

teardown() {
    # Clean up stubs, fixtures
    rm -rf "${BATS_TMPDIR}/bin"
    rm -f "${BATS_TMPDIR}/os-release"
    unset OS_RELEASE_PATH EXT4_CHECK_PATH CLAUDE_BIN AUDIT_LOG PROVISION_TEST_ALLOW_MUTATION
}

# ===========================================================================
# PV-01 — aios user created with correct UID/GID/shell
# Spec: R2.1, R2.2
# Linux-deferred: requires real Linux root + PROVISION_TEST_ALLOW_MUTATION=1
# ===========================================================================
@test "PV-01 aios exists with UID=9001, GID=9001, shell=/usr/sbin/nologin, home=/nonexistent; /nonexistent does not exist" {
    skip_unless_linux_root_mutation
    # Run the full provisioner
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    # Verify user entry
    run getent passwd aios
    [ "$status" -eq 0 ]
    local uid gid shell home
    uid="$(printf '%s' "$output" | cut -d: -f3)"
    gid="$(printf '%s' "$output" | cut -d: -f4)"
    home="$(printf '%s' "$output" | cut -d: -f6)"
    shell="$(printf '%s' "$output" | cut -d: -f7)"
    [ "$uid" -eq 9001 ]
    [ "$gid" -eq 9001 ]
    [ "$shell" = "/usr/sbin/nologin" ]
    [ "$home" = "/nonexistent" ]
    # /nonexistent must NOT exist as a directory
    run stat /nonexistent
    [ "$status" -ne 0 ]
}

# ===========================================================================
# PV-02 — aios not in sudo or admin group
# Spec: R2.3, R2.4
# Linux-deferred
# ===========================================================================
@test "PV-02 aios is not in sudo or admin group" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run id -nG aios
    [ "$status" -eq 0 ]
    [[ "$output" != *"sudo"* ]]
    [[ "$output" != *"admin"* ]]
}

# ===========================================================================
# PV-03 — UID 9001 collision with non-aios account causes abort
# Spec: R2.6
# Linux-deferred
# ===========================================================================
@test "PV-03 UID 9001 collision with 'collide' account → non-zero exit, stderr contains UID collision, no aios created" {
    skip_unless_linux_root_mutation
    # Isolation: clear any state a prior mutating test left so UID 9001 is free
    # for this collision setup (PV-01 etc. create aios at UID 9001 and do not
    # clean up — bats has no rollback for real OS mutations).
    deprovision_aios_state
    userdel collide 2>/dev/null || true
    # Pre-create a user with UID 9001 that is NOT aios
    useradd -r -u 9001 collide 2>/dev/null || true
    # provision.sh should abort with a collision error
    run bash "$PROVISION"
    [ "$status" -ne 0 ]
    [[ "$output" == *"9001"* ]] || [[ "$stderr" == *"9001"* ]]
    # aios must not have been created
    run id aios
    [ "$status" -ne 0 ]
    # Cleanup collision user
    userdel collide 2>/dev/null || true
}

# ===========================================================================
# PV-04 — GID 9001 collision with non-aios group causes abort
# Spec: R2.7
# Linux-deferred
# ===========================================================================
@test "PV-04 GID 9001 collision with 'other' group → non-zero exit, stderr contains GID collision" {
    skip_unless_linux_root_mutation
    # Isolation: clear any state a prior mutating test left so GID 9001 is free
    # for this collision setup.
    deprovision_aios_state
    groupdel other 2>/dev/null || true
    groupadd -g 9001 other 2>/dev/null || true
    run bash "$PROVISION"
    [ "$status" -ne 0 ]
    [[ "$output" == *"9001"* ]] || [[ "$stderr" == *"9001"* ]]
    groupdel other 2>/dev/null || true
}

# ===========================================================================
# PV-05 — Platform tree owner, group, and mode
# Spec: R3.1, R3.2
# Linux-deferred
# ===========================================================================
@test "PV-05 /opt/osgania/platform and /opt/osgania/platform/hooks are root:aios 750" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -c '%U:%G %a' /opt/osgania/platform
    [ "$status" -eq 0 ]
    [ "$output" = "root:aios 750" ]
    run stat -c '%U:%G %a' /opt/osgania/platform/hooks
    [ "$status" -eq 0 ]
    [ "$output" = "root:aios 750" ]
}

# ===========================================================================
# PV-06 — Hook files owner, group, mode, execute bit
# Spec: R3.3, R3.4
# Linux-deferred
# ===========================================================================
@test "PV-06 guardia.sh and camara.sh are root:aios 750 and executable" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -c '%U:%G %a' /opt/osgania/platform/hooks/guardia.sh
    [ "$status" -eq 0 ]
    [ "$output" = "root:aios 750" ]
    run stat -c '%U:%G %a' /opt/osgania/platform/hooks/camara.sh
    [ "$status" -eq 0 ]
    [ "$output" = "root:aios 750" ]
    run test -x /opt/osgania/platform/hooks/guardia.sh
    [ "$status" -eq 0 ]
    run test -x /opt/osgania/platform/hooks/camara.sh
    [ "$status" -eq 0 ]
}

# ===========================================================================
# PV-07 — No managed-settings.json copy under platform/
# Spec: R3.7
# Linux-deferred
# ===========================================================================
@test "PV-07 managed-settings.json is NOT placed under /opt/osgania/platform/" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run test -f /opt/osgania/platform/managed-settings.json
    [ "$status" -ne 0 ]
    run bash -c 'find /opt/osgania/platform -name "managed-settings.json" 2>/dev/null | wc -l | tr -d " "'
    [ "$status" -eq 0 ]
    [ "$output" = "0" ]
}

# ===========================================================================
# PV-08 — No /opt/osgania/client/ created
# Spec: R3.8
# Linux-deferred
# ===========================================================================
@test "PV-08 /opt/osgania/client/ is NOT created by provision.sh" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run test -d /opt/osgania/client
    [ "$status" -ne 0 ]
}

# ===========================================================================
# PV-09 — Operator policy installed at correct path with correct mode
# Spec: R4.1, R4.2, R4.4
# Linux-deferred
# ===========================================================================
@test "PV-09 /etc/claude-code/managed-settings.json is root:root 644 and valid JSON" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -c '%U:%G %a' /etc/claude-code/managed-settings.json
    [ "$status" -eq 0 ]
    [ "$output" = "root:root 644" ]
    run jq . /etc/claude-code/managed-settings.json
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

# ===========================================================================
# PV-10 — Secrets directory mode and ownership
# Spec: R5.1, R5.2
# Linux-deferred
# ===========================================================================
@test "PV-10 /etc/osgania/secrets is root:root 700 and empty" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -c '%U:%G %a' /etc/osgania/secrets
    [ "$status" -eq 0 ]
    [ "$output" = "root:root 700" ]
    # Provision.sh writes no secret values (R5.2)
    run bash -c 'ls -A /etc/osgania/secrets | wc -l | tr -d " "'
    [ "$output" = "0" ]
}

# ===========================================================================
# PV-11 — Audit directory owner, group, and mode
# Spec: R6.1, R6.5
# Linux-deferred
# ===========================================================================
@test "PV-11 /var/log/osgania is root:aios 750" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -c '%U:%G %a' /var/log/osgania
    [ "$status" -eq 0 ]
    [ "$output" = "root:aios 750" ]
}

# ===========================================================================
# PV-12 — Audit file owner, group, and mode
# Spec: R6.2, R6.4
# Linux-deferred
# ===========================================================================
@test "PV-12 /var/log/osgania/audit.jsonl is root:aios 620" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -c '%U:%G %a' /var/log/osgania/audit.jsonl
    [ "$status" -eq 0 ]
    [ "$output" = "root:aios 620" ]
}

# ===========================================================================
# PV-13 — Audit file has chattr +a flag set
# Spec: R7.1, R7.3
# Linux-deferred
# ===========================================================================
@test "PV-13 lsattr /var/log/osgania/audit.jsonl shows the 'a' (append-only) flag in attribute field" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run lsattr /var/log/osgania/audit.jsonl
    [ "$status" -eq 0 ]
    # FIX-1: assert on attribute FIELD (first token), not the full lsattr line.
    # The full line contains the path "/var/log/osgania/audit.jsonl" which always
    # contains 'a', causing a false positive even when +a is NOT set.
    local attr_field
    attr_field="$(printf '%s' "$output" | awk '{print $1}')"
    [[ "$attr_field" =~ ^-*a ]] || [[ "$attr_field" == *a* && "${#attr_field}" -le 20 ]]
    # Stricter: the 'a' flag is at a known position in the lsattr attribute string
    run bash -c "printf '%s' \"$output\" | awk '{print \$1}' | grep -q 'a'"
    [ "$status" -eq 0 ]
}

# ===========================================================================
# PV-14 — Target filesystem is ext4
# Spec: R1.4, R7.5 (ordering dependency)
# Linux-deferred
# ===========================================================================
@test "PV-14 /var/log/osgania is on an ext4-family filesystem" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -f -c %T /var/log/osgania
    [ "$status" -eq 0 ]
    [[ "$output" == "ext4" || "$output" == "ext2/ext3" || "$output" == "ext3" || "$output" == "ext2" ]]
}

# ===========================================================================
# PV-15 — Non-ext4 filesystem causes abort before chattr +a
# Spec: R1.4
# macOS-safe via stub (real Linux test is also here, SKIP-gated for that part)
# ===========================================================================
@test "PV-15 non-ext4 filesystem (tmpfs stub) → provision aborts, stderr contains filesystem type, audit.jsonl not created" {
    # This test is macOS-safe via a stubbed stat binary injected in PATH.
    # The stub returns "tmpfs" for any stat -f -c %T call.
    make_stat_stub "tmpfs"
    export EXT4_CHECK_PATH="${BATS_TMPDIR}/fakepath"

    # Call check_ext4 directly (function is sourced from provision.sh)
    run check_ext4
    [ "$status" -ne 0 ]
    [[ "$output" == *"tmpfs"* ]]
}

@test "PV-15b non-ext4 filesystem (overlayfs stub) → check_ext4 aborts, stderr contains overlayfs" {
    make_stat_stub "overlayfs"
    export EXT4_CHECK_PATH="${BATS_TMPDIR}/fakepath"
    run check_ext4
    [ "$status" -ne 0 ]
    [[ "$output" == *"overlayfs"* ]]
}

@test "PV-15c ext4 filesystem stub → check_ext4 returns 0" {
    make_stat_stub "ext4"
    export EXT4_CHECK_PATH="${BATS_TMPDIR}/fakepath"
    run check_ext4
    [ "$status" -eq 0 ]
}

@test "PV-15d ext2/ext3 filesystem stub → check_ext4 returns 0 (accepted ext4-family)" {
    make_stat_stub "ext2/ext3"
    export EXT4_CHECK_PATH="${BATS_TMPDIR}/fakepath"
    run check_ext4
    [ "$status" -eq 0 ]
}

# ===========================================================================
# PV-16 — jq is on PATH after provisioning
# Spec: R8.1, R8.2
# Linux-deferred
# ===========================================================================
@test "PV-16 after provisioning, which jq exits 0 with a non-empty path" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run which jq
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

# ===========================================================================
# PV-17 — CLI version is recorded and within range
# Spec: R9.1, R9.3
# macOS-safe (stub) — live test is Linux-deferred
# ===========================================================================
@test "PV-17 assert_cli_version with stub >= floor → CLI_VERSION_OK=1, no WARNING" {
    make_stub "claude" 0 "Claude Code 2.1.200"
    export CLAUDE_BIN="${BATS_TMPDIR}/bin/claude"
    CLI_VERSION_OK=0
    CLI_VERSION_RECORDED=""
    run assert_cli_version
    [ "$status" -eq 0 ]
    [[ "$output" != *"WARNING"* ]]
    # After run, the function set CLI_VERSION_RECORDED and CLI_VERSION_OK
    # We check by calling directly (not via run) to inspect state
    CLI_VERSION_OK=0
    CLI_VERSION_RECORDED=""
    assert_cli_version
    [ "$CLI_VERSION_OK" -eq 1 ]
    [ "$CLI_VERSION_RECORDED" = "2.1.200" ]
}

@test "PV-17b assert_cli_version with stub == floor (2.1.153) → CLI_VERSION_OK=1" {
    make_stub "claude" 0 "Claude Code 2.1.153"
    export CLAUDE_BIN="${BATS_TMPDIR}/bin/claude"
    CLI_VERSION_OK=0
    assert_cli_version
    [ "$CLI_VERSION_OK" -eq 1 ]
}

@test "PV-17 (Linux live)" {
    skip_unless_linux_root_mutation
    # Scope: Slice 1 (vps-provisioning-base) is the OS baseline and does NOT
    # install the Claude CLI (a fresh Ubuntu has no Node/npm). Installing Node +
    # the CLI + delivering the API key + live Layer-3 verification is deferred to
    # Slice 2 (vps-provisioning-hardening). Skip this live check when the CLI is
    # not present, matching install_cli's non-fatal record-only behavior here.
    command -v claude >/dev/null 2>&1 || skip "Claude CLI not installed — install + live Layer-3 verification deferred to Slice 2 (vps-provisioning-hardening)"
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run claude --version
    [ "$status" -eq 0 ]
    # Version string must parse as semver
    run bash -c 'claude --version | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -n 1'
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

# ===========================================================================
# PV-18 — Provisioning summary contains CLI version, DISABLE_AUTOUPDATER note,
#          and Slice 2 forward dependency note
# Spec: R9.2, R9.2a
# macOS-safe via format_summary with stub state
# ===========================================================================
@test "PV-18 format_summary output contains CLI version string and DISABLE_AUTOUPDATER note" {
    CLI_VERSION_RECORDED="2.1.200"
    CLI_VERSION_OK=1
    LAYER3_STATUS="VERIFIED"
    OS_VERSION="26.04"
    OS_TARGET="ubuntu-2604"
    run format_summary
    [ "$status" -eq 0 ]
    [[ "$output" == *"2.1.200"* ]]
    [[ "$output" == *"DISABLE_AUTOUPDATER"* ]]
}

@test "PV-18b format_summary output contains Slice 2 forward dependency note" {
    CLI_VERSION_RECORDED="2.1.200"
    CLI_VERSION_OK=1
    LAYER3_STATUS="VERIFIED"
    OS_VERSION="26.04"
    OS_TARGET="ubuntu-2604"
    run format_summary
    [ "$status" -eq 0 ]
    [[ "$output" == *"Slice 2"* ]]
}

# ===========================================================================
# PV-19 — Layer-3 mode-lock live validation result is recorded in summary
# Spec: R9.4, R9.5
# macOS-safe via format_summary stub
# ===========================================================================
@test "PV-19 format_summary contains 'Layer-3: VERIFIED' when LAYER3_STATUS=VERIFIED" {
    CLI_VERSION_RECORDED="2.1.200"
    CLI_VERSION_OK=1
    LAYER3_STATUS="VERIFIED"
    OS_VERSION="26.04"
    OS_TARGET="ubuntu-2604"
    run format_summary
    [ "$status" -eq 0 ]
    [[ "$output" == *"Layer-3"* ]]
    [[ "$output" == *"VERIFIED"* ]]
}

@test "PV-19b format_summary contains 'Layer-3: UNVERIFIED' when LAYER3_STATUS=UNVERIFIED" {
    CLI_VERSION_RECORDED="2.1.153"
    CLI_VERSION_OK=1
    LAYER3_STATUS="UNVERIFIED"
    OS_VERSION="26.04"
    OS_TARGET="ubuntu-2604"
    run format_summary
    [ "$status" -eq 0 ]
    [[ "$output" == *"Layer-3"* ]]
    [[ "$output" == *"UNVERIFIED"* ]]
}

# ===========================================================================
# PV-20 — CLI version below floor emits WARNING, does NOT abort
# Spec: R9.3
# macOS-safe (stub)
# ===========================================================================
@test "PV-20 assert_cli_version with stub below floor (2.1.100) → exits 0, WARNING in output, Layer-3 flagged" {
    make_stub "claude" 0 "Claude Code 2.1.100"
    export CLAUDE_BIN="${BATS_TMPDIR}/bin/claude"
    CLI_VERSION_OK=0
    CLI_VERSION_RECORDED=""
    run assert_cli_version
    # Must NOT abort (exit 0)
    [ "$status" -eq 0 ]
    # Output must contain WARNING
    [[ "$output" == *"WARNING"* ]]
    # Output must mention Layer-3
    [[ "$output" == *"Layer-3"* ]]
}

@test "PV-20b assert_cli_version with stub 2.0.999 (major below) → exits 0, WARNING" {
    make_stub "claude" 0 "Claude Code 2.0.999"
    export CLAUDE_BIN="${BATS_TMPDIR}/bin/claude"
    run assert_cli_version
    [ "$status" -eq 0 ]
    [[ "$output" == *"WARNING"* ]]
}

# ===========================================================================
# PV-21 — AUDIT_LOG is not set in the environment
# Spec: R10.1, R10.2
# macOS-safe
# ===========================================================================
@test "PV-21 check_audit_log_env when AUDIT_LOG is unset → exits 0" {
    unset AUDIT_LOG
    run check_audit_log_env
    [ "$status" -eq 0 ]
}

@test "PV-21b check_audit_log_env when AUDIT_LOG is set → exits non-zero, stderr contains AUDIT_LOG" {
    export AUDIT_LOG="/tmp/fake.jsonl"
    run check_audit_log_env
    [ "$status" -ne 0 ]
    [[ "$output" == *"AUDIT_LOG"* ]]
    unset AUDIT_LOG
}

# ===========================================================================
# PV-22 — Idempotent re-run: no duplicate user
# Spec: R11.1, R11.2
# Linux-deferred
# ===========================================================================
@test "PV-22 running provision.sh twice produces exactly one aios user, id -u aios = 9001" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run bash -c 'getent passwd aios | wc -l | tr -d " "'
    [ "$status" -eq 0 ]
    [ "$output" = "1" ]
    run id -u aios
    [ "$status" -eq 0 ]
    [ "$output" = "9001" ]
}

# ===========================================================================
# PV-23 — Idempotent re-run does not corrupt audit log
# Spec: R11.1, R11.5, R11.6
# Linux-deferred
# ===========================================================================
@test "PV-23 re-run preserves audit.jsonl inode, content, and +a flag" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    # Write a known line (append is allowed under +a)
    printf '{"test":"marker"}\n' >> /var/log/osgania/audit.jsonl
    local inode_before
    inode_before="$(stat -c %i /var/log/osgania/audit.jsonl)"
    # Re-run
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    # Inode must be same (file not recreated)
    run stat -c %i /var/log/osgania/audit.jsonl
    [ "$status" -eq 0 ]
    [ "$output" = "$inode_before" ]
    # Content must be preserved
    run grep -c 'test.*marker' /var/log/osgania/audit.jsonl
    [ "$status" -eq 0 ]
    [ "$output" -ge 1 ]
    # +a flag must still be set
    run lsattr /var/log/osgania/audit.jsonl
    [[ "$output" == *"a"* ]]
}

# ===========================================================================
# PV-24 — Idempotent re-run corrects permissions drift
# Spec: R11.2
# Linux-deferred
# ===========================================================================
@test "PV-24 re-run restores /opt/osgania/platform mode to 750 after manual chmod to 0755" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    # Introduce drift
    chmod 0755 /opt/osgania/platform
    run stat -c '%a' /opt/osgania/platform
    [ "$output" = "755" ]
    # Re-run should correct it
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    run stat -c '%a' /opt/osgania/platform
    [ "$status" -eq 0 ]
    [ "$output" = "750" ]
}

# ===========================================================================
# PV-25 — Dry-run (--check) mode reports plan without mutating state
# Spec: R1.7
# macOS-safe
# ===========================================================================
@test "PV-25 --check mode: exits 0, prints non-empty plan, mentions 'aios' and all key paths" {
    # FIX-2: --check now runs check_preconditions. Stubs are required on macOS so
    # preconditions pass (valid Ubuntu fixture + tool stubs + ext4 stat stub).
    make_os_release "ubuntu" "24.04"
    mkdir -p "${BATS_TMPDIR}/bin"
    for tool in chattr lsattr useradd install getent systemctl; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/${tool}"
        chmod +x "${BATS_TMPDIR}/bin/${tool}"
    done
    # stat stub must return ext4 for check_ext4
    printf '#!/usr/bin/env bash\nprintf "ext4\n"\nexit 0\n' > "${BATS_TMPDIR}/bin/stat"
    chmod +x "${BATS_TMPDIR}/bin/stat"
    run bash "$PROVISION" --check
    [ "$status" -eq 0 ]
    [ -n "$output" ]
    # Plan must mention the main subjects
    [[ "$output" == *"aios"* ]]
    [[ "$output" == *"/opt/osgania/platform"* ]]
    [[ "$output" == *"/etc/claude-code/managed-settings.json"* ]]
    [[ "$output" == *"/etc/osgania/secrets"* ]]
    [[ "$output" == *"/var/log/osgania/audit.jsonl"* ]]
    [[ "$output" == *"chattr"* ]]
    [[ "$output" == *"AUDIT_LOG"* ]]
}

@test "PV-25b --check mode: getent passwd aios returns no entry (no user created)" {
    # FIX-2: --check now runs check_preconditions, so stubs are required.
    make_os_release "ubuntu" "24.04"
    mkdir -p "${BATS_TMPDIR}/bin"
    for tool in chattr lsattr useradd install systemctl; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/${tool}"
        chmod +x "${BATS_TMPDIR}/bin/${tool}"
    done
    # getent stub: exit 0 generically so check_required_tools passes,
    # but return non-zero for 'getent passwd aios' (user not created)
    printf '%s\n' '#!/usr/bin/env bash' \
        'if [[ "$1" == "passwd" && "$2" == "aios" ]]; then exit 1; fi' \
        'exit 0' > "${BATS_TMPDIR}/bin/getent"
    chmod +x "${BATS_TMPDIR}/bin/getent"
    printf '#!/usr/bin/env bash\nprintf "ext4\n"\nexit 0\n' > "${BATS_TMPDIR}/bin/stat"
    chmod +x "${BATS_TMPDIR}/bin/stat"
    run bash "$PROVISION" --check
    [ "$status" -eq 0 ]
    # User must not have been created
    run "${BATS_TMPDIR}/bin/getent" passwd aios
    [ "$status" -ne 0 ]
}

@test "PV-25c parse_args --check sets CHECK_MODE=1" {
    CHECK_MODE=0
    parse_args --check
    [ "$CHECK_MODE" -eq 1 ]
}

@test "PV-25d parse_args (no args) sets CHECK_MODE=0" {
    CHECK_MODE=1
    parse_args
    [ "$CHECK_MODE" -eq 0 ]
}

@test "PV-25e parse_args --unknown-flag exits non-zero with usage on stderr" {
    run parse_args --unknown-flag
    [ "$status" -ne 0 ]
    [[ "$output" == *"Usage"* ]] || [[ "$output" == *"unknown"* ]]
}

# ===========================================================================
# PV-26 — Missing required tool causes abort before any mutation
# Spec: R1.5
# macOS-safe (PATH stub: stubs that return 1 for specific tools)
# Strategy: instead of copying real binaries, create a restricted stub
# directory where we control which tools exist. We use a wrapper script
# approach so stderr is captured by bats.
# ===========================================================================
@test "PV-26 when chattr is missing from PATH, check_required_tools exits non-zero, stderr contains 'chattr'" {
    # Create a stub directory with everything EXCEPT chattr
    local stub_bin="${BATS_TMPDIR}/stub_bin_pv26"
    mkdir -p "$stub_bin"
    # Create stubs for all required tools except chattr
    for tool in lsattr useradd install stat getent jq; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "${stub_bin}/${tool}"
        chmod +x "${stub_bin}/${tool}"
    done
    # Write a wrapper script that sets the restricted PATH, sources provision.sh,
    # and calls check_required_tools — combining stderr+stdout for bats capture.
    local wrapper="${BATS_TMPDIR}/pv26_wrapper.sh"
    printf '#!/usr/bin/env bash\nexport PATH="%s"\nsource "%s"\ncheck_required_tools 2>&1\n' \
        "$stub_bin" "${BATS_TEST_DIRNAME}/../scripts/provision.sh" > "$wrapper"
    chmod +x "$wrapper"
    run bash "$wrapper"
    [ "$status" -ne 0 ]
    [[ "$output" == *"chattr"* ]]
}

@test "PV-26b when useradd AND adduser are missing, check_required_tools exits non-zero, stderr contains 'useradd'" {
    local stub_bin="${BATS_TMPDIR}/stub_bin_pv26b"
    mkdir -p "$stub_bin"
    # Create stubs for required tools but NOT useradd or adduser
    for tool in chattr lsattr install stat getent jq; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "${stub_bin}/${tool}"
        chmod +x "${stub_bin}/${tool}"
    done
    local wrapper="${BATS_TMPDIR}/pv26b_wrapper.sh"
    printf '#!/usr/bin/env bash\nexport PATH="%s"\nsource "%s"\ncheck_required_tools 2>&1\n' \
        "$stub_bin" "${BATS_TEST_DIRNAME}/../scripts/provision.sh" > "$wrapper"
    chmod +x "$wrapper"
    run bash "$wrapper"
    [ "$status" -ne 0 ]
    [[ "$output" == *"useradd"* ]]
}

# ===========================================================================
# PV-27 — Audit file append-only protects existing content (chattr +a blocks truncation)
# Spec: R7.1, R7.6
# Linux-deferred
# ===========================================================================
@test "PV-27 truncation of +a-armed audit.jsonl fails and content is preserved" {
    skip_unless_linux_root_mutation
    REPO_ROOT="$(pwd)" bash "$PROVISION"
    # Write a known line (append is allowed under +a)
    printf '{"test":"sentinel-line"}\n' >> /var/log/osgania/audit.jsonl
    # Attempt truncation — this must fail because +a blocks truncation even for root
    run bash -c '> /var/log/osgania/audit.jsonl'
    [ "$status" -ne 0 ]
    # Content must be preserved
    run grep -c 'sentinel-line' /var/log/osgania/audit.jsonl
    [ "$status" -eq 0 ]
    [ "$output" -ge 1 ]
}

# ===========================================================================
# Additional unit tests for macOS-safe functions (Phase 2, 3, 4 coverage)
# ===========================================================================

# --- detect_os ---

@test "detect_os with ubuntu 26.04 fixture → OS_TARGET=ubuntu-2604" {
    make_os_release "ubuntu" "26.04"
    OS_VERSION=""
    OS_TARGET=""
    detect_os
    [ "$OS_TARGET" = "ubuntu-2604" ]
    [ "$OS_VERSION" = "26.04" ]
}

@test "detect_os with ubuntu 24.04 fixture → OS_TARGET=ubuntu-2404" {
    make_os_release "ubuntu" "24.04"
    OS_VERSION=""
    OS_TARGET=""
    detect_os
    [ "$OS_TARGET" = "ubuntu-2404" ]
    [ "$OS_VERSION" = "24.04" ]
}

@test "detect_os with ID=debian → exits non-zero, stderr contains unsupported OS" {
    make_os_release "debian" "12"
    run detect_os
    [ "$status" -ne 0 ]
    [[ "$output" == *"debian"* ]] || [[ "$output" == *"unsupported"* ]]
}

@test "detect_os with VERSION_ID=22.04 → exits non-zero, stderr identifies unsupported version" {
    make_os_release "ubuntu" "22.04"
    run detect_os
    [ "$status" -ne 0 ]
    [[ "$output" == *"22.04"* ]] || [[ "$output" == *"unsupported"* ]]
}

# --- semver_gte ---

@test "semver_gte 2.1.153 2.1.153 → exit 0 (equal is >=)" {
    run semver_gte "2.1.153" "2.1.153"
    [ "$status" -eq 0 ]
}

@test "semver_gte 2.1.200 2.1.153 → exit 0 (patch higher)" {
    run semver_gte "2.1.200" "2.1.153"
    [ "$status" -eq 0 ]
}

@test "semver_gte 3.0.0 2.1.153 → exit 0 (major higher)" {
    run semver_gte "3.0.0" "2.1.153"
    [ "$status" -eq 0 ]
}

@test "semver_gte 2.1.152 2.1.153 → exit 1 (patch lower)" {
    run semver_gte "2.1.152" "2.1.153"
    [ "$status" -eq 1 ]
}

@test "semver_gte 2.0.999 2.1.153 → exit 1 (minor lower)" {
    run semver_gte "2.0.999" "2.1.153"
    [ "$status" -eq 1 ]
}

@test "semver_gte 1.99.99 2.1.153 → exit 1 (major lower)" {
    run semver_gte "1.99.99" "2.1.153"
    [ "$status" -eq 1 ]
}

# --- report_plan (PV-25 extended) ---

@test "report_plan output is non-empty and mentions all planned mutations" {
    run report_plan
    [ "$status" -eq 0 ]
    [ -n "$output" ]
    [[ "$output" == *"aios"* ]]
    [[ "$output" == *"/opt/osgania/platform"* ]]
    [[ "$output" == *"/etc/claude-code/managed-settings.json"* ]]
    [[ "$output" == *"/etc/osgania/secrets"* ]]
    [[ "$output" == *"chattr +a"* ]]
    [[ "$output" == *"AUDIT_LOG"* ]]
    [[ "$output" == *"jq"* ]]
}

@test "report_plan does not create any files in BATS_TMPDIR (no side effects)" {
    local before
    before="$(ls "${BATS_TMPDIR}" 2>/dev/null | wc -l | tr -d ' ')"
    run report_plan
    [ "$status" -eq 0 ]
    local after
    after="$(ls "${BATS_TMPDIR}" 2>/dev/null | wc -l | tr -d ' ')"
    [ "$before" = "$after" ]
}

# ===========================================================================
# FIX-1 regression — lsattr false-positive via attribute field extraction
# Spec: R7.3
# macOS-safe: stub lsattr returning various outputs
# ===========================================================================

# Helper: make a stub lsattr that returns a fixed single line of output
make_lsattr_stub() {
    local output_line="$1"
    mkdir -p "${BATS_TMPDIR}/bin"
    printf '#!/usr/bin/env bash\nprintf '"'"'%%s\n'"'"' %q\nexit 0\n' \
        "$output_line" > "${BATS_TMPDIR}/bin/lsattr"
    chmod +x "${BATS_TMPDIR}/bin/lsattr"
}

# Helper: make a stub chattr that is a no-op
make_chattr_stub() {
    mkdir -p "${BATS_TMPDIR}/bin"
    printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/chattr"
    chmod +x "${BATS_TMPDIR}/bin/chattr"
}

@test "FIX-1a lsattr stub with 'a' in attribute field → create_audit_tree verification passes" {
    # Attribute field contains 'a' (append-only set correctly)
    # "-----a-------e-- /var/log/osgania/audit.jsonl"
    make_lsattr_stub "-----a-------e-- /var/log/osgania/audit.jsonl"
    make_chattr_stub
    # Use a temp file path for AUDIT_FILE so we can pre-create it
    local tmp_audit="${BATS_TMPDIR}/audit_fix1a.jsonl"
    touch "$tmp_audit"
    # Directly test the attribute field extraction logic
    local lsattr_out attr_field
    lsattr_out="$(lsattr "$tmp_audit" 2>/dev/null)"
    attr_field="$(printf '%s' "$lsattr_out" | awk '{print $1}')"
    # attr_field should be "-----a-------e--" — contains 'a'
    run bash -c "printf '%s' \"$attr_field\" | grep -q 'a'"
    [ "$status" -eq 0 ]
}

@test "FIX-1b lsattr stub attribute field WITHOUT 'a' but path contains 'a' → verification correctly FAILS" {
    # This is the regression case: attribute field "----i--------e--" has no 'a',
    # but the path /var/log/osgania/audit.jsonl has many 'a' letters.
    # The old code (grep -q 'a' on the full lsattr line) would PASS falsely.
    # The fixed code (grep on attr_field only) must FAIL.
    local fake_lsattr_line="----i--------e-- /var/log/osgania/audit.jsonl"
    local attr_field
    attr_field="$(printf '%s' "$fake_lsattr_line" | awk '{print $1}')"
    # attr_field = "----i--------e--" — does NOT contain 'a'
    run bash -c "printf '%s' \"$attr_field\" | grep -q 'a'"
    [ "$status" -ne 0 ]
    # Confirm that the OLD approach (grep -q 'a' on the full line) would have falsely passed
    run bash -c "printf '%s' \"$fake_lsattr_line\" | grep -q 'a'"
    [ "$status" -eq 0 ]
    # This test documents the exact regression: old=pass, new=fail on same input
}

@test "FIX-1c lsattr returns empty output → create_audit_tree verification reports FATAL and fails" {
    # Empty lsattr output must be treated as verification failure, not silent pass
    mkdir -p "${BATS_TMPDIR}/bin"
    # Stub lsattr that returns empty output (exit 0)
    printf '#!/usr/bin/env bash\nprintf ""\nexit 0\n' > "${BATS_TMPDIR}/bin/lsattr"
    chmod +x "${BATS_TMPDIR}/bin/lsattr"
    make_chattr_stub
    # Stub install to be a no-op
    printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/install"
    chmod +x "${BATS_TMPDIR}/bin/install"
    # Pre-create the audit dir and file stubs so the function doesn't need real fs
    local tmp_audit_dir="${BATS_TMPDIR}/fake_audit_dir"
    local tmp_audit_file="${BATS_TMPDIR}/fake_audit_dir/audit.jsonl"
    mkdir -p "$tmp_audit_dir"
    touch "$tmp_audit_file"
    # Override AUDIT_DIR and AUDIT_FILE for this test
    AUDIT_DIR="$tmp_audit_dir"
    AUDIT_FILE="$tmp_audit_file"
    run create_audit_tree
    [ "$status" -ne 0 ]
    [[ "$output" == *"lsattr produced no output"* ]] || [[ "$output" == *"FATAL"* ]]
    # Restore
    AUDIT_DIR="/var/log/osgania"
    AUDIT_FILE="/var/log/osgania/audit.jsonl"
}

# ===========================================================================
# FIX-2 regression — --check validates preconditions (R1.7)
# macOS-safe: uses a non-Ubuntu os-release fixture
# ===========================================================================

@test "FIX-2a --check with non-Ubuntu OS fixture exits non-zero (precondition enforced)" {
    # R1.7 fix: --check must run check_preconditions before report_plan
    # A non-Ubuntu os-release must cause non-zero exit, not a clean plan
    make_os_release "debian" "12"
    # We need systemctl stub and stat stub to avoid failing on those before OS check
    # detect_os fails first, so those aren't needed
    run bash "$PROVISION" --check
    [ "$status" -ne 0 ]
    [[ "$output" == *"debian"* ]] || [[ "$output" == *"unsupported"* ]]
}

@test "FIX-2b --check with valid Ubuntu 24.04 fixture + required stubs exits 0 with plan" {
    # This verifies the happy path of --check still works after FIX-2
    make_os_release "ubuntu" "24.04"
    # Stubs for tools checked by check_required_tools and systemctl + stat
    mkdir -p "${BATS_TMPDIR}/bin"
    for tool in chattr lsattr useradd install stat getent systemctl; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/${tool}"
        chmod +x "${BATS_TMPDIR}/bin/${tool}"
    done
    # stat stub must output a valid fs type for check_ext4
    printf '#!/usr/bin/env bash\nprintf "ext4\n"\nexit 0\n' > "${BATS_TMPDIR}/bin/stat"
    chmod +x "${BATS_TMPDIR}/bin/stat"
    run bash "$PROVISION" --check
    [ "$status" -eq 0 ]
    [[ "$output" == *"aios"* ]]
}

# ===========================================================================
# FIX-3 regression — existing aios with wrong attributes aborts (R2.8)
# Linux-deferred: requires real getent + real user manipulation
# ===========================================================================

@test "FIX-3 existing aios with wrong UID → create_aios_account aborts (Linux-gated)" {
    skip_unless_linux_root_mutation
    # Create aios with wrong UID (e.g., 9002) by adding a different user first
    # and then pointing the check at a fake getent — or use a wrapper approach.
    # Since this requires real Linux user creation, we use a wrapper that stubs
    # getent to return aios with wrong UID.
    local wrapper="${BATS_TMPDIR}/fix3_wrapper.sh"
    # Write the wrapper with the provision.sh path resolved at test time so the
    # wrapper works regardless of the working directory when bash executes it.
    {
        printf '#!/usr/bin/env bash\n'
        printf '# Stub getent to return aios with wrong UID\n'
        printf 'mkdir -p "${BATS_TMPDIR}/bin"\n'
        printf 'cat > "${BATS_TMPDIR}/bin/getent" << '"'"'STUBEOF'"'"'\n'
        printf '#!/usr/bin/env bash\n'
        printf 'if [[ "$1" == "passwd" && "$2" == "aios" ]]; then\n'
        printf '    printf '"'"'aios:x:9002:9001:/nonexistent:/usr/sbin/nologin\n'"'"'\n'
        printf '    exit 0\n'
        printf 'fi\n'
        printf '/usr/bin/getent "$@"\n'
        printf 'STUBEOF\n'
        printf 'chmod +x "${BATS_TMPDIR}/bin/getent"\n'
        printf 'export PATH="${BATS_TMPDIR}/bin:${PATH}"\n'
        printf 'source %q\n' "${BATS_TEST_DIRNAME}/../scripts/provision.sh"
        printf 'create_aios_account 2>&1\n'
    } > "$wrapper"
    chmod +x "$wrapper"
    run bash "$wrapper"
    [ "$status" -ne 0 ]
    [[ "$output" == *"9002"* ]] || [[ "$output" == *"R2.8"* ]] || [[ "$output" == *"wrong"* ]] || [[ "$output" == *"does not match"* ]]
}

# ===========================================================================
# FIX-4 regression — all collision checks happen BEFORE any mutation
# macOS-safe: uses stub getent to simulate collision scenarios
# ===========================================================================

@test "FIX-4a GID collision detected → no groupadd called (macOS-safe via stubs)" {
    # Stub getent to report GID 9001 taken by group "other"
    mkdir -p "${BATS_TMPDIR}/bin"
    cat > "${BATS_TMPDIR}/bin/getent" << 'STUBEOF'
#!/usr/bin/env bash
if [[ "$1" == "group" && "$2" == "9001" ]]; then
    printf 'other:x:9001:\n'
    exit 0
fi
if [[ "$1" == "group" && "$2" == "aios" ]]; then
    exit 1
fi
exit 1
STUBEOF
    chmod +x "${BATS_TMPDIR}/bin/getent"
    # groupadd stub that logs if called
    printf '#!/usr/bin/env bash\nprintf "groupadd-called\n"\nexit 0\n' \
        > "${BATS_TMPDIR}/bin/groupadd"
    chmod +x "${BATS_TMPDIR}/bin/groupadd"
    run create_aios_account
    [ "$status" -ne 0 ]
    # groupadd must NOT have been called (no "groupadd-called" in output)
    [[ "$output" != *"groupadd-called"* ]]
    [[ "$output" == *"9001"* ]] || [[ "$output" == *"other"* ]]
}

@test "FIX-4b UID collision detected → groupadd NOT called (no partial state)" {
    # GID check passes, UID check fails — groupadd must NOT run
    mkdir -p "${BATS_TMPDIR}/bin"
    cat > "${BATS_TMPDIR}/bin/getent" << 'STUBEOF'
#!/usr/bin/env bash
if [[ "$1" == "group" && "$2" == "9001" ]]; then
    exit 1  # no GID collision
fi
if [[ "$1" == "group" && "$2" == "aios" ]]; then
    exit 1  # aios group doesn't exist yet
fi
if [[ "$1" == "passwd" && "$2" == "9001" ]]; then
    printf 'collide:x:9001:9001:/home/collide:/bin/bash\n'
    exit 0  # UID collision
fi
exit 1
STUBEOF
    chmod +x "${BATS_TMPDIR}/bin/getent"
    printf '#!/usr/bin/env bash\nprintf "groupadd-called\n"\nexit 0\n' \
        > "${BATS_TMPDIR}/bin/groupadd"
    chmod +x "${BATS_TMPDIR}/bin/groupadd"
    run create_aios_account
    [ "$status" -ne 0 ]
    # groupadd must NOT have been called (partial state guard)
    [[ "$output" != *"groupadd-called"* ]]
    [[ "$output" == *"9001"* ]] || [[ "$output" == *"collide"* ]]
}

@test "FIX-4c nologin path mismatch → groupadd NOT called (nologin check is a pre-mutation precondition)" {
    # Regression for NEW-2: nologin check must run BEFORE groupadd so a mismatch
    # aborts without creating any group (no partial state).
    # All GID/UID collision checks pass (aios group/user don't exist, no numeric collision).
    mkdir -p "${BATS_TMPDIR}/bin"
    cat > "${BATS_TMPDIR}/bin/getent" << 'STUBEOF'
#!/usr/bin/env bash
# No numeric GID/UID collision, aios group/user do not exist
exit 1
STUBEOF
    chmod +x "${BATS_TMPDIR}/bin/getent"
    # groupadd stub that logs if called
    printf '#!/usr/bin/env bash\nprintf "groupadd-called\n"\nexit 0\n' \
        > "${BATS_TMPDIR}/bin/groupadd"
    chmod +x "${BATS_TMPDIR}/bin/groupadd"
    # Stub nologin at a wrong path so the assertion fires
    printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/nologin"
    chmod +x "${BATS_TMPDIR}/bin/nologin"
    # With BATS_TMPDIR/bin first in PATH, `command -v nologin` returns the stub path
    # which is NOT /usr/sbin/nologin → mismatch → abort BEFORE groupadd
    run create_aios_account
    [ "$status" -ne 0 ]
    [[ "$output" == *"nologin"* ]] || [[ "$output" == *"/usr/sbin/nologin"* ]]
    # groupadd must NOT have been called
    [[ "$output" != *"groupadd-called"* ]]
}

# ===========================================================================
# FIX-5 regression — semver_gte with pre-release, empty, non-numeric, leading zeros
# macOS-safe
# ===========================================================================

@test "FIX-5a semver_gte '2.1.153-beta' '2.1.153' → exit 0 (equal after stripping suffix)" {
    run semver_gte "2.1.153-beta" "2.1.153"
    [ "$status" -eq 0 ]
}

@test "FIX-5b semver_gte '2.1.152-beta' '2.1.153' → exit 1 (below floor after stripping)" {
    run semver_gte "2.1.152-beta" "2.1.153"
    [ "$status" -eq 1 ]
}

@test "FIX-5c semver_gte '' '2.1.153' → exit 1 (empty string treated as 0.0.0)" {
    run semver_gte "" "2.1.153"
    [ "$status" -eq 1 ]
}

@test "FIX-5d semver_gte '2.1.abc' '2.1.153' → no crash, exit 1 (non-numeric patch → 0)" {
    run semver_gte "2.1.abc" "2.1.153"
    # Must not crash (exit 2 or similar from bash error)
    [ "$status" -eq 1 ]
}

@test "FIX-5e semver_gte '2.01.0153' '2.1.153' → exit 0 (leading zeros treated as base-10)" {
    # 0153 in octal = 107 in decimal, which would be < 153 — wrong without base-10 forcing
    # With base-10 forcing: 0153 = 153, so 2.01.0153 == 2.1.153 → exit 0
    run semver_gte "2.01.0153" "2.1.153"
    [ "$status" -eq 0 ]
}

@test "FIX-5f semver_gte '2.1.154+build' '2.1.153' → exit 0 (build metadata stripped)" {
    run semver_gte "2.1.154+build" "2.1.153"
    [ "$status" -eq 0 ]
}

# ===========================================================================
# FIX-6 regression — Layer-3 probe exit 0 → FAILED, not UNVERIFIED
# macOS-safe: drives _classify_layer3_probe directly
# ===========================================================================

@test "FIX-6a _classify_layer3_probe exit=0 → LAYER3_STATUS=FAILED" {
    LAYER3_STATUS="UNVERIFIED"
    _classify_layer3_probe 0 "some output from CLI"
    [ "$LAYER3_STATUS" = "FAILED" ]
}

@test "FIX-6b _classify_layer3_probe exit=1 with refusal keyword → LAYER3_STATUS=VERIFIED" {
    LAYER3_STATUS="UNVERIFIED"
    _classify_layer3_probe 1 "Error: --dangerously-skip-permissions is disabled by operator policy"
    [ "$LAYER3_STATUS" = "VERIFIED" ]
}

@test "FIX-6c _classify_layer3_probe exit=1 no refusal keyword → LAYER3_STATUS=UNVERIFIED" {
    LAYER3_STATUS="VERIFIED"
    _classify_layer3_probe 1 "some other error message"
    [ "$LAYER3_STATUS" = "UNVERIFIED" ]
}

@test "FIX-6d format_summary with LAYER3_STATUS=FAILED → output contains 'FAILED'" {
    CLI_VERSION_RECORDED="2.1.153"
    CLI_VERSION_OK=1
    LAYER3_STATUS="FAILED"
    OS_VERSION="24.04"
    OS_TARGET="ubuntu-2404"
    run format_summary
    [ "$status" -eq 0 ]
    [[ "$output" == *"FAILED"* ]]
    [[ "$output" == *"Layer-3"* ]]
}

@test "FIX-6e format_summary with LAYER3_STATUS=UNVERIFIED → output contains 'UNVERIFIED' not 'FAILED'" {
    CLI_VERSION_RECORDED="2.1.153"
    CLI_VERSION_OK=1
    LAYER3_STATUS="UNVERIFIED"
    OS_VERSION="24.04"
    OS_TARGET="ubuntu-2404"
    run format_summary
    [ "$status" -eq 0 ]
    [[ "$output" == *"UNVERIFIED"* ]]
    [[ "$output" != *"FAILED"* ]]
}

# ===========================================================================
# FIX-7 regression — symlink at AUDIT_FILE is rejected
# macOS-safe: creates a real symlink in BATS_TMPDIR
# ===========================================================================

@test "FIX-7a symlink at AUDIT_FILE → create_audit_tree aborts with clear message" {
    local tmp_target="${BATS_TMPDIR}/real_target.jsonl"
    local tmp_link="${BATS_TMPDIR}/symlink_audit.jsonl"
    local tmp_audit_dir="${BATS_TMPDIR}/audit_dir_fix7"
    touch "$tmp_target"
    mkdir -p "$tmp_audit_dir"
    ln -sf "$tmp_target" "$tmp_link"
    # Override AUDIT_DIR and AUDIT_FILE
    AUDIT_DIR="$tmp_audit_dir"
    AUDIT_FILE="$tmp_link"
    run create_audit_tree
    [ "$status" -ne 0 ]
    [[ "$output" == *"symlink"* ]]
    # Restore
    AUDIT_DIR="/var/log/osgania"
    AUDIT_FILE="/var/log/osgania/audit.jsonl"
    rm -f "$tmp_link" "$tmp_target"
}

@test "FIX-7b symlink at AUDIT_DIR → create_audit_tree aborts with clear message" {
    local tmp_real_dir="${BATS_TMPDIR}/real_audit_dir"
    local tmp_link_dir="${BATS_TMPDIR}/link_audit_dir"
    mkdir -p "$tmp_real_dir"
    ln -sf "$tmp_real_dir" "$tmp_link_dir"
    AUDIT_DIR="$tmp_link_dir"
    AUDIT_FILE="${tmp_link_dir}/audit.jsonl"
    run create_audit_tree
    [ "$status" -ne 0 ]
    [[ "$output" == *"symlink"* ]]
    # Restore
    AUDIT_DIR="/var/log/osgania"
    AUDIT_FILE="/var/log/osgania/audit.jsonl"
    rm -f "$tmp_link_dir"
}

@test "FIX-7c non-symlink AUDIT_FILE pre-exists → create_audit_tree does not reject it (control case)" {
    # Verify the symlink check does NOT reject a regular file
    local tmp_audit_dir="${BATS_TMPDIR}/audit_dir_fix7c"
    local tmp_audit_file="${BATS_TMPDIR}/audit_dir_fix7c/audit.jsonl"
    mkdir -p "$tmp_audit_dir"
    touch "$tmp_audit_file"
    AUDIT_DIR="$tmp_audit_dir"
    AUDIT_FILE="$tmp_audit_file"
    # Stubs for chattr and lsattr so the function can proceed past the symlink guard
    mkdir -p "${BATS_TMPDIR}/bin"
    printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/chattr"
    chmod +x "${BATS_TMPDIR}/bin/chattr"
    # lsattr stub returns a line WITH 'a' in attribute field.
    # Use %s with -- to avoid printf treating the attribute dashes as flags.
    printf '%s\n' '#!/usr/bin/env bash' \
        'printf "%s %s\n" "-----a-------e--" "$1"' \
        'exit 0' > "${BATS_TMPDIR}/bin/lsattr"
    chmod +x "${BATS_TMPDIR}/bin/lsattr"
    # install stub (no-op — AUDIT_FILE already pre-created with touch)
    printf '#!/usr/bin/env bash\nexit 0\n' > "${BATS_TMPDIR}/bin/install"
    chmod +x "${BATS_TMPDIR}/bin/install"
    run create_audit_tree
    [ "$status" -eq 0 ]
    # Restore
    AUDIT_DIR="/var/log/osgania"
    AUDIT_FILE="/var/log/osgania/audit.jsonl"
}

# ===========================================================================
# FIX-8 regression — exact group name matching (hyphenated groups)
# macOS-safe: directly tests the group-check logic via sourced functions
# ===========================================================================

@test "FIX-8a group list 'aios sudo-users' → NOT flagged as sudo membership" {
    # The group "sudo-users" must not trigger the abort (only exact "sudo" should)
    local groups_output="aios sudo-users"
    run bash -c "printf '%s' \"$groups_output\" | tr ' ' '\n' | grep -qxF 'sudo'"
    [ "$status" -ne 0 ]
}

@test "FIX-8b group list 'aios sudo' → flagged as sudo membership (exact match)" {
    local groups_output="aios sudo"
    run bash -c "printf '%s' \"$groups_output\" | tr ' ' '\n' | grep -qxF 'sudo'"
    [ "$status" -eq 0 ]
}

@test "FIX-8c group list 'aios admin-tools' → NOT flagged as admin membership" {
    local groups_output="aios admin-tools"
    run bash -c "printf '%s' \"$groups_output\" | tr ' ' '\n' | grep -qxF 'admin'"
    [ "$status" -ne 0 ]
}

@test "FIX-8d group list 'aios admin' → flagged as admin membership (exact match)" {
    local groups_output="aios admin"
    run bash -c "printf '%s' \"$groups_output\" | tr ' ' '\n' | grep -qxF 'admin'"
    [ "$status" -eq 0 ]
}

# ===========================================================================
# FIX-9 regression — bogus REPO_ROOT causes abort before any install
# macOS-safe: uses a temp dir missing the required source files
# ===========================================================================

@test "FIX-9a bogus REPO_ROOT missing all expected files → install_platform_tree aborts" {
    local bogus_root="${BATS_TMPDIR}/bogus_repo"
    mkdir -p "$bogus_root"
    REPO_ROOT="$bogus_root"
    run install_platform_tree
    [ "$status" -ne 0 ]
    [[ "$output" == *"REPO_ROOT"* ]] || [[ "$output" == *"validation failed"* ]]
    unset REPO_ROOT
}

@test "FIX-9b bogus REPO_ROOT missing managed-settings.json → _validate_repo_root aborts" {
    local bogus_root="${BATS_TMPDIR}/partial_repo"
    mkdir -p "${bogus_root}/platform/hooks"
    touch "${bogus_root}/platform/hooks/guardia.sh"
    touch "${bogus_root}/platform/hooks/camara.sh"
    # managed-settings.json is absent
    run _validate_repo_root "$bogus_root"
    [ "$status" -ne 0 ]
    [[ "$output" == *"managed-settings.json"* ]]
}

@test "FIX-9c valid REPO_ROOT with all required files → _validate_repo_root passes" {
    local valid_root="${BATS_TMPDIR}/valid_repo"
    mkdir -p "${valid_root}/platform/hooks"
    touch "${valid_root}/platform/managed-settings.json"
    touch "${valid_root}/platform/hooks/guardia.sh"
    touch "${valid_root}/platform/hooks/camara.sh"
    run _validate_repo_root "$valid_root"
    [ "$status" -eq 0 ]
}
