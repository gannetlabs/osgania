#!/usr/bin/env bats
# egress.bats — bats test scenarios for U2: nft egress wall
#
# Spec:   openspec/changes/vps-provisioning-hardening-2b/spec.md (HB-02)
# Design: openspec/changes/vps-provisioning-hardening-2b/design.md (§2)
# TDD:    STRICT — tests written before implementation (RED → GREEN cycle)
#
# Tier legend:
#   HOST-SAFE      — pure config/string assertions; no root, no nft, no systemd;
#                    runs on macOS
#   LINUX-ROOT     — requires Ubuntu 24.04/26.04 + EUID==0 +
#                    PROVISION_TEST_ALLOW_MUTATION=1; skipped on macOS
#   LINUX-ROOT/LIVE-KEY — additionally requires LIVE_KEY_AVAILABLE=1 and a live
#                    API key at the secrets path
#
# HOST-SAFE scenarios: HB-02-S1, HB-02-S2, HB-02-S2c, HB-02-S2d, HB-02-S2e, HB-02-S3
# LINUX-ROOT scenarios (skip-guarded): HB-02-S2b, HB-02-S4, HB-02-S5, HB-02-S8
# LINUX-ROOT/LIVE-KEY scenarios (skip-guarded): HB-02-S6, HB-02-S7, HB-02-S9
#
# Run (HOST-SAFE only): bats tests/egress.bats
# Run (all tiers, VPS): sudo PROVISION_TEST_ALLOW_MUTATION=1 [LIVE_KEY_AVAILABLE=1] bats tests/egress.bats

load test_helper

PROVISION_AGENT="${BATS_TEST_DIRNAME}/../scripts/provision-agent.sh"
REPO_ROOT_AGENT="${BATS_TEST_DIRNAME}/.."

# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

setup() {
    _ORIG_PATH="$PATH"
    mkdir -p "${BATS_TMPDIR}/bin"
    export PATH="${BATS_TMPDIR}/bin:${PATH}"
    # Source provision-agent.sh so we can call build_service_unit() directly.
    # shellcheck disable=SC1090
    source "$PROVISION_AGENT"
    load_managed_settings_fixture
}

teardown() {
    export PATH="$_ORIG_PATH"
    rm -rf "${BATS_TMPDIR}/bin"
    unset MANAGED_SETTINGS_PATH PROVISION_TEST_ALLOW_MUTATION LIVE_KEY_AVAILABLE
}

# ===========================================================================
# HOST-SAFE cluster — nft ruleset template structure
# ===========================================================================

# ---------------------------------------------------------------------------
# HB-02-S1 — nft ruleset template contains correct chain structure (HOST-SAFE)
# Spec: HB-02.1
# TDD: RED before U2-T3 (platform/nft/osgania-egress.nft does not yet exist)
#      GREEN after U2-T3 creates the file
# ---------------------------------------------------------------------------
@test "HB-02-S1 nft ruleset template contains correct chain structure" {
    local nft_file="${REPO_ROOT_AGENT}/platform/nft/osgania-egress.nft"
    [ -f "$nft_file" ] || return 1

    local content
    content="$(cat "$nft_file")"

    # Must contain the inet table declaration (HB-02.1)
    [[ "$content" == *"table inet osgania_egress"* ]] || return 1

    # Must use meta skuid 9001 (uid-based, NOT cgroup — HB-02.1 spec note)
    [[ "$content" == *"meta skuid 9001 jump aios_egress"* ]] || return 1

    # Must contain the aios_egress chain
    [[ "$content" == *"chain aios_egress"* ]] || return 1

    # Must contain the terminal counter drop rule (HB-02.3)
    [[ "$content" == *"counter drop"* ]] || return 1

    # Must NOT use cgroup matching (hardware gate #6 proved skuid is the
    # correct and timing-safe selector for Type=oneshot; cgroup has race
    # conditions with oneshot units)
    [[ "$content" != *"cgroup"* ]] || return 1

    # Must declare the output hook with correct type/priority (HB-02.1 — spec)
    # A ruleset using hook input instead of hook output would NOT filter egress.
    [[ "$content" == *"type filter hook output priority 0"* ]] || return 1

    # Chain policy must be accept (uid-scoped jump handles the restriction)
    [[ "$content" == *"policy accept"* ]] || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S2 — nft ruleset template contains both Anthropic CIDRs (HOST-SAFE)
# Spec: HB-02.2, HB-02.4
# TDD: RED before U2-T3
#      GREEN after U2-T3 creates the file
#
# FIX-3: assertions are on the RENDERED output (template substituted with
# provisioner constants) rather than the raw template (which now uses
# @@ANTHROPIC_EGRESS_V4@@ / @@ANTHROPIC_EGRESS_V6@@ placeholders).
# ---------------------------------------------------------------------------
@test "HB-02-S2 nft ruleset template contains both Anthropic CIDRs and loopback rules" {
    local nft_file="${REPO_ROOT_AGENT}/platform/nft/osgania-egress.nft"
    [ -f "$nft_file" ] || return 1

    # Render the template using the provisioner constants (single-source proof)
    local rendered
    rendered="$(mktemp)"
    sed -e "s|@@ANTHROPIC_EGRESS_V4@@|${ANTHROPIC_EGRESS_V4}|g" \
        -e "s|@@ANTHROPIC_EGRESS_V6@@|${ANTHROPIC_EGRESS_V6}|g" \
        "$nft_file" > "$rendered"

    local content
    content="$(cat "$rendered")"
    rm -f "$rendered"

    # Anthropic IPv4 range (HB-02.2)
    [[ "$content" == *"ip daddr 160.79.104.0/23 tcp dport 443 accept"* ]] || return 1

    # Anthropic IPv6 range (HB-02.2, HB-02.4 — IPv6 must be in lockstep)
    [[ "$content" == *"ip6 daddr 2607:6bc0::/48 tcp dport 443 accept"* ]] || return 1

    # Loopback IPv4 (needed for local stub resolver 127.0.0.53 — systemd-resolved)
    [[ "$content" == *"ip daddr 127.0.0.0/8 accept"* ]] || return 1

    # Loopback IPv6
    [[ "$content" == *"ip6 daddr ::1/128 accept"* ]] || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S2c — Service unit declares After=nftables.service (HOST-SAFE)
# Spec: HB-02.7a
# TDD: GREEN (U1-T5 already delivered this — cross-check only)
#      If RED here, U1 is broken — STOP and report, do NOT modify U1 units.
# ---------------------------------------------------------------------------
@test "HB-02-S2c service unit declares After=nftables.service and Wants=nftables.service" {
    local service_file="${REPO_ROOT_AGENT}/platform/systemd/osgania-agent.service"
    [ -f "$service_file" ] || return 1

    local content
    content="$(cat "$service_file")"

    # Boot ordering: wall must be loaded before the agent activates (HB-02.7a)
    [[ "$content" == *"After=nftables.service"* ]] || return 1

    # Either Wants= or Requires= is acceptable per the spec
    { [[ "$content" == *"Wants=nftables.service"* ]] || \
      [[ "$content" == *"Requires=nftables.service"* ]]; } || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S2d — Timer unit declares After=nftables.service (HOST-SAFE)
# Spec: HB-02.7a
# TDD: GREEN (U1-T6 already delivered this — cross-check only)
#      If RED here, U1 is broken — STOP and report, do NOT modify U1 units.
# ---------------------------------------------------------------------------
@test "HB-02-S2d timer unit declares After=nftables.service and Wants=nftables.service" {
    local timer_file="${REPO_ROOT_AGENT}/platform/systemd/osgania-agent.timer"
    [ -f "$timer_file" ] || return 1

    local content
    content="$(cat "$timer_file")"

    # Boot ordering: timer must also wait for the wall (HB-02.7a — BOTH units required)
    [[ "$content" == *"After=nftables.service"* ]] || return 1

    # Either Wants= or Requires= is acceptable per the spec
    { [[ "$content" == *"Wants=nftables.service"* ]] || \
      [[ "$content" == *"Requires=nftables.service"* ]]; } || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S2e — Provisioner constants are the single source that reaches the
#             rendered ruleset (HOST-SAFE)
# Spec: HB-02.2, design §2
# TDD: NEW — proves that ANTHROPIC_EGRESS_V4/V6 constants (not hardcoded
#      literals) are what flows into the installed .nft file.
# ---------------------------------------------------------------------------
@test "HB-02-S2e rendered nft template contains provisioner CIDR constants in accept rules" {
    local nft_file="${REPO_ROOT_AGENT}/platform/nft/osgania-egress.nft"
    [ -f "$nft_file" ] || return 1

    # The provisioner constants must be defined (sourced from provision-agent.sh in setup)
    [[ -n "${ANTHROPIC_EGRESS_V4:-}" ]] || return 1
    [[ -n "${ANTHROPIC_EGRESS_V6:-}" ]] || return 1

    # Render the template exactly as unit2_install_egress_wall() does
    local rendered
    rendered="$(mktemp)"
    sed -e "s|@@ANTHROPIC_EGRESS_V4@@|${ANTHROPIC_EGRESS_V4}|g" \
        -e "s|@@ANTHROPIC_EGRESS_V6@@|${ANTHROPIC_EGRESS_V6}|g" \
        "$nft_file" > "$rendered"

    local content
    content="$(cat "$rendered")"
    rm -f "$rendered"

    # The rendered .nft must contain the exact CIDR values from the constants
    # in the correct tcp dport 443 accept rule context (not just anywhere in the file)
    [[ "$content" == *"ip daddr ${ANTHROPIC_EGRESS_V4} tcp dport 443 accept"* ]] || return 1
    [[ "$content" == *"ip6 daddr ${ANTHROPIC_EGRESS_V6} tcp dport 443 accept"* ]] || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S3 — Assembled service unit contains telemetry-disable env vars (HOST-SAFE)
# Spec: HB-02.8
# TDD: GREEN (U1-T5 already delivered this — cross-check only)
#      If RED here, U1 is broken — STOP and report, do NOT modify build_service_unit().
# ---------------------------------------------------------------------------
@test "HB-02-S3 assembled service unit contains DISABLE_TELEMETRY and DISABLE_ERROR_REPORTING" {
    local unit
    unit="$(build_service_unit)"

    # Telemetry env vars must be present (HB-02.8)
    [[ "$unit" == *"Environment=DISABLE_TELEMETRY=1"* ]] || return 1
    [[ "$unit" == *"Environment=DISABLE_ERROR_REPORTING=1"* ]] || return 1
}

# ===========================================================================
# LINUX-ROOT cluster — live nft behavior (deferred to disposable VPS)
# All tests below have skip guards; they do NOT run on macOS.
# ===========================================================================

# ---------------------------------------------------------------------------
# HB-02-S2b — nft ruleset install is idempotent (LINUX-ROOT)
# Spec: HB-02.9
# ---------------------------------------------------------------------------
@test "HB-02-S2b nft ruleset install is idempotent (second run yields exactly one table)" {
    skip_unless_linux_root_mutation
    # On VPS: run unit2_install_egress_wall twice; assert exactly one osgania_egress table
    REPO_ROOT="$REPO_ROOT_AGENT" bash "$PROVISION_AGENT" --unit2-only 2>/dev/null || true
    REPO_ROOT="$REPO_ROOT_AGENT" bash "$PROVISION_AGENT" --unit2-only 2>/dev/null || true
    local table_count
    table_count="$(nft list ruleset 2>/dev/null | grep -c 'table inet osgania_egress' || true)"
    [ "$table_count" -eq 1 ]
}

# ---------------------------------------------------------------------------
# HB-02-S4 — nft table loaded on host after Unit 2 provisioning (LINUX-ROOT)
# Spec: HB-02.1, HB-02.7
# ---------------------------------------------------------------------------
@test "HB-02-S4 nft table inet osgania_egress is loaded and contains expected chains" {
    skip_unless_linux_root_mutation
    # On VPS: assert after unit2_install_egress_wall has run
    run nft list table inet osgania_egress
    [ "$status" -eq 0 ] || return 1
    local out="$output"
    [[ "$out" == *"aios_egress"* ]] || return 1
    [[ "$out" == *"meta skuid 9001"* ]] || return 1
    [[ "$out" == *"counter drop"* ]] || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S5 — uid 9001 blocked from non-Anthropic destinations (LINUX-ROOT)
# Spec: HB-02.3, HB-07.1
# ---------------------------------------------------------------------------
@test "HB-02-S5 uid 9001 blocked from 1.1.1.1:443; drop counter increments" {
    skip_unless_linux_root_mutation
    # On VPS: attempt TCP connect as uid 9001 to 1.1.1.1:443; assert timeout/refused
    local drop_before drop_after
    drop_before="$(nft list table inet osgania_egress 2>/dev/null \
        | grep -oE 'packets [0-9]+ bytes [0-9]+' | head -1 | awk '{print $2}')"
    runuser -u aios -- timeout 6 bash -c \
        "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null && return 1 || true
    drop_after="$(nft list table inet osgania_egress 2>/dev/null \
        | grep -oE 'packets [0-9]+ bytes [0-9]+' | head -1 | awk '{print $2}')"
    # Drop counter must have incremented
    [ "${drop_after:-0}" -gt "${drop_before:-0}" ] || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S6 — uid 9001 can reach Anthropic IPv4 endpoint (LINUX-ROOT/LIVE-KEY)
# Spec: HB-07.1, HB-07.2
# ---------------------------------------------------------------------------
@test "HB-02-S6 uid 9001 can reach Anthropic IPv4 endpoint 160.79.104.10:443" {
    skip_unless_live_key
    # On VPS with live key: TLS handshake to Anthropic IPv4
    runuser -u aios -- timeout 10 bash -c \
        "exec 3<>/dev/tcp/160.79.104.10/443" 2>/dev/null || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S7 — uid 9001 can reach Anthropic IPv6 endpoint (LINUX-ROOT/LIVE-KEY)
# Spec: HB-07.1, HB-02.4
# ---------------------------------------------------------------------------
@test "HB-02-S7 uid 9001 can reach Anthropic IPv6 endpoint 2607:6bc0::10:443" {
    skip_unless_live_key
    # On VPS with live key: TLS handshake to Anthropic IPv6 (if IPv6 available)
    if ! ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
        skip "no global IPv6 address on this host"
    fi
    runuser -u aios -- timeout 10 bash -c \
        "exec 3<>/dev/tcp/2607:6bc0::10/443" 2>/dev/null || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S8 — root retains full network access under the wall (LINUX-ROOT)
# Spec: HB-02.6, HB-07.3
# ---------------------------------------------------------------------------
@test "HB-02-S8 root (uid 0) retains full network access — wall does not apply to root" {
    skip_unless_linux_root_mutation
    # On VPS: root must be able to reach 1.1.1.1:443 (uid-scoped wall does not block root)
    timeout 10 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null || return 1
}

# ---------------------------------------------------------------------------
# HB-02-S9 — real claude -p works end-to-end under the wall (LINUX-ROOT/LIVE-KEY)
# Spec: HB-07.2
# ---------------------------------------------------------------------------
@test "HB-02-S9 real claude -p run under the egress wall completes end-to-end" {
    skip_unless_live_key
    # On VPS with live key: start the agent service and assert the stream-json result
    systemctl start osgania-agent.service 2>/dev/null || true

    # Target the last audit record that contains the expected fields
    local audit_record
    audit_record="$(tail -20 /var/log/osgania/audit.jsonl 2>/dev/null \
        | jq -s 'map(select(.terminal_reason != null)) | last' 2>/dev/null)"

    # terminal_reason must be "completed"
    printf '%s\n' "$audit_record" | \
        jq -e '.terminal_reason == "completed"' > /dev/null 2>/dev/null || return 1

    # is_error must be false
    printf '%s\n' "$audit_record" | \
        jq -e '.is_error == false' > /dev/null 2>/dev/null || return 1

    # apiKeySource must be ANTHROPIC_API_KEY
    printf '%s\n' "$audit_record" | \
        jq -e '.apiKeySource == "ANTHROPIC_API_KEY"' > /dev/null 2>/dev/null || return 1
}
