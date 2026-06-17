#!/usr/bin/env bats
# managed-settings.bats — bats-core test suite for platform/managed-settings.json
#
# Scenarios: MS-01..MS-13
# Requirements: R9.1..R12.2
#
# All assertions use jq against the file directly.
# These are STRUCTURAL (presence) checks only — runtime engine enforcement
# is out of bats scope (see spec R9.7 testability note).

load test_helper

MS_FILE="platform/managed-settings.json"

# ---------------------------------------------------------------------------
# MS-01 — sudo deny rule present
# Requirement: R9.1
# ---------------------------------------------------------------------------

@test "MS-01 deny rules contain Bash(sudo *)" {
    run jq -e '.permissions.deny | map(. == "Bash(sudo *)") | any' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-02 — curl deny rule present
# Requirement: R9.2
# ---------------------------------------------------------------------------

@test "MS-02 deny rules contain Bash(curl *)" {
    run jq -e '.permissions.deny | map(. == "Bash(curl *)") | any' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-03 — wget deny rule present
# Requirement: R9.3
# ---------------------------------------------------------------------------

@test "MS-03 deny rules contain Bash(wget *)" {
    run jq -e '.permissions.deny | map(. == "Bash(wget *)") | any' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-04 — secrets read deny rule present
# Requirement: R9.4
# Note: structural presence check only — do NOT attempt to invoke the Read tool
# ---------------------------------------------------------------------------

@test "MS-04 deny rules contain Read(/etc/osgania/secrets/**)" {
    run jq -e '.permissions.deny | map(. == "Read(/etc/osgania/secrets/**)") | any' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-05 — platform Edit deny rule present
# Requirement: R9.5
# ---------------------------------------------------------------------------

@test "MS-05 deny rules contain Edit(/opt/osgania/platform/**)" {
    run jq -e '.permissions.deny | map(. == "Edit(/opt/osgania/platform/**)") | any' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-06 — platform Write deny rule present
# Requirement: R9.6
# ---------------------------------------------------------------------------

@test "MS-06 deny rules contain Write(/opt/osgania/platform/**)" {
    run jq -e '.permissions.deny | map(. == "Write(/opt/osgania/platform/**)") | any' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-07 — bypass mode disabled (nested under permissions, string "disable")
# Requirement: R10.1, ADR-006
# jq assertion: .permissions.disableBypassPermissionsMode == "disable"
# Must NOT be a top-level key
# ---------------------------------------------------------------------------

@test "MS-07 permissions.disableBypassPermissionsMode is nested string 'disable'" {
    # Nested under permissions, value is string "disable"
    run jq -e '.permissions.disableBypassPermissionsMode == "disable"' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

@test "MS-07b disableBypassPermissionsMode is NOT a top-level key" {
    run jq -e '.disableBypassPermissionsMode == null' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-08 — managed hooks only enforced (top-level boolean true)
# Requirement: R11.1
# ---------------------------------------------------------------------------

@test "MS-08 allowManagedHooksOnly is true at top level" {
    run jq -e '.allowManagedHooksOnly == true' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-09 — guardia registered as PreToolUse for Bash with timeout 10
# Requirement: R12.1
# ---------------------------------------------------------------------------

@test "MS-09 guardia registered as PreToolUse for Bash with command path and timeout 10" {
    # Confirm PreToolUse entry exists for Bash matcher pointing to guardia.sh with timeout 10
    run jq -e '
        .hooks.PreToolUse[]
        | select(.matcher == "Bash")
        | .hooks[]
        | select(.command == "/opt/osgania/platform/hooks/guardia.sh")
        | .timeout == 10
    ' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-10 — camara registered as PostToolUse for all tools (*) with timeout 10
# Requirement: R12.2
# ---------------------------------------------------------------------------

@test "MS-10 camara registered as PostToolUse with matcher * and command path and timeout 10" {
    # Confirm PostToolUse entry exists with matcher "*" pointing to camara.sh with timeout 10
    run jq -e '
        .hooks.PostToolUse[]
        | select(.matcher == "*")
        | .hooks[]
        | select(.command == "/opt/osgania/platform/hooks/camara.sh")
        | .timeout == 10
    ' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-11 — file is valid JSON
# Requirements: R9.1–R12.2 (general)
# ---------------------------------------------------------------------------

@test "MS-11 managed-settings.json is valid JSON" {
    run jq -e '.' "$MS_FILE"
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# MS-12 — defaultMode is "default"
# Requirement: R9.8
# ---------------------------------------------------------------------------

@test "MS-12 permissions.defaultMode is 'default'" {
    run jq -e '.permissions.defaultMode == "default"' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

# ---------------------------------------------------------------------------
# MS-13 — allow list is empty (deny-only L0 posture)
# Requirement: R9.9
# ---------------------------------------------------------------------------

@test "MS-13 permissions.allow is an empty array" {
    run jq -e '.permissions.allow == []' "$MS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}
