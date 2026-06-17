#!/usr/bin/env bash
# camara.sh — PostToolUse hook: append-only audit record per tool call
#
# Interface (Claude Code hook contract):
#   Input:  single JSON object on STDIN (session_id, tool_name, tool_input, tool_response)
#   Output: nothing (no output to STDOUT required for PostToolUse)
#   Side effect: one JSON Lines record appended to $AUDIT_LOG
#   Exit:   always 0 — fail-open (R5.4, ADR-005)
#
# Audit record fields (design Q1):
#   ts                — ISO-8601 UTC timestamp
#   session_id        — from STDIN .session_id, capped at 128 bytes (N2)
#   tool_name         — from STDIN .tool_name, capped at 64 bytes (N2)
#   tool_input_summary — redacted summary (see derivation below)
#   exit_code         — from STDIN .tool_response.exit_code, or null
#   decision          — "logged" normally; "logged-parse-error" on bad STDIN
#
# tool_input_summary derivation (R6.3, ADR-004):
#   Bash  → .tool_input.command, truncated to 512 bytes + "…[truncated]" marker (N1)
#   Read/Edit/Write → .tool_input.file_path only; content/old_string/new_string dropped
#   Other → first scalar that looks like a path, else "(summary unavailable)"
#
# NEVER log tool_response body — only exit_code (R6.3, CA-09).
# All JSON built with jq --arg so values are correctly escaped (R6.4, ADR-004).
#
# N2 ATOMICITY CAP: session_id capped at 128 bytes, tool_name capped at 64 bytes
# Combined worst-case line: 526 + 128 + 64 + ~135 overhead = ~853 bytes < PIPE_BUF(4096)

set -euo pipefail
# Fail-open trap: if any unexpected internal error fires (e.g. jq non-zero after the
# STDIN guard), exit 0 so camara never blocks the agent (R5.4, ADR-005, drift #2).
# Stderr warnings from explicit checks are still emitted for diagnostics.
trap 'exit 0' EXIT

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# R7.1a: override via environment for test isolation; production uses default.
AUDIT_LOG="${AUDIT_LOG:-/var/log/osgania/audit.jsonl}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# cap_bytes <string> <max_bytes>
# Truncates a string to at most <max_bytes> bytes. No marker added (N2 rule).
cap_bytes() {
    printf '%s' "$1" | head -c "$2"
}

# append_record <json_line>
# Atomically appends a single JSON line to AUDIT_LOG.
# Fail-open: if the file is not writable, warns to stderr and returns (R5.4).
append_record() {
    local record="$1"
    if [[ ! -w "$AUDIT_LOG" ]]; then
        printf '[camara] WARNING: audit log not writable: %s\n' "$AUDIT_LOG" >&2
        return 0
    fi
    printf '%s\n' "$record" >> "$AUDIT_LOG"
}

# ---------------------------------------------------------------------------
# Read STDIN
# ---------------------------------------------------------------------------

stdin_data="$(cat)"

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# Handle malformed / empty STDIN (R8.4, CA-08)
# ---------------------------------------------------------------------------

if [[ -z "$stdin_data" ]] || ! printf '%s' "$stdin_data" | jq -e '.' > /dev/null 2>&1; then
    # Build minimal parse-error record with jq for correct escaping
    record="$(jq -cn \
        --arg ts "$ts" \
        '{"ts":$ts,"session_id":"unknown","tool_name":"unknown","tool_input_summary":"(parse error)","exit_code":null,"decision":"logged-parse-error"}')"
    append_record "$record"
    exit 0
fi

# ---------------------------------------------------------------------------
# Extract fields
# ---------------------------------------------------------------------------

# session_id — top-level field per spec R5.2 / design Q1
# N2 ATOMICITY CAP: session_id capped at 128 bytes (truncated silently, no marker)
raw_session_id="$(printf '%s' "$stdin_data" | jq -r '.session_id // "unknown"')"
session_id="$(cap_bytes "$raw_session_id" 128)"

# tool_name
# N2 ATOMICITY CAP: tool_name capped at 64 bytes (truncated silently, no marker)
raw_tool_name="$(printf '%s' "$stdin_data" | jq -r '.tool_name // "unknown"')"
tool_name="$(cap_bytes "$raw_tool_name" 64)"

# exit_code — from tool_response.exit_code; null if absent (R6.2)
# Coerce: accept only a JSON integer (number equal to its floor); anything else becomes null.
# This prevents objects, arrays, strings, and floats from reaching the audit record.
exit_code_raw="$(printf '%s' "$stdin_data" | jq -c \
    '(.tool_response.exit_code // null)
     | if (type == "number" and floor == .) or type == "null" then . else null end')"

# ---------------------------------------------------------------------------
# Derive tool_input_summary (redacted, R6.3, design Q1 derivation)
# NEVER include tool_response body.
# ---------------------------------------------------------------------------

# N1 TRUNCATION RULE constants (see test_helper.bash and tasks T11)
#   Max content bytes: 512
#   Marker: "…[truncated]" = 3 (U+2026) + 11 (ASCII) = 14 bytes
#   Max total summary bytes: 526
TRUNCATION_LIMIT=512
TRUNCATION_MARKER="…[truncated]"

case "$tool_name" in
    Bash)
        # For Bash: use the command string, truncated to 512 bytes + marker (N1)
        raw_cmd="$(printf '%s' "$stdin_data" | jq -r '.tool_input.command // ""')"
        raw_cmd_bytes="$(printf '%s' "$raw_cmd" | wc -c | tr -d ' ')"
        if [ "$raw_cmd_bytes" -gt "$TRUNCATION_LIMIT" ]; then
            # Cut at TRUNCATION_LIMIT bytes (head -c is byte-safe on Linux/macOS)
            cmd_cut="$(printf '%s' "$raw_cmd" | head -c "$TRUNCATION_LIMIT")"
            summary="${cmd_cut}${TRUNCATION_MARKER}"
        else
            summary="$raw_cmd"
        fi
        ;;
    Read|Edit|Write)
        # For file tools: file_path only — drop content / old_string / new_string (R6.3)
        summary="$(printf '%s' "$stdin_data" | jq -r '.tool_input.file_path // "(summary unavailable)"')"
        ;;
    *)
        # For any other tool: extract the first string field whose key name matches
        # a safe allow-list pattern (path, file, name, url, id, query, action,
        # description). Keys that match sensitive patterns (key, secret, password,
        # token, credential, auth, connection) are never logged regardless of
        # insertion order. Falls back to "(summary unavailable)" for unknown tools
        # or when no safe field is found. (R6.3, ADR-004, security fix)
        summary="$(printf '%s' "$stdin_data" | jq -r '
            .tool_input
            | if type == "object" then
                to_entries
                | map(select(
                    (.value | type == "string") and
                    (.key | test("path|file|name|url|id|query|action|description"; "i")) and
                    (.key | test("key|secret|password|token|credential|auth|connection"; "i") | not)
                  ))
                | first
                | .value // "(summary unavailable)"
              else
                "(summary unavailable)"
              end
        ' 2>/dev/null)" || summary="(summary unavailable)"
        # Ensure jq returned a non-empty value (empty string from a matching field
        # that is itself empty should still fall back gracefully).
        [[ -n "$summary" ]] || summary="(summary unavailable)"
        ;;
esac

# ---------------------------------------------------------------------------
# Build the audit record with jq (injection-safe by construction, R6.4, ADR-004)
# All field values go through --arg / --argjson so jq handles escaping.
# ---------------------------------------------------------------------------

record="$(jq -cn \
    --arg ts "$ts" \
    --arg session_id "$session_id" \
    --arg tool_name "$tool_name" \
    --arg tool_input_summary "$summary" \
    --argjson exit_code "$exit_code_raw" \
    '{
        "ts": $ts,
        "session_id": $session_id,
        "tool_name": $tool_name,
        "tool_input_summary": $tool_input_summary,
        "exit_code": $exit_code,
        "decision": "logged"
    }')"

append_record "$record"
exit 0
