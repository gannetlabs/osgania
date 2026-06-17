#!/usr/bin/env bats
# camara.bats — bats-core test suite for platform/hooks/camara.sh (PostToolUse audit hook)
#
# Scenarios: CA-01..CA-10, CL-01
# Requirements: R5.4, R5.5, R6.1..R6.4, R7.1a, R7.3, R7.5, R8.4
#
# All camara tests:
#   - Export AUDIT_LOG to a BATS_TMPDIR temp file (R7.1a override, never touches production path)
#   - Pipe JSON to camara.sh via STDIN
#   - Assert on the temp audit file contents using jq

load test_helper

CAMARA="platform/hooks/camara.sh"

setup() {
    setup_audit_log
}

teardown() {
    teardown_audit_log
}

# ---------------------------------------------------------------------------
# CA-01 — Bash tool call produces an audit record
# Requirements: R5.5, R6.1, R6.2
# ---------------------------------------------------------------------------

@test "CA-01 Bash tool call produces audit record with correct fields" {
    local json
    json='{"session_id":"test-session-001","tool_name":"Bash","tool_input":{"command":"ls /tmp"},"tool_response":{"exit_code":0}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    # A new line must have been appended
    local line_count
    line_count="$(count_audit_lines)"
    [ "$line_count" -eq 1 ]

    # The line must be valid JSON
    parse_audit_last_line '.' > /dev/null

    # Check individual fields
    local ts session_id tool_name tool_input_summary decision
    ts="$(parse_audit_last_line '.ts')"
    session_id="$(parse_audit_last_line -r '.session_id')"
    tool_name="$(parse_audit_last_line -r '.tool_name')"
    tool_input_summary="$(parse_audit_last_line -r '.tool_input_summary')"
    decision="$(parse_audit_last_line -r '.decision')"

    # ts must be a non-empty ISO 8601 UTC string (e.g. 2026-06-14T10:23:45Z)
    [ -n "$ts" ]
    printf '%s' "$ts" | grep -qE '^"?[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"?$'

    [ "$session_id" = "test-session-001" ]
    [ "$tool_name" = "Bash" ]
    [ "$tool_input_summary" = "ls /tmp" ]
    [ "$decision" = "logged" ]
}

# ---------------------------------------------------------------------------
# CA-02 — Read tool call produces audit record
# Requirements: R5.5, R6.2
# ---------------------------------------------------------------------------

@test "CA-02 Read tool call produces audit record with file path summary" {
    local json
    json='{"session_id":"test-session-002","tool_name":"Read","tool_input":{"file_path":"/home/aios/app/config.js"},"tool_response":{}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]
    parse_audit_last_line '.' > /dev/null

    local tool_name tool_input_summary decision
    tool_name="$(parse_audit_last_line -r '.tool_name')"
    tool_input_summary="$(parse_audit_last_line -r '.tool_input_summary')"
    decision="$(parse_audit_last_line -r '.decision')"

    [ "$tool_name" = "Read" ]
    # summary must identify the file path
    printf '%s' "$tool_input_summary" | grep -q '/home/aios/app/config.js'
    [ "$decision" = "logged" ]
}

# ---------------------------------------------------------------------------
# CA-03 — Edit tool call: old_string/new_string MUST be redacted
# Requirements: R5.5, R6.2, R6.3
# ---------------------------------------------------------------------------

@test "CA-03 Edit tool call summary contains file_path but NOT old_string or new_string" {
    local json
    json='{"session_id":"test-session-003","tool_name":"Edit","tool_input":{"file_path":"/home/aios/app/index.js","old_string":"foo","new_string":"bar"},"tool_response":{}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]
    parse_audit_last_line '.' > /dev/null

    local tool_name tool_input_summary decision
    tool_name="$(parse_audit_last_line -r '.tool_name')"
    tool_input_summary="$(parse_audit_last_line -r '.tool_input_summary')"
    decision="$(parse_audit_last_line -r '.decision')"

    [ "$tool_name" = "Edit" ]
    # file_path must appear
    printf '%s' "$tool_input_summary" | grep -q '/home/aios/app/index.js'
    # old_string and new_string must NOT appear
    if printf '%s' "$tool_input_summary" | grep -q 'foo'; then
        echo "FAIL: old_string 'foo' found in tool_input_summary (must be redacted)"
        return 1
    fi
    if printf '%s' "$tool_input_summary" | grep -q 'bar'; then
        echo "FAIL: new_string 'bar' found in tool_input_summary (must be redacted)"
        return 1
    fi
    [ "$decision" = "logged" ]
}

# ---------------------------------------------------------------------------
# CA-04 — Write tool call: content MUST be redacted
# Requirements: R5.5, R6.2, R6.3
# ---------------------------------------------------------------------------

@test "CA-04 Write tool call summary contains file_path but NOT file content" {
    local json
    json='{"session_id":"test-session-004","tool_name":"Write","tool_input":{"file_path":"/home/aios/app/new-file.js","content":"this is secret content that should never appear in audit"},"tool_response":{}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]
    parse_audit_last_line '.' > /dev/null

    local tool_name tool_input_summary decision
    tool_name="$(parse_audit_last_line -r '.tool_name')"
    tool_input_summary="$(parse_audit_last_line -r '.tool_input_summary')"
    decision="$(parse_audit_last_line -r '.decision')"

    [ "$tool_name" = "Write" ]
    printf '%s' "$tool_input_summary" | grep -q '/home/aios/app/new-file.js'
    if printf '%s' "$tool_input_summary" | grep -q 'secret content'; then
        echo "FAIL: file content found in tool_input_summary (must be redacted)"
        return 1
    fi
    [ "$decision" = "logged" ]
}

# ---------------------------------------------------------------------------
# CA-05 — Multiple sequential calls produce appended lines; earlier lines unchanged
# Requirements: R6.1, R7.3, R7.5
# ---------------------------------------------------------------------------

@test "CA-05 three sequential calls produce exactly 3 appended lines, all valid JSON, earlier lines unchanged" {
    local json1 json2 json3
    json1='{"session_id":"sess-A","tool_name":"Bash","tool_input":{"command":"echo one"},"tool_response":{"exit_code":0}}'
    json2='{"session_id":"sess-B","tool_name":"Read","tool_input":{"file_path":"/tmp/a.txt"},"tool_response":{}}'
    json3='{"session_id":"sess-C","tool_name":"Bash","tool_input":{"command":"echo three"},"tool_response":{"exit_code":0}}'

    send_stdin_to_hook "$json1" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]
    send_stdin_to_hook "$json2" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]
    send_stdin_to_hook "$json3" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 3 ]

    # Each line must parse as valid JSON independently
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '%s' "$line" | jq -e '.' > /dev/null
    done < "$AUDIT_LOG"

    # First line must still be from sess-A (append-only, not overwritten)
    local first_session
    first_session="$(head -n 1 "$AUDIT_LOG" | jq -r '.session_id')"
    [ "$first_session" = "sess-A" ]
}

# ---------------------------------------------------------------------------
# CA-06 — Audit log is valid JSON Lines after repeated appends
# Requirements: R7.5
# ---------------------------------------------------------------------------

@test "CA-06 audit log is valid JSON Lines after repeated appends (N+1 lines all parseable)" {
    # Pre-populate log with 2 valid JSON lines
    printf '%s\n' '{"ts":"2026-01-01T00:00:00Z","session_id":"pre-1","tool_name":"Bash","tool_input_summary":"pre","exit_code":0,"decision":"logged"}' >> "$AUDIT_LOG"
    printf '%s\n' '{"ts":"2026-01-01T00:00:01Z","session_id":"pre-2","tool_name":"Read","tool_input_summary":"/tmp/x","exit_code":null,"decision":"logged"}' >> "$AUDIT_LOG"

    local json
    json='{"session_id":"sess-new","tool_name":"Bash","tool_input":{"command":"echo new"},"tool_response":{"exit_code":0}}'
    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 3 ]

    # All 3 lines must be independently parseable as JSON
    local line_num=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        line_num=$((line_num + 1))
        if ! printf '%s' "$line" | jq -e '.' > /dev/null; then
            echo "FAIL: line $line_num is not valid JSON: $line"
            return 1
        fi
        # No trailing commas — JSON object must not end with ,}
        if printf '%s' "$line" | grep -qE ',\s*\}'; then
            echo "FAIL: line $line_num has trailing comma"
            return 1
        fi
    done < "$AUDIT_LOG"

    # No enclosing array brackets
    if head -n 1 "$AUDIT_LOG" | grep -q '^\['; then
        echo "FAIL: audit log starts with '[' — must be JSON Lines, not array"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# CA-07 — Special characters in command are JSON-escaped correctly
# Requirements: R6.4
# ---------------------------------------------------------------------------

@test "CA-07 command with special chars (quotes, newlines) produces valid JSON audit record" {
    # Command contains double-quotes and a backslash-n escape sequence
    local json
    json='{"session_id":"sess-escape","tool_name":"Bash","tool_input":{"command":"echo \"hello\\nworld\""},"tool_response":{"exit_code":0}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    # The line MUST parse as valid JSON (no escaping break)
    parse_audit_last_line '.' > /dev/null

    # tool_input_summary must be a string (not broken)
    local summary_type
    summary_type="$(parse_audit_last_line '.tool_input_summary | type')"
    [ "$summary_type" = '"string"' ]
}

# ---------------------------------------------------------------------------
# CA-08 — Malformed STDIN: camara exits 0 and either appends record or warns
# Requirements: R8.4, R5.4
# ---------------------------------------------------------------------------

@test "CA-08 malformed STDIN (empty) causes exit 0 with either minimal record or stderr warning" {
    send_stdin_to_hook_with_stderr "" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    # Either: a minimal audit record was appended (decision contains "parse-error")
    # OR: a warning was written to stderr.
    local lines
    lines="$(count_audit_lines)"
    if [ "$lines" -gt 0 ]; then
        # A minimal record must be valid JSON
        parse_audit_last_line '.' > /dev/null
        # Decision should indicate parse error
        local decision
        decision="$(parse_audit_last_line -r '.decision')"
        printf '%s' "$decision" | grep -q 'parse-error'
    else
        # No record appended — must have written a warning to stderr
        [ -n "$HOOK_STDERR" ]
    fi
}

# ---------------------------------------------------------------------------
# CA-09 — Audit record does NOT contain full tool_response body (no secret leak)
# Requirements: R6.3
# ---------------------------------------------------------------------------

@test "CA-09 audit record does NOT contain tool_response body (no secret leak)" {
    local json
    json='{"session_id":"sess-secret","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":{"stdout":"SECRET_API_KEY=abc123\nother output","exit_code":0}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    # The audit line MUST NOT contain the secret value
    local raw_line
    raw_line="$(cat "$AUDIT_LOG")"
    if printf '%s' "$raw_line" | grep -q 'SECRET_API_KEY=abc123'; then
        echo "FAIL: tool_response secret value found in audit record"
        return 1
    fi

    # exit_code must still be captured
    local exit_code
    exit_code="$(parse_audit_last_line '.exit_code')"
    [ "$exit_code" = "0" ]
}

# ---------------------------------------------------------------------------
# CA-10 — tool_input_summary is truncated to 512 bytes with ellipsis marker
# Requirements: R6.2 (truncation), R7.3 (atomic append)
# N1 rule: 512 bytes content + "…[truncated]" (14 bytes) = 526 bytes max
# ---------------------------------------------------------------------------

@test "CA-10 long Bash command is truncated to 512 bytes with ellipsis marker in summary" {
    # Build a command of 600 'x' characters (> 512)
    local long_cmd
    long_cmd="$(python3 -c "print('x' * 600, end='')")"
    local json
    json="$(jq -cn --arg cmd "$long_cmd" \
        '{"session_id":"sess-trunc","tool_name":"Bash","tool_input":{"command":$cmd},"tool_response":{"exit_code":0}}')"

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    # Must be valid JSON
    parse_audit_last_line '.' > /dev/null

    # Extract tool_input_summary (raw string value)
    local summary
    summary="$(parse_audit_last_line -r '.tool_input_summary')"

    # Must end with "…[truncated]"
    local marker="…[truncated]"
    if [[ "$summary" != *"$marker" ]]; then
        echo "FAIL: tool_input_summary does not end with '…[truncated]'"
        echo "Got: $summary"
        return 1
    fi

    # Byte length must be <= 526 (512 content + 14 marker)
    local byte_len
    byte_len="$(printf '%s' "$summary" | wc -c | tr -d ' ')"
    if [ "$byte_len" -gt 526 ]; then
        echo "FAIL: tool_input_summary is $byte_len bytes, expected <= 526"
        return 1
    fi

    # The record itself must be a single newline-terminated line (no embedded newlines)
    local raw_line
    raw_line="$(cat "$AUDIT_LOG")"
    local newline_count
    # Count newlines — wc -l counts trailing \n too, so result should be 1
    newline_count="$(printf '%s' "$raw_line" | wc -l | tr -d ' ')"
    [ "$newline_count" -eq 0 ]  # printf '%s' strips the trailing newline; 0 embedded newlines
}

# ---------------------------------------------------------------------------
# CL-01 — shellcheck passes on camara.sh
# Requirements: R8.2
# ---------------------------------------------------------------------------

@test "CL-01 shellcheck passes on camara.sh with zero warnings" {
    run shellcheck -s bash "$CAMARA"
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# CA-11 — MCP tool with credential as first field must NOT leak the value
# Regression for: secret-leak via wildcard case blind first-field heuristic
# Requirements: R6.3, ADR-004
# ---------------------------------------------------------------------------

@test "CA-11 MCP tool with connection_string credential does not appear in audit log" {
    local json
    json='{"session_id":"sess-mcp","tool_name":"mcp__database__execute","tool_input":{"connection_string":"postgresql://admin:S3cr3tP@ssw0rd@db.internal/prod","query":"SELECT 1"},"tool_response":{}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    # The audit record must be valid JSON and must be a single line
    parse_audit_last_line '.' > /dev/null

    # The credential value MUST NOT appear anywhere in the log
    local raw_line
    raw_line="$(cat "$AUDIT_LOG")"
    if printf '%s' "$raw_line" | grep -q 'S3cr3tP'; then
        echo "FAIL: credential value 'S3cr3tP' found in audit record (secret leak)"
        return 1
    fi
    if printf '%s' "$raw_line" | grep -q 'connection_string'; then
        echo "FAIL: credential field name 'connection_string' found in audit record"
        return 1
    fi

    # The record must still be one JSON line (no injection, no newline splitting)
    local newline_count
    newline_count="$(printf '%s' "$raw_line" | wc -l | tr -d ' ')"
    [ "$newline_count" -eq 0 ]

    # summary must NOT contain the credential — it may be a safe field value
    # (e.g. "SELECT 1" from the "query" field) or the placeholder; both are acceptable
    local summary
    summary="$(parse_audit_last_line -r '.tool_input_summary')"
    if printf '%s' "$summary" | grep -q 'S3cr3tP'; then
        echo "FAIL: credential value 'S3cr3tP' present in tool_input_summary"
        return 1
    fi
    if printf '%s' "$summary" | grep -q 'postgresql'; then
        echo "FAIL: credential connection string present in tool_input_summary"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# CA-12 — Unknown tool with api_key as only field must NOT leak the key value
# Regression for: secret-leak via wildcard case blind first-field heuristic
# Requirements: R6.3, ADR-004
# ---------------------------------------------------------------------------

@test "CA-12 unknown tool with api_key field does not leak key value in audit log" {
    local json
    json='{"session_id":"sess-custom","tool_name":"CustomTool","tool_input":{"api_key":"SUPERSECRET_KEY_XYZ"},"tool_response":{}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    # The audit record must be valid JSON
    parse_audit_last_line '.' > /dev/null

    # The secret value MUST NOT appear in the log
    local raw_line
    raw_line="$(cat "$AUDIT_LOG")"
    if printf '%s' "$raw_line" | grep -q 'SUPERSECRET_KEY_XYZ'; then
        echo "FAIL: secret value 'SUPERSECRET_KEY_XYZ' found in audit record (secret leak)"
        return 1
    fi

    # summary must fall back to the safe placeholder
    local summary
    summary="$(parse_audit_last_line -r '.tool_input_summary')"
    [ "$summary" = "(summary unavailable)" ]
}

# ---------------------------------------------------------------------------
# CA-13 — Unknown tool with a safe path-like field DOES log that field value
# Ensures the fix does not over-block legitimate safe summaries
# Requirements: R6.3, ADR-004
# ---------------------------------------------------------------------------

@test "CA-13 unknown tool with file_path field logs the path value safely" {
    local json
    json='{"session_id":"sess-safetool","tool_name":"SomeMcpFileTool","tool_input":{"file_path":"/home/aios/data/report.csv","api_key":"should-not-appear"},"tool_response":{}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    parse_audit_last_line '.' > /dev/null

    # The api_key value MUST NOT appear
    local raw_line
    raw_line="$(cat "$AUDIT_LOG")"
    if printf '%s' "$raw_line" | grep -q 'should-not-appear'; then
        echo "FAIL: api_key value found in audit record (secret leak)"
        return 1
    fi

    # The safe file_path value MUST appear in the summary
    local summary
    summary="$(parse_audit_last_line -r '.tool_input_summary')"
    printf '%s' "$summary" | grep -q '/home/aios/data/report.csv'
}

# ---------------------------------------------------------------------------
# CA-14 — exit_code type coercion: non-integer values become null (R6.2)
# Regression for: object/array/string/float must not reach the audit record.
# ---------------------------------------------------------------------------

@test "CA-14a exit_code object is coerced to null in audit record" {
    local json
    json='{"session_id":"sess-ec-obj","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":{"exit_code":{"injected":"x"}}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    parse_audit_last_line '.' > /dev/null

    # exit_code must be JSON null, not an object
    local ec_type
    ec_type="$(parse_audit_last_line '.exit_code | type')"
    [ "$ec_type" = '"null"' ]
}

@test "CA-15 unexpected internal jq error during processing does NOT cause non-zero exit (fail-open trap)" {
    # Feed a payload engineered to stress processing: valid JSON shell with deeply nested
    # fields and a tool_input.command value containing special characters that exercise
    # the jq pipeline.  The trap 'exit 0' EXIT must guarantee exit status 0 even if
    # an internal subshell or jq call fails for any reason.
    local json
    json="$(jq -cn --arg cmd "$(python3 -c "import sys; sys.stdout.write('x' * 512 + ' && echo y' + '\"' * 50)")" \
        '{"session_id":"sess-trap","tool_name":"Bash","tool_input":{"command":$cmd},"tool_response":{"exit_code":0}}')"

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]
}

@test "CA-14b exit_code integer 0 is preserved as 0 in audit record" {
    local json
    json='{"session_id":"sess-ec-int","tool_name":"Bash","tool_input":{"command":"true"},"tool_response":{"exit_code":0}}'

    send_stdin_to_hook "$json" "$CAMARA"
    [ "$HOOK_STATUS" -eq 0 ]

    [ "$(count_audit_lines)" -eq 1 ]

    parse_audit_last_line '.' > /dev/null

    local ec
    ec="$(parse_audit_last_line '.exit_code')"
    [ "$ec" = "0" ]
}
