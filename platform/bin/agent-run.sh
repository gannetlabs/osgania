#!/usr/bin/env bash
# /opt/osgania/platform/bin/agent-run.sh — root:root 0755
# Launch wrapper (ADR-6): source the API key from the systemd LoadCredential
# tmpfs into ANTHROPIC_API_KEY, then exec the real CLI. The key value never
# appears in the unit file, the journal, or any versioned file — only in this
# process's env at runtime (read from $CREDENTIALS_DIRECTORY, a per-unit
# non-swappable tmpfs). Spec: HA-05.1, HA-05.1a, HA-08.4.
set -euo pipefail
: "${CREDENTIALS_DIRECTORY:?CREDENTIALS_DIRECTORY is not set — agent-run.sh must run under systemd LoadCredential}"
# Strip ALL whitespace (trailing newline, a CRLF \r from a Windows-pasted key,
# stray surrounding spaces). A valid Anthropic key contains no whitespace, so
# [:space:] removal is lossless and prevents the opaque 401 this pivot exists
# to escape. export-then-assign (NOT `export X=$(...)`) keeps set -e fail-closed.
export ANTHROPIC_API_KEY
ANTHROPIC_API_KEY="$(tr -d '[:space:]' < "${CREDENTIALS_DIRECTORY}/anthropic-api-key")"
[[ -n "$ANTHROPIC_API_KEY" ]] || { printf 'agent-run.sh: API key file is empty or whitespace-only\n' >&2; exit 1; }
exec /usr/bin/claude "$@"
