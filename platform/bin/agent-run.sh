#!/usr/bin/env bash
# /opt/osgania/platform/bin/agent-run.sh — root:root 0755
# Launch wrapper (2b / PRODUCTION LAUNCHER, NOT a transparent pass-through).
# Sources the API key from the systemd LoadCredential tmpfs into ANTHROPIC_API_KEY,
# then execs the real CLI with the canonical prompt-file invocation.
#
# IMPORTANT (JD-6 / HB-01.3): This wrapper hardcodes the entire claude invocation:
#   exec /usr/bin/claude --permission-mode dontAsk --settings /opt/osgania/platform/agent-settings.json --setting-sources "" -p "$(cat "$PROMPT_FILE")"
# "$@" is NOT forwarded to claude; only the HB-01.8 -p guard checks it.
# Any caller that needs different claude args (e.g. --output-format stream-json)
# MUST invoke /usr/bin/claude DIRECTLY — do NOT route through this wrapper.
#
# Spec: HA-05.1, HA-05.1a, HA-08.4, HB-01.3, HB-01.4, HB-01.6, HB-01.7, HB-01.8
set -euo pipefail
: "${CREDENTIALS_DIRECTORY:?CREDENTIALS_DIRECTORY is not set — agent-run.sh must run under systemd LoadCredential}"
# Strip ALL whitespace (trailing newline, a CRLF \r from a Windows-pasted key,
# stray surrounding spaces). A valid Anthropic key contains no whitespace, so
# [:space:] removal is lossless and prevents the opaque 401 this pivot exists
# to escape. export-then-assign (NOT `export X=$(...)`) keeps set -e fail-closed.
export ANTHROPIC_API_KEY
ANTHROPIC_API_KEY="$(tr -d '[:space:]' < "${CREDENTIALS_DIRECTORY}/anthropic-api-key")"
[[ -n "$ANTHROPIC_API_KEY" ]] || { printf 'agent-run.sh: API key file is empty or whitespace-only\n' >&2; exit 1; }

# Canonical prompt file path (HB-01.4): root-owned, outside the agent-writable
# /opt/osgania/client/ subtree. The agent CAN read but CANNOT write this file.
PROMPT_FILE="/opt/osgania/platform/prompts/agent-prompt.txt"

# HB-01.8: guard against direct interactive invocation without -p.
# Iterate over "$@" as standalone positional arguments — do NOT use a $* substring
# match (which would falsely trigger on a value argument containing the chars "-p").
_found_p=0
for _arg in "$@"; do
    [[ "$_arg" == "-p" ]] && _found_p=1 && break
done
if [[ "$_found_p" -eq 0 ]]; then
    printf 'agent-run.sh: -p argument is required; refusing to exec claude without it\n' >&2
    exit 1
fi
unset _found_p _arg

# Production launch: hardcoded canonical invocation (HB-01.3).
# --permission-mode dontAsk MUST precede --settings, --setting-sources, and -p.
# --settings loads the operator-managed allow[] from the root-owned platform layer;
# the agent (aios) can read but NOT write this file (managed deny blocks Edit/Write
# under /opt/osgania/platform/**). No chattr needed: ownership + root-owned parent suffice.
# --setting-sources "" excludes user/project/local settings so the agent cannot
# self-escalate by writing its own settings.json (allow[] is additive across sources;
# an agent-writable source could otherwise add allow entries beyond the reviewed set).
AGENT_SETTINGS_FILE="/opt/osgania/platform/agent-settings.json"
exec /usr/bin/claude --permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p "$(cat "$PROMPT_FILE")"
