#!/usr/bin/env bash
# guardia.sh — PreToolUse hook: token-aware denylist veto
#
# Interface (Claude Code hook contract):
#   Input:  single JSON object on STDIN (tool_name, tool_input, session_id)
#   Output: hookSpecificOutput JSON on STDOUT (ONLY on deny; empty on pass-through)
#   Exit:   always 0 (R1.5)
#
# Decision algorithm (ordered, spec R2.1..R2.7, 2b Amendment A1):
#   0. tool_name != "Bash"          → pass-through (exit 0, empty stdout) [2b: was defer; HB-04.3]
#   1. empty/invalid STDIN          → pass-through (exit 0, empty stdout) [2b: was defer; HB-04.3]
#   2. sudo token boundary match    → deny   (R2.1)
#   3. curl/wget token boundary     → deny   (R2.2)
#   4. rm -rf two-pass flag check   → deny   (R2.3)
#   5. disk-wipe leading token      → deny   (R2.4)
#   6. /etc/osgania/secrets substr  → deny   (R2.5)
#   7. platform/ substring          → deny   (R2.6)
#   8. else                         → pass-through (exit 0, empty stdout) [2b: was defer; HB-04.1]
#
# 2b Amendment A1 (PSC R2.7): ALL non-deny branches now emit NOTHING and exit 0
# (pass-through). Previously they emitted permissionDecision:"defer". Hardware gate
# #1 exp6 proved defer is TERMINAL in headless -p and pre-empts the permission flow,
# blocking even allowlisted non-Bash tools. Pass-through lets the normal flow
# (deny[] → ask → allow[]) decide. Unit 3 only (2b).
#
# guardia has exactly ONE non-deny outcome: pass-through (exit 0, empty stdout).
# It emits deny or it emits nothing. It never emits allow, ask, or defer. (HB-04)
#
# Non-goals:
#   - No network calls (R4.1)
#   - No filesystem reads beyond STDIN (R4.2)
#   - Never emits "allow" (R1.4)

# Do NOT use set -e here: grep returns 1 on no-match (expected), which would
# abort the script under set -e. Use explicit error checking instead.
set -uo pipefail

# ---------------------------------------------------------------------------
# Output helpers — always built with jq so reason strings are JSON-escaped.
# ---------------------------------------------------------------------------

emit_deny() {
    local reason="$1"
    jq -cn \
        --arg reason "$reason" \
        '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
    exit 0
}

# ---------------------------------------------------------------------------
# Step 1 / Step 0 — read and parse STDIN
# ---------------------------------------------------------------------------

stdin_data="$(cat)"

# Guard: empty STDIN → pass-through (R4.5; 2b Amendment A1: was emit_defer)
# Hardware gate #1: defer is TERMINAL in headless -p; pass-through is safe.
if [[ -z "$stdin_data" ]]; then
    exit 0
fi

# Parse tool_name from JSON; on invalid JSON jq will fail → pass-through (R4.5; 2b Amendment A1)
tool_name="$(printf '%s' "$stdin_data" | jq -r '.tool_name // empty' 2>/dev/null)" || true

if [[ -z "$tool_name" ]]; then
    exit 0
fi

# Step 0: only Bash tool calls are subject to the denylist (R1.6; 2b Amendment A1)
# Non-Bash tools → pass-through (HB-04.3). Previously emitted defer which blocked
# allowlisted non-Bash tools (Read, Write) in headless -p (gate #1).
if [[ "$tool_name" != "Bash" ]]; then
    exit 0
fi

# Extract the command string
cmd="$(printf '%s' "$stdin_data" | jq -r '.tool_input.command // empty' 2>/dev/null)" || true

# Missing or empty command → pass-through (2b Amendment A1: was emit_defer)
if [[ -z "$cmd" ]]; then
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 2 — sudo check (R2.1)
# ERE word boundary: (^|[^[:alnum:]_])sudo([^[:alnum:]_]|$), case-insensitive.
# Catches: "sudo ...", "... && sudo ...", "SUDO ...", "Sudo ..."
# Rejects:  "pseudo-random-generator", "sudoers"
# Note: real privilege-escalation containment is the managed-settings deny
# rule (Bash(sudo *)) and OS sudoers; this case-insensitive match is
# defense-in-depth only.
# ---------------------------------------------------------------------------

if printf '%s' "$cmd" | grep -iqE '(^|[^[:alnum:]_])sudo([^[:alnum:]_]|$)'; then
    emit_deny "[guardia] denied: sudo — privilege escalation is not permitted"
fi

# ---------------------------------------------------------------------------
# Step 3 — curl / wget check (R2.2)
# Same word-boundary template for both tokens, case-insensitive.
# Catches: "curl ...", "wget ...", "CURL ...", "WGET ...", "Curl ..."
# Rejects:  "curling", "wgetrc"
# Note: real network containment is the egress firewall and the
# managed-settings deny rules (Bash(curl *)/Bash(wget *)); this
# case-insensitive match is defense-in-depth only.
# ---------------------------------------------------------------------------

if printf '%s' "$cmd" | grep -iqE '(^|[^[:alnum:]_])(curl|wget)([^[:alnum:]_]|$)'; then
    emit_deny "[guardia] denied: network — curl/wget outbound calls are not permitted"
fi

# ---------------------------------------------------------------------------
# Step 4 — rm -rf two-pass check (R2.3)
# Pass A: command contains a bounded "rm" token.
# Pass B: combined flag letters from all short -xyz groups, PLUS explicit
#         checks for GNU long-form --recursive and --force, must include
#         both r/R AND f (in any combination of short/long forms).
# Catches: rm -rf, rm -fr, rm -r -f, rm -Rf, rm --recursive --force,
#          rm -r --force, rm --recursive -f
# Rejects:  rm -r (no -f), rm -f (no -r)
# ---------------------------------------------------------------------------

if printf '%s' "$cmd" | grep -qE '(^|[^[:alnum:]_])rm([^[:alnum:]_]|$)'; then
    # Collect all letters from short flag clusters (strips dashes, concatenates)
    flags_letters="$(printf '%s' "$cmd" | grep -oE '[[:space:]]-[A-Za-z]+' | tr -d ' -' | tr -d '\n')"

    has_recursive=false
    has_force=false

    # Check for r or R in the collected short flag letters
    if printf '%s' "$flags_letters" | grep -q '[rR]'; then
        has_recursive=true
    fi
    # Check for GNU long-form --recursive
    if printf '%s' "$cmd" | grep -qE '(^|[[:space:]])--recursive([[:space:]]|$)'; then
        has_recursive=true
    fi

    # Check for f in the collected short flag letters
    if printf '%s' "$flags_letters" | grep -q 'f'; then
        has_force=true
    fi
    # Check for GNU long-form --force
    if printf '%s' "$cmd" | grep -qE '(^|[[:space:]])--force([[:space:]]|$)'; then
        has_force=true
    fi

    if [[ "$has_recursive" == "true" && "$has_force" == "true" ]]; then
        emit_deny "[guardia] denied: rm -rf — recursive forced deletion is not permitted"
    fi
fi

# ---------------------------------------------------------------------------
# Step 5 — disk-wipe leading token check (R2.4)
# Strip leading whitespace and env-var assignments (VAR=value prefixes),
# then deny if the first real token is: dd, wipefs, or mkfs(.*)?.
# The deny reason MUST include the matched token (spec GD-11/12/13).
# Non-goal (v1): chained form "echo ... && dd ..." is NOT caught (GD-N6).
# ---------------------------------------------------------------------------

# Use parameter expansion to strip leading whitespace
# (no external command needed — avoids pipefail issues)
stripped="${cmd#"${cmd%%[! ]*}"}"

# Strip leading VAR=value tokens (e.g. "FOO=bar BAZ=qux cmd args").
# Pattern requires: identifier immediately followed by =, then zero or more
# non-space characters (empty assignments like A= are valid shell prefixes),
# then a space or end-of-string. This avoids false-matching commands whose
# arguments contain = (e.g. "dd if=/dev/zero" — "if" is a word but "dd if=..."
# does NOT start with "IDENTIFIER=" immediately).
# Each iteration removes one VAR=value prefix.
while [[ "$stripped" =~ ^[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*([[:space:]]|$) ]]; do
    # Remove up to and including the first space
    stripped="${stripped#* }"
    # Strip any additional leading whitespace
    stripped="${stripped#"${stripped%%[! ]*}"}"
    [[ -z "$stripped" ]] && break
done

# Extract leading token: everything up to the first whitespace or special char
leading_token="${stripped%%[ 	;|&]*}"
# Normalise to basename so absolute paths like /bin/dd and /sbin/wipefs are
# caught the same as bare names (e.g. leading_token=/bin/dd → base=dd).
leading_token_base="${leading_token##*/}"

if [[ "$leading_token_base" == "dd" || "$leading_token_base" == "wipefs" ]]; then
    emit_deny "[guardia] denied: disk-wipe — leading token '$leading_token_base' is a low-level disk tool"
fi

# Check mkfs or mkfs.variant
if printf '%s' "$leading_token_base" | grep -qE '^mkfs(\..*)?$'; then
    emit_deny "[guardia] denied: disk-wipe — leading token '$leading_token_base' is a low-level disk tool"
fi

# ---------------------------------------------------------------------------
# Step 6 — secrets path check (R2.5)
# Fixed substring: /etc/osgania/secrets (no trailing slash) anywhere in the
# command. The trailing-slash-free form catches both directory references
# (ls /etc/osgania/secrets, find /etc/osgania/secrets -type f) and file
# references (/etc/osgania/secrets/db_password) — every existing case still
# matches because /etc/osgania/secrets/ contains /etc/osgania/secrets as a
# prefix. Covers cat, less, command substitution, any mechanism naming the path.
# ---------------------------------------------------------------------------

if [[ "$cmd" == *"/etc/osgania/secrets"* ]]; then
    emit_deny "[guardia] denied: secrets — access to secrets path is not permitted"
fi

# ---------------------------------------------------------------------------
# Step 7 — platform/ path check (R2.6)
# Matches the operator platform tree only — not unrelated paths that contain
# "platform" as a non-leading path segment (e.g. "cross-platform/").
#
# Two cases are denied:
#   a) Absolute path: /opt/osgania/platform/ anywhere in the command.
#   b) Relative path: "platform/" where "platform" begins a path token, i.e.
#      it is preceded by start-of-string, whitespace, a quote ('"' or "'"),
#      '=', or '(' — meaning it cannot be preceded by a word character or '-'.
#      This rejects "cross-platform/", "my-platform/", etc.
#
# Intentional false-positive: "cat platform/README.md" is also denied — this
# is correct per spec R2.6 and ADR-003 (agent has no legitimate need to name
# paths under platform/ in a Bash command).
# ---------------------------------------------------------------------------

if printf '%s' "$cmd" | grep -qE '/opt/osgania/platform/|(^|[[:space:]"'\''=(])(platform/)'; then
    emit_deny "[guardia] denied: platform — agent commands may not reference the platform directory"
fi

# ---------------------------------------------------------------------------
# Step 7.5 — env-dump + bash-native egress (R2 extension, spec HA-15 / ADR-7)
#
# PIVOT mitigation: the API key now lives in ANTHROPIC_API_KEY in the agent's
# environment (and is inherited by Bash-tool children), so deny the obvious
# ways to print the environment, plus bash's /dev/tcp,/dev/udp network
# pseudo-device. SPEED-BUMP ONLY (HA-15.6): does NOT stop interpreters
# (python/node/awk) or a bare `echo "$VAR"`/${!x} — those are contained by
# single-tenancy + the 2b egress firewall, not by guardia.
#
# Placed AFTER the secrets (Step 6) and platform (Step 7) checks so that a
# command matching BOTH an inherited category and env-dump keeps the INHERITED
# deny reason (first-match-wins; spec HA-15.5 / HA-15-S7).
#
# MUST NOT false-positive the ubiquitous benign forms (spec HA-15.3):
#   set -e / set -euo pipefail / set -o pipefail / set +e
#   declare -i x / declare -a x / declare x=1 / export FOO=bar
#   env FOO=bar cmd / env -u FOO cmd / env -i cmd
# Each matcher denies ONLY the dump form; when a form cannot be cleanly
# distinguished with guardia's no-shell-parser model, it FAILS OPEN (defer).
# ---------------------------------------------------------------------------

# Bash-native egress: /dev/tcp,/dev/udp substrings (HA-15.5a). A curl/wget-free
# exfil channel; legitimate agent commands almost never name these.
if [[ "$cmd" == *"/dev/tcp"* || "$cmd" == *"/dev/udp"* ]]; then
    emit_deny "[guardia] denied: net-builtin — bash /dev/tcp,/dev/udp network pseudo-device is not permitted"
fi

# env-dump: read of /proc/<pid>/environ for any pid form — self, thread-self, numeric,
# $$, $BASHPID, a bare $VAR ($PPID/$PID/…), ${...}, plus the per-thread /task/<tid>/ alias.
# tool-agnostic — matches any reader that NAMES the path (HA-15.2).
# SC2016: the `\$` sequences are LITERAL dollar signs in the ERE (matching the
# shell-syntax pid forms $$, $BASHPID, ${...} as they appear in the command
# STRING), not shell expansions — single quotes are intentional.
# shellcheck disable=SC2016
if printf '%s' "$cmd" | grep -qE '/proc/(self|thread-self|[0-9]+|\$\$|\$BASHPID|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]*\})(/task/[^/]+)?/environ'; then
    emit_deny "[guardia] denied: env-dump — reading the process environ is not permitted"
fi

# env-dump: printenv as a COMMAND WORD (its sole purpose is printing the env).
# Leading boundary excludes '/', trailing requires space/pipe/;/&/EOL, so a mere
# filename like printenv.sh / scripts/printenv.md defers (Phase-3 false-positive fix).
if printf '%s' "$cmd" | grep -qE '(^|[^[:alnum:]_/])printenv([[:space:]]|[|;&]|$)'; then
    emit_deny "[guardia] denied: env-dump — printenv is not permitted"
fi

# env-dump: `env` used as a DUMP — leading `env` (optionally /abs/path/env) with
# nothing after, only dash-options (incl. -0 and its --null long synonym), or
# piped/redirected. NOT `env VAR=val cmd`, `env -u FOO cmd`, `env -i cmd`,
# `env --unset=FOO cmd`, `env --ignore-environment cmd` (a command word after the
# options → fail open).
if printf '%s' "$cmd" | grep -qE '^[[:space:]]*(/[^[:space:]]*/)?env[[:space:]]*((-[A-Za-z0]+|--null)[[:space:]]*)*([|;&>]|$)'; then
    emit_deny "[guardia] denied: env-dump — bare 'env' (environment dump) is not permitted"
fi

# env-dump: bare `set` (prints all vars+functions), incl. redirect-to-file `set > f`.
# NOT `set -e`/`set +e`/`set -o …`/`set -- …` (a leading - or + flag after `set` → defer).
if printf '%s' "$cmd" | grep -qE '^[[:space:]]*set[[:space:]]*([|;&>]|$)'; then
    emit_deny "[guardia] denied: env-dump — bare 'set' (variable dump) is not permitted"
fi

# env-dump: bare `declare`/`typeset` (no args dumps all vars+values), incl. `declare > f`. NOT `declare -i x`.
if printf '%s' "$cmd" | grep -qE '^[[:space:]]*(declare|typeset)[[:space:]]*([|;&>]|$)'; then
    emit_deny "[guardia] denied: env-dump — bare 'declare'/'typeset' (variable dump) is not permitted"
fi

# env-dump: print-definitions flag `-p` (incl. fused clusters -px/-pf/-ip) on
# declare/typeset/local/export/readonly. Anchored to command position (start or after
# |;&) so a quoted arg like echo "use export -p" defers (Phase-3 false-positive fix).
# NOT `export FOO=bar`.
if printf '%s' "$cmd" | grep -qE '(^|[|;&][[:space:]]*)(declare|typeset|local|export|readonly)[[:space:]]+-[A-Za-z]*p[A-Za-z]*([[:space:]]|$)'; then
    emit_deny "[guardia] denied: env-dump — '-p' variable/definition dump is not permitted"
fi

# env-dump: compgen variable/exported-name enumeration (-v / -e / fused -ve|-ev / -A variable / -A export).
if printf '%s' "$cmd" | grep -qE '(^|[^[:alnum:]_])compgen[[:space:]]+(-[A-Za-z]*[ve][A-Za-z]*|-A[[:space:]]+(variable|export))([[:space:]]|$)'; then
    emit_deny "[guardia] denied: env-dump — compgen variable enumeration is not permitted"
fi

# ---------------------------------------------------------------------------
# Step 8 — default: pass-through (PSC R2.7-2b amendment: was defer, now exit 0)
# Hardware gate #1 exp6 proved: defer is TERMINAL in headless -p; pass-through
# lets the normal flow (deny[] → ask → allow[]) decide. Unit 3 only (2b).
# ---------------------------------------------------------------------------
exit 0
