# Design: platform-security-core

**Change**: platform-security-core
**Project**: osgania
**Artifact store**: openspec
**Date**: 2026-06-14
**Status**: design
**Depends on**: proposal.md (required), spec.md (contract)

This document is the HOW at the architectural level. It resolves the three open design questions left by the proposal and spec, fixes the exact managed-settings key names against the official Claude Code reference, and records the architecture decisions (ADRs) with rationale and rejected alternatives. Implementation tasks come next (`sdd-tasks`); this design does not list per-file steps.

---

## Quick path (what was decided)

| # | Open question | Decision (one line) |
|---|---------------|---------------------|
| Q1 | Audit log format + path + integrity | JSON Lines at `/var/log/osgania/audit.jsonl`, root-owned `chattr +a` directory, single atomic `>>` append per call, fail-open so the agent never breaks |
| Q2 | guardia denylist patterns + match semantics | Token-aware matching on `tool_input.command` parsed by `jq`: env-prefix-stripped leading token for disk-wipe, whole-token word-boundary regex for `sudo`/`curl`/`wget`, flag-combination scan for `rm`, fixed substring for the secrets path and `platform/` writes; default `defer` |
| Q3 | managed-settings.json structure | `permissions.deny`/`allow`/`defaultMode`/`disableBypassPermissionsMode: "disable"`, top-level `allowManagedHooksOnly: true`, top-level `hooks` registering guardia on `Bash` (PreToolUse) and camara on `*` (PostToolUse) |

Two key names are now **confirmed verbatim against the official docs** and one spec assumption is **corrected** (see ADR-006):

- `permissions.disableBypassPermissionsMode` = `"disable"` (string, nested under `permissions` — NOT a top-level boolean `true` as the spec assumed in R10.1/MS-07).
- `allowManagedHooksOnly` = `true` (boolean, **top-level**, managed-settings-only).

---

## Architecture at a glance

### Component map

```
                          Claude Code CLI runtime (per-client VPS)
                          ────────────────────────────────────────
   agent issues a tool call
            │
            ▼
   ┌──────────────────────┐   STDIN JSON
   │  PreToolUse dispatch  │ ───────────────►  platform/hooks/guardia.sh   (LAYER 2: independent veto)
   └──────────────────────┘                    emits deny | defer on STDOUT
            │  (if not denied by hook)
            ▼
   ┌──────────────────────┐
   │  Deny rules           │ ◄──────────────  permissions.deny  in managed-settings.json  (LAYER 1: primary gate)
   │  Allow rules          │
   │  Ask rules            │
   │  Permission mode      │ ◄──────────────  permissions.disableBypassPermissionsMode = "disable" (LAYER 3: mode lock)
   └──────────────────────┘
            │  (tool actually executes)
            ▼
   ┌──────────────────────┐   STDIN JSON
   │  PostToolUse dispatch │ ───────────────►  platform/hooks/camara.sh    (AUDIT: append-only record)
   └──────────────────────┘                    appends one JSON line to /var/log/osgania/audit.jsonl
```

### Runtime processing order (ground truth from explore.md)

```
PreToolUse Hook → Deny Rules → Allow Rules → Ask Rules → Permission Mode Check → canUseTool → PostToolUse Hook
```

guardia runs **before** the managed deny rules. That ordering is the whole basis for defense in depth (see ADR-001): the two layers fail independently.

### Boundaries (isolation contract)

| Boundary | Who controls it | Agent capability |
|----------|-----------------|------------------|
| `platform/managed-settings.json` (installed to `/etc/claude-code/managed-settings.json`) | Operator only; highest precedence | Cannot read-to-override, cannot edit (denied), cannot bypass (mode locked) |
| `platform/hooks/*.sh` | Operator only; loaded as managed hooks | Cannot inject/replace/disable (`allowManagedHooksOnly: true`); cannot write (denied + OS perms) |
| `/var/log/osgania/audit.jsonl` | Root-owned, `chattr +a` | `aios` may append, cannot truncate/rewrite/delete |
| `/etc/osgania/secrets/**` | Root-owned secrets store | `Read()` denied in policy + guardia denies Bash reads of the path |

---

## Q1 — Audit log: format, path, integrity

**Decision.** Append-only **JSON Lines** at `/var/log/osgania/audit.jsonl`, written by `camara.sh` as a single atomic line append, root-owned directory with `chattr +a`, and **fail-open** so a log failure never blocks the agent.

This keeps the spec contract (R6, R7) intact. The directive's alternative path `/opt/osgania/client/audit/actions.jsonl` is rejected for v1 (see ADR-002) so we do not place an operator-integrity artifact inside the client-writable tree.

### Record format (one JSON object per line, `\n`-terminated)

Each PostToolUse invocation appends exactly one line. Fields:

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `ts` | ISO 8601 string, UTC | `date -u +%Y-%m-%dT%H:%M:%SZ` | Hook-invocation time; second precision is sufficient |
| `session_id` | string | STDIN `.session_id` (top-level field, per R1.2 / R5.2 — NOT `.tool_input.session_id`) | `"unknown"` if absent |
| `tool_name` | string | STDIN `.tool_name` | `"unknown"` if absent |
| `tool_input_summary` | string | derived (see below) | Redacted + truncated; NEVER full content |
| `exit_code` | integer or null | STDIN `.tool_response.exit_code` if present, else `null` | |
| `decision` | string | constant | `"logged"` normally; `"logged-parse-error"` on malformed STDIN (R8.4) |

Canonical example line:

```json
{"ts":"2026-06-14T10:23:45Z","session_id":"sess-abc","tool_name":"Bash","tool_input_summary":"ls /tmp","exit_code":0,"decision":"logged"}
```

#### `tool_input_summary` derivation (redaction + truncation)

- **Bash**: `tool_input.command`, truncated to **512 bytes**, with a trailing `…[truncated]` marker when cut. Never include `tool_response` (R6.3) — that is where secret output would appear.
- **Read / Edit / Write**: `tool_input.file_path` only. File `content` / `old_string` / `new_string` are dropped (R6.3, CA-04).
- **Any other tool**: the first scalar field from `tool_input` that looks like a path or short identifier; otherwise the literal `"(summary unavailable)"`.
- **Escaping**: the summary is assembled with `jq -c` so control characters, backslashes, and quotes are JSON-escaped by construction (R6.4, CA-07). We never hand-build JSON with string interpolation.

This redaction is the single place where secrets could leak into the audit trail, so it is the focus of ADR-004 and the "secret leak surface" checklist below.

### Path and integrity model

| Aspect | Decision |
|--------|----------|
| File | `/var/log/osgania/audit.jsonl` (spec R7.1 fixes the `.jsonl` extension; we keep the spec directory) |
| Directory | `/var/log/osgania/` — owned `root:aios`, mode `0750` (root rwx, group `aios` r-x) |
| File ownership | `root:aios`, mode `0620` (root rw, group `aios` write-only, other none) |
| Append-only inode | `chattr +a /var/log/osgania/audit.jsonl` set by **provision.sh** (separate change). This spec/design records the requirement (R7.4); enforcement is provisioning. |
| Open mode | `>>` (O_APPEND) only. Never `>`, never in-place edit (R7.3). |

Why `0620` group-write rather than world-write `622` (spec R7.2 left this open): the agent runs as `aios`, which is the file group, so group-write is the least privilege that still lets `aios` append. `chattr +a` makes append the **only** mutation possible regardless of mode — even root cannot rewrite existing lines without first clearing the attribute. That is what satisfies "cannot rewrite history" (CA-05, success criterion in the proposal).

**Critical provisioning dependency**: the directory mode is `0750` (group `aios` has r-x, NOT write). This means `aios` **cannot create** `/var/log/osgania/audit.jsonl` if it does not already exist — the directory denies group write. `provision.sh` MUST pre-create the file with the correct ownership (`root:aios`) and mode (`0620`) before the agent ever runs. If provision.sh does not do this, camara's first append on a fresh system will fail and fall through to fail-open (R5.4), silently dropping the record. This directly violates R5.5 ("every tool call MUST produce an audit record"). The spec R7 assumes the file is pre-created by provisioning; `sdd-tasks` for the provisioning change MUST include this file-creation step.

### Known limitations (accepted for v1)

**KL-1 — cap_bytes truncates by bytes, not by Unicode code point.**
`cap_bytes` uses `head -c` (byte count). If a multibyte UTF-8 sequence straddles the byte boundary, the trailing bytes of that sequence are cut, producing a U+FFFD replacement character when the truncated string is later interpreted as UTF-8. This can affect `session_id`, `tool_name`, and `tool_input_summary`. The audit record remains valid JSON (jq handles the partial bytes gracefully); the consequence is cosmetic — one character of the truncated field may render as `?` / replacement glyph. Accepted for v1; a code-point-aware truncation can replace `head -c` in a follow-up if non-ASCII field values become common.

**KL-2 — camara FAILS OPEN when `$AUDIT_LOG` does not exist.**
If the audit log file is missing at hook invocation time, `[[ ! -w "$AUDIT_LOG" ]]` is true (a nonexistent file is not writable), so camara warns to stderr, writes nothing, and exits 0. This is BY DESIGN (ADR-005, R5.4). The file MUST be pre-created by `provision.sh` before the agent runs (cross-change dependency N5). The directory mode is `0750` — group `aios` has r-x but NOT write — which intentionally prevents `aios` from creating the file itself. If `provision.sh` skips the file-creation step, every camara invocation on a fresh system silently drops the record, violating R5.5. This is a provisioning contract, not a code defect in camara.

### Safe append algorithm in camara.sh

1. Read all STDIN into a variable.
2. Parse with `jq`. If parse fails → build a minimal `"logged-parse-error"` record (ts + decision) and continue (R8.4, CA-08).
3. Build the record with `jq -cn --arg …` (compact, escaped, single line).
4. Append atomically: `printf '%s\n' "$record" >> "$AUDIT_LOG"`. A single `printf` line append under `O_APPEND` is atomic for writes below `PIPE_BUF` (4096 bytes on Linux); our line is bounded well under that by the 512-byte command truncation, so concurrent hook invocations cannot interleave a line.
5. **Fail-open**: if the directory/file is missing or not writable, write a one-line warning to STDERR and `exit 0`. camara MUST NOT block execution (R5.3, R5.4) and MUST NOT abort the agent if the log is unavailable.

The log path is overridable via an `AUDIT_LOG` environment variable defaulting to `/var/log/osgania/audit.jsonl`, purely so bats tests can point at a temp file (CA-01..CA-09). Production uses the default.

---

## Q2 — guardia denylist: patterns and match semantics

**Decision.** guardia parses `tool_input.command` with `jq`, applies a **token-aware** decision algorithm (not raw shell glob, not naive substring for command names), and emits `deny` or `defer`. Matching is **case-sensitive** by default (shell command names are case-sensitive on Linux), with word boundaries to avoid false positives like a file literally named `curl` or the word `pseudo`.

The non-negotiable property: matching guardia operates on the **whole command string** (so it catches `sudo` after `&&`, `;`, `|`, or env prefixes — GD-02), but uses token boundaries so benign text like `echo 'curling is a sport'` (GD-06) and `pseudo-random-generator` (GD-03) defer.

### Decision algorithm (precise, ordered)

guardia evaluates the categories in this order and denies on the first match. `CMD` is `tool_input.command`.

```
0. If tool_name != "Bash"            → defer            (R1.6, GD-22, GD-23)
1. If STDIN empty or not JSON        → defer            (R4.5, GD-24, GD-25)
2. If CMD matches SUDO_RE            → deny "sudo"      (R2.1)
3. If CMD matches NET_RE             → deny "curl/wget" (R2.2)
4. If CMD matches RM_RF (2-pass)     → deny "rm -rf"    (R2.3)
5. If CMD leading-token ∈ DISKWIPE   → deny "disk-wipe" (R2.4)
6. If CMD contains SECRETS_PATH      → deny "secrets"   (R2.5)
7. If CMD contains "platform/"       → deny "platform"  (R2.6)
8. else                              → defer            (R2.7)
```

### Pattern definitions

All regexes are evaluated with `grep -E` / bash `[[ =~ ]]` against `CMD`. `\b`-style boundaries are emulated with explicit non-word delimiters because POSIX ERE in bash does not support `\b` portably.

| Category | Match rule | Why this shape |
|----------|-----------|----------------|
| **sudo** (R2.1) | Token `sudo` bounded by start/whitespace/`;`/`&`/`\|`/`(` on the left and whitespace/end on the right. ERE: `(^\|[^[:alnum:]_])sudo([^[:alnum:]_]\|$)` | Catches `sudo …`, `… && sudo …`; rejects `pseudo`, `sudoers` (GD-03) |
| **curl / wget** (R2.2) | Same boundary template for `curl` and `wget`: `(^\|[^[:alnum:]_])(curl\|wget)([^[:alnum:]_]\|$)` | Catches piped `curl … \| bash` (GD-04); rejects `curling`, `wgetrc` (GD-06) |
| **rm -rf** (R2.3) | Two-pass: (a) command contains a bounded `rm` token; (b) the combined option letters after it include both `r`/`R` **and** `f`. Implementation: extract flag clusters matching `-[A-Za-z]+` plus standalone `-r`/`-R`/`-f`, OR-reduce their letters, require `{r∨R}∧f`. | Catches `rm -rf`, `rm -fr`, `rm -r -f`, `rm -Rf` (GD-07..09); defers `rm -r` alone (GD-10) |
| **disk-wipe** (R2.4) | Strip leading whitespace and env-assignment prefixes (`A=b C=d cmd`), take the **leading token**, deny if it equals `dd`, `wipefs`, or matches `mkfs(\..+)?`. The deny reason MUST include the matched leading token so spec scenarios GD-11/GD-12/GD-13 (which assert the reason contains `dd` / `mkfs` / `wipefs` respectively) pass. Reason template: `"[guardia] denied: disk-wipe — leading token '<TOKEN>' is a low-level disk tool"` where `<TOKEN>` is the actual extracted leading token (e.g. `dd`, `mkfs.ext4`, `wipefs`). | First-token anchoring avoids denying `echo dd` while catching `mkfs.ext4` (GD-11..13). Env-prefix strip handles `IF=… dd …` style attempts. |
| **secrets read** (R2.5) | Fixed substring `/etc/osgania/secrets/` anywhere in `CMD`. | Path is unambiguous; substring covers `cat`, `less`, command substitution `$(cat …)` (GD-14..16). No false-positive risk — the path is operator-owned. |
| **platform/ writes** (R2.6, A6) | Fixed substring `platform/` anywhere in `CMD`. | Spec R2.6 explicitly mandates substring-deny for v1; the write-context heuristic is **deferred** (see ADR-003). Covers redirects and `cp/mv` into `platform/` (GD-17, GD-18). |

### Match-semantics rules (the gotchas)

- **Case sensitivity**: case-**insensitive** (`grep -i`) for `sudo`, `curl`, and `wget`. The implementation deliberately matches CURL, WGET, SUDO, etc. to close trivial uppercase-evasion bypasses. Real containment for network operations is the egress firewall and for privilege escalation it is the OS layer — so slightly over-matching command names is acceptable defense-in-depth. Disk-wipe leading-token matching remains case-sensitive because `DD`, `MKFS`, `WIPEFS` are not realistic attacker payloads on Linux.
- **Command chaining**: because we scan the **whole** command string (not just the first token) for `sudo`/`curl`/`wget`/secrets/`platform/`, chaining with `;`, `&&`, `||`, `|`, and subshells `( … )` is covered for those categories (GD-02). The disk-wipe category is intentionally leading-token-only and therefore does NOT catch `foo && dd …`; this is an accepted v1 gap (residual risk R-2) because `dd`/`mkfs`/`wipefs` as a leading token covers the overwhelming majority of real invocations and avoids denying benign strings that merely contain `dd`.
- **Env-prefix handling**: only the disk-wipe leading-token check strips `VAR=value ` prefixes before reading the first token. The whole-string categories don't need it.
- **No filesystem / network access** (R4.1, R4.2): guardia only parses STDIN and runs regex in-process. No `stat`, no resolving paths, no DNS.
- **Default is defer, never allow**: guardia emits only `deny` or `defer` (R1.4). It never short-circuits the normal permission flow with `allow`.

### Output contract (R1.3)

Deny:
```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[guardia] denied: <category> — <brief explanation>"}}
```
Defer:
```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer","permissionDecisionReason":""}}
```
Always `exit 0` after writing STDOUT (R1.5). Built with `jq -cn` so the reason string is JSON-escaped.

---

## Q3 — managed-settings.json structure

**Decision.** The full shape below, using the **confirmed verbatim key names**. Note the two corrections versus the spec's assumptions, captured in ADR-006:

- Bypass neutralization lives at `permissions.disableBypassPermissionsMode` with value `"disable"` (string), NOT a top-level boolean `disableBypassPermissionsMode: true`.
- `allowManagedHooksOnly: true` is a **top-level** managed-only boolean.

```json
{
  "permissions": {
    "defaultMode": "default",
    "deny": [
      "Bash(sudo *)",
      "Bash(curl *)",
      "Bash(wget *)",
      "Read(/etc/osgania/secrets/**)",
      "Edit(/opt/osgania/platform/**)",
      "Write(/opt/osgania/platform/**)"
    ],
    "allow": [],
    "disableBypassPermissionsMode": "disable"
  },
  "allowManagedHooksOnly": true,
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/osgania/platform/hooks/guardia.sh",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/osgania/platform/hooks/camara.sh",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

### Structure rationale

| Key | Value | Why |
|-----|-------|-----|
| `permissions.defaultMode` | `"default"` | Normal permission flow; we are not setting `acceptEdits`/`plan`. Explicit so the mode is operator-pinned, not inherited. |
| `permissions.deny` | 6 rules (R9.1–R9.6) | Primary gate (Layer 1). Mirrors guardia's intent for Bash net/sudo; adds Read/Edit/Write protections guardia does not cover (guardia is Bash-only). |
| `permissions.allow` | `[]` | L0 baseline declares **no** allows. Per-client allow rules are the autonomy ladder (deferred). Empty array makes the deny-only posture explicit. |
| `permissions.disableBypassPermissionsMode` | `"disable"` | Locks out `bypassPermissions` mode and the `--dangerously-skip-permissions` flag (Layer 3). Confirmed verbatim. |
| `allowManagedHooksOnly` | `true` | Only managed/SDK/force-enabled-plugin hooks load. The agent cannot inject, replace, or disable guardia/camara. Top-level, managed-only. |
| `hooks.PreToolUse[].matcher` | `"Bash"` | guardia guards Bash only for v1 (proposal settled decision 2). |
| `hooks.PostToolUse[].matcher` | `"*"` | camara audits every tool (R5.5, R12.2). |
| `hooks[].command` | absolute `/opt/osgania/platform/hooks/*.sh` | Hooks run by the runtime, not as agent tools, so the `Bash(...)`/`Edit(...)` deny rules do not block them (R9.7). Absolute path because the runtime's CWD is the client workspace, not `platform/`. |
| `hooks[].timeout` | `10` | guardia/camara do no network and minimal I/O; 10 s is generous and explicit (proposal/spec R12, risk "hook timeout too short"). |

### Install target

The template lives at `platform/managed-settings.json` in the repo. **provision.sh (separate change)** copies it to `/etc/claude-code/managed-settings.json` on the VPS. This change ships the template only; nothing is installed on a live system here (proposal rollback section).

---

## Defense in depth: how guardia and the deny rules relate

This is the core architectural decision (ADR-001). The two layers are **independent**, not redundant.

| Property | guardia.sh (Layer 2) | managed-settings `permissions.deny` (Layer 1) | mode lock (Layer 3) |
|----------|----------------------|-----------------------------------------------|---------------------|
| Where it runs | PreToolUse hook, **before** deny rules | runtime deny evaluation, **after** the hook | permission-mode check |
| Implementation | bash + jq + regex (this repo) | JSON matchers (Claude Code engine) | `"disable"` string |
| Failure mode | bash bug / bad regex | bad matcher / missing file | n/a (declarative) |
| Bypassable? | **No** — a PreToolUse `deny` blocks even in `bypassPermissions` and with `--dangerously-skip-permissions` | deny rules are also unbypassable, but they assume the file is installed and correct | locks the mode itself |
| Scope | Bash command string only | Bash + Read + Edit + Write path matchers | all modes |
| Match extent (Bash net/sudo) | **Whole command string** — catches `sudo`/`curl`/`wget` after `&&`, `;`, `\|`, and in subshells (GD-02) | **Leading token only** — `Bash(sudo *)`, `Bash(curl *)`, `Bash(wget *)` match only when the command starts with that token; chained forms like `echo x && sudo cmd` are NOT caught by Layer 1 | n/a |

**Why both:** this difference in match extent is the precise reason guardia exists as an independent second layer. A dangerous command like `echo x && sudo rm /tmp` defeats the `Bash(sudo *)` Layer 1 matcher (leading token is `echo`) but is caught by guardia's whole-string regex. A dangerous Bash command must defeat guardia's regex **and** the deny matcher **simultaneously** to execute — different code, different syntax, different match extent, different authors of failure — so a single gap in either layer does not unlock the platform. guardia additionally produces a structured `permissionDecisionReason` that lands in the audit context, which the bare deny rule does not.

**The cost** (accepted): the net/sudo denylist is expressed twice (guardia regex + `permissions.deny`). The list is small and changes rarely, so drift risk is low and is mitigated by documenting both locations here as one policy (residual risk R-1).

---

## Architecture Decision Records

### ADR-001 — Option C: defense-in-depth hybrid (guardia independent of deny rules)
- **Decision**: guardia.sh keeps its own minimal denylist and runs as an independent PreToolUse veto, layered over (not replacing) `permissions.deny`.
- **Rationale**: the runtime evaluates the hook before deny rules, giving independent failure modes; a hook `deny` is unbypassable even in bypass mode; guardia adds structured audit reasons.
- **Rejected — Option A (hardcoded denylist only, no managed deny rules)**: loses the OS-path Read/Edit/Write protections and the unbypassable JSON layer; relies entirely on a bash script being correct.
- **Rejected — Option B (thin wrapper, defer everything, deny rules sole gate)**: zero defense in depth; if managed-settings is missing/misconfigured nothing vetoes dangerous Bash. The hook would add no security value.
- **Cost**: denylist duplicated in two places (mitigated: small, documented as one policy).

### ADR-002 — Audit log path `/var/log/osgania/audit.jsonl`, not under `client/`
- **Decision**: keep the spec path `/var/log/osgania/audit.jsonl`; reject the directive's `/opt/osgania/client/audit/actions.jsonl`.
- **Rationale**: the audit trail is an **operator-integrity** artifact. Placing it inside the client-writable `/opt/osgania/client/` tree puts it adjacent to agent-writable files and complicates the `chattr +a` / ownership story. `/var/log/` is the conventional, root-owned location for append-only system logs and keeps the integrity boundary clean. Filename `.jsonl` is fixed by spec R7.1.
- **Rejected — `/opt/osgania/client/audit/actions.jsonl`**: client-tree placement weakens the integrity boundary; also risks being caught by future broad `client/` rules. Revisit only if the future central-control-plane change needs per-client co-location.

### ADR-003 — guardia `platform/` write match is plain substring for v1
- **Decision**: deny any Bash command whose string contains `platform/` (spec R2.6 / A6).
- **Rationale**: a write-context heuristic (only deny on `>`, `>>`, `tee`, `cp`, `mv`, `sed -i`, …) is fragile and easy to evade; the managed `Edit/Write(/opt/osgania/platform/**)` deny rules already cover the file-tool path. For Bash, the cheap, unevadable rule is "no command may name `platform/`". The small false-positive cost (e.g. `cat platform/README.md`) is acceptable for an operator-only directory the agent has no reason to touch.
- **Rejected — write-context regex**: more code, more bypass surface, marginal benefit. Deferred until a real benign use case appears.

### ADR-004 — Redaction by construction with `jq`, summary excludes `tool_response`
- **Decision**: camara builds every record with `jq -cn --arg`, never string interpolation; `tool_input_summary` is truncated to 512 bytes for Bash and reduced to `file_path` for file tools; `tool_response` body is never logged, only `exit_code`.
- **Rationale**: the audit log is the one place agent I/O is persisted, so it is the primary secret-leak surface. `jq` guarantees JSON-correct escaping (R6.4); excluding `tool_response` prevents secret command output (e.g. a printed token) from being written (R6.3, CA-09).
- **Rejected — log full `tool_response`**: directly leaks secrets that appear in command output. Unacceptable against the "secrets never leak" principle.

### ADR-005 — Fail-open audit, fail-closed veto
- **Decision**: camara (audit) is **fail-open** — a log write failure logs a stderr warning and exits 0, never blocking the agent. guardia (veto) is effectively **fail-safe-defer** — malformed input defers to the normal permission flow (which still has the deny rules behind it), it does not crash.
- **Rationale**: an audit outage must not take the client's agent offline (availability), while a veto outage must not silently allow — but since guardia defers to the still-present deny rules + mode lock, deferring on guardia error is safe, not permissive. The deny rules are the backstop.
- **Rejected — fail-closed audit (block tool if log write fails)**: turns a logging hiccup into a full client outage; disproportionate. The integrity guarantee comes from `chattr +a`, not from blocking on write failure.

### ADR-006 — Corrected managed-settings key names against the official reference
- **Decision**: use `permissions.disableBypassPermissionsMode: "disable"` (nested, string) and `allowManagedHooksOnly: true` (top-level, boolean), per the confirmed docs.
- **Rationale**: the spec originally assumed a **top-level** `disableBypassPermissionsMode: true` (boolean). The official permissions reference defines it **under `permissions`** with the accepted value **`"disable"`**. Implementing the original assumption verbatim would silently no-op. The spec has been **fully corrected** to match this design: R10.1 mandates the nested string form, R10.2 documents the correction, MS-07 asserts `.permissions.disableBypassPermissionsMode == "disable"` (NOT `.disableBypassPermissionsMode == true`), and A4 is marked Resolved. **The spec and design are now aligned.** `sdd-verify` only needs to confirm the implemented JSON matches the nested-string form and check the CLI runtime behavior (see caveat below). `allowManagedHooksOnly: true` is confirmed verbatim as a top-level boolean (A5 in spec resolved by this ADR).
- **Caveat (recorded, not from official docs)**: GitHub issue anthropics/claude-code#44642 reports `disableBypassPermissionsMode` had **no effect** in CLI v2.1.92 due to a bug. Verify enforcement on the installed CLI version during the verify phase. If the installed version is affected, guardia (Layer 2) and the deny rules (Layer 1) still hold; only the mode-lock (Layer 3) would be degraded — defense in depth absorbs it.
- **Source**: https://code.claude.com/docs/en/permissions , https://code.claude.com/docs/en/settings , https://github.com/anthropics/claude-code/issues/44642

### ADR-007 — Onboarding generator language (open_decisions OD-001): defer, not decided here
- **Decision**: OD-001 (Python vs Node for the onboarding generator) is **out of scope** for platform-security-core and remains open. This change ships no generator.
- **Rationale**: nothing in the three locks depends on the generator language. Forcing the decision now would couple a security-core slice to an unrelated tooling choice. Decide it in the onboarding-generator change.

---

## Secret-leak surface review (config rule: flag every place secrets could leak)

| Surface | Risk | Mitigation in this design |
|---------|------|---------------------------|
| Audit `tool_input_summary` | A Bash command could embed a secret as an argument (e.g. `export TOKEN=…`) | Truncated to 512 bytes; this is an accepted minimal risk — the field must record *what ran*. Reading the secrets path itself is denied by guardia + deny rules, so the most common leak vector is blocked upstream. |
| Audit `tool_response` | Command output could print a secret | **Never logged** (ADR-004, R6.3). Only `exit_code` extracted. |
| Reads of `/etc/osgania/secrets/**` | Agent tries to read secrets | Denied twice: `Read(/etc/osgania/secrets/**)` (Layer 1) + guardia substring match for Bash (Layer 2). |
| `curl`/`wget` exfiltration | Agent ships a secret off-box | Denied twice: `Bash(curl *)`/`Bash(wget *)` (Layer 1) + guardia net regex (Layer 2). camara cannot ship logs off-box for the same reason (proposal settled decision 1). |
| Secrets in versioned files | A secret committed to the repo | No secrets in any artifact this change ships; managed-settings references the secrets **path**, never a value. |

---

## How each non-negotiable principle is satisfied

| Principle (openspec/config.yaml) | Satisfied by |
|----------------------------------|--------------|
| Client-facing agent has NO root and is read-only by default | guardia denies `sudo` (no privilege escalation via Bash); deny rules + OS perms keep `platform/` and secrets read-only/denied. (OS read-only default is the provisioning layer; this change does not regress it.) |
| Operator policy (managed-settings.json) cannot be overridden by the client/agent | `permissions.disableBypassPermissionsMode: "disable"` locks bypass mode; `allowManagedHooksOnly: true` prevents hook injection/replacement; `Edit/Write(/opt/osgania/platform/**)` deny edits to the policy/hooks; precedence is highest. |
| Audit log of every action (camara.sh PostToolUse) | camara registered on `*`; appends one JSON line per tool call; `chattr +a` + ownership make it append-only (history immutable). |
| Secrets never in versioned files, repo, or conversation | secrets-read denied two ways; `tool_response` never logged; no secret values in any shipped artifact (see leak review). |
| Verify product facts against official docs; never guess | both managed-settings keys confirmed verbatim against the official reference; the known CLI bug is recorded as a verify-phase check (ADR-006). |
| Brain vs apps separation / MCP least-privilege | out of scope for L0; not regressed. Deferred to the MCP connection change. |
| Per-client isolation | out of scope for L0 (one VPS per client is a provisioning property); this change adds no cross-client surface. |

---

## Rollback plan (config rule: required for managed-settings changes)

- All five artifacts are **new files** in a greenfield repo; no existing behavior is replaced.
- **Nothing is installed on a live VPS by this change.** Installation of `managed-settings.json` to `/etc/claude-code/` and `chattr +a` on the audit log are **provision.sh's** job (separate change). The artifacts here are templates and scripts under version control.
- **Rollback = revert the change set.** No live system state is mutated, so revert is clean: no data migration, no de-provisioning, no audit-log surgery.
- If this design is later installed and must be rolled back at the VPS level (out of scope here, noted for the provisioning change): remove `/etc/claude-code/managed-settings.json`, restart the agent; the audit log remains (append-only, intentionally not deleted on rollback).

---

## Checklist (reviewer can confirm)

- [ ] Q1 resolved: JSON Lines format, fields, `/var/log/osgania/audit.jsonl`, `chattr +a` integrity, fail-open append.
- [ ] Q2 resolved: token-aware decision algorithm with exact patterns and match semantics (case, boundaries, chaining, env-prefix).
- [ ] Q3 resolved: full managed-settings.json shape with confirmed key names.
- [ ] Confirmed keys used verbatim: `permissions.disableBypassPermissionsMode: "disable"`, `allowManagedHooksOnly: true`.
- [ ] Spec and design aligned (ADR-006): spec R10.1/R10.2/MS-07/A4 already reflect the nested-string form `permissions.disableBypassPermissionsMode == "disable"`. No spec edit needed — verify only confirms the implemented JSON and the CLI runtime check.
- [ ] Defense-in-depth relationship documented (guardia independent, runs first, deny unbypassable).
- [ ] Every secret-leak surface flagged (config rule).
- [ ] Every non-negotiable principle mapped.
- [ ] Rollback plan present (config rule).

## Next step

Run `sdd-tasks` to break this design and the spec into TDD task units. Tasks MUST: (1) pair every bash file with a shellcheck lint task, (2) add a verify-phase check for the CLI-version bug (issue #44642) on `disableBypassPermissionsMode` (spec and design are already aligned on the nested-string form — no spec edit is needed for this). Note: the former task "(1) update spec scenario MS-07 to the corrected key shape" is complete — spec R10.1/R10.2/MS-07/A4 are already correct.
