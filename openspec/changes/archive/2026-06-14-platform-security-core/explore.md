# Exploration: platform-security-core

**Change**: platform-security-core
**Date**: 2026-06-14
**Artifact store**: openspec
**Status**: complete

---

## Why This Slice Is First

OSGANIA runs one Claude Code CLI agent per client VPS. The client-facing agent has LEGITIMATE access to tools (Bash, Edit, Read) and MUST have those tools to do useful work. The risk is that the agent — whether through prompt injection, runaway autonomy, or a misconfigured client session — executes a destructive or secret-leaking command.

This change establishes the non-overridable security baseline that all subsequent work builds on. Without it, no autonomy ladder, no onboarding generator, and no MCP connection is safe to ship. It is the foundation — everything else inherits its trust model.

---

## Current State

Greenfield. The repo contains only:

- `openspec/config.yaml` — SDD project config (artifact store: openspec, strict_tdd: true)
- `.atl/skill-registry.md` — skill index

No scripts, no hooks, no settings files, no tests exist yet.

The non-negotiable principles are declared in `openspec/config.yaml`:
- Client-facing agent has no root and is read-only by default (OS layer).
- Operator policy via managed-settings.json cannot be overridden by the client or agent.
- Every agent action must be logged (camara.sh).
- Secrets must never appear in versioned files or conversations.

---

## Affected Files (to be created)

| Path | Role |
|------|------|
| `platform/managed-settings.json` | Operator policy template — installed to /etc/claude-code/managed-settings.json on the VPS |
| `platform/hooks/guardia.sh` | PreToolUse hook — vetoes dangerous tool calls before execution |
| `platform/hooks/camara.sh` | PostToolUse hook — appends every tool action to the audit log |
| `tests/guardia.bats` | bats-core behavioral tests for guardia.sh |
| `tests/camara.bats` | bats-core behavioral tests for camara.sh |

---

## Verified Technical Constraints

These constraints are ground truth — they are ENFORCED by the Claude Code runtime and cannot be worked around.

### managed-settings.json

| Constraint | Detail |
|------------|--------|
| Location | `/etc/claude-code/managed-settings.json` on Linux |
| Precedence | Highest — cannot be overridden by user or project settings |
| Permission rule syntax | `Read(path)`, `Edit(path)`, `Bash(command)` matchers |
| Example deny patterns | `Bash(curl *)`, `Bash(sudo *)`, `Read(./.env)`, `Read(./.env.*)`, `Read(./secrets/**)`, `Edit(/opt/osgania/platform/**)` |
| `allowManagedHooksOnly` | When true, ONLY managed hooks, SDK hooks, and force-enabled plugin hooks load. Client/agent cannot inject or disable operator hooks. |

### Hook Mechanics

| Constraint | Detail |
|------------|--------|
| PreToolUse STDIN fields | `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input` (object; `tool_input.command` for Bash) |
| PreToolUse decision output | `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}` |
| Decision values | `allow`, `deny`, `ask`, `defer` (defer = no decision, normal permission flow continues) |
| Deny is unbypassable | A `permissionDecision: "deny"` from a PreToolUse hook blocks the tool even in `bypassPermissions` mode and with `--dangerously-skip-permissions` |
| Exit codes | exit 0 = success (stdout parsed for JSON decision); exit 2 = blocking error (stderr text used as block reason, PreToolUse exit 2 blocks the tool) |
| PostToolUse | Cannot prevent execution (tool already ran). Can modify output via `updatedToolOutput`. Audit use only. |
| Hook timeout | Configurable per hook entry. Default varies; set explicitly (e.g., 10s for guardia). |

### Permission Processing Order (Claude Code runtime)

```
PreToolUse Hook → Deny Rules → Allow Rules → Ask Rules → Permission Mode Check → canUseTool → PostToolUse Hook
```

This means guardia runs BEFORE the managed-settings deny rules are evaluated. It is an additional layer, not a replacement.

### Bypass Neutralization

The `permission_mode` field in hook STDIN can be `bypassPermissions`. The operator MUST neutralize this via a managed-settings key. Flag: **`disableBypassPermissionsMode`** — confirm exact key spelling against the Claude Code settings reference at implementation time.

---

## Approaches for guardia.sh Deny Logic

### Option A — Hardcoded Denylist in the Hook

guardia.sh contains its own pattern list and denies any matching command independently.

| | Detail |
|-|--------|
| Pros | Self-contained; no dependency on managed-settings being correctly installed; portable; testable in pure bash |
| Cons | Denylist is duplicated across managed-settings.json AND the hook; two places to update when policy changes; bash pattern matching is error-prone |
| Effort | Low |

### Option B — Thin Wrapper Deferring to Managed-Settings Rules

guardia.sh defers all decisions (`permissionDecision: defer`) and lets managed-settings deny rules be the sole gate.

| | Detail |
|-|--------|
| Pros | Single source of truth for deny policy; no duplication; simpler hook code |
| Cons | Zero defense in depth — if managed-settings.json is misconfigured or missing, nothing vetoes dangerous calls; hook adds no security value |
| Effort | Very Low |

### Option C — Defense-in-Depth Hybrid (Recommended Direction)

managed-settings deny rules are the PRIMARY gate. guardia.sh is a SECOND INDEPENDENT layer with its own minimal denylist and structured audit reason. They share the same deny intent but are separate implementations.

| | Detail |
|-|--------|
| Pros | Two independent failure modes must both be misconfigured simultaneously for a dangerous command to slip through; structured `permissionDecisionReason` from guardia provides richer audit context; guardia's deny is documented-unbypassable even in `bypassPermissions` mode; testable independently via bats |
| Cons | Denylist exists in two places; must keep them in sync during policy updates |
| Effort | Medium |

**Lean/Recommended**: Option C. guardia's `permissionDecision: deny` is documented to block even in `bypassPermissions` mode — this is a stronger runtime guarantee than managed-settings deny rules in certain edge cases. Two independent layers with overlapping intent is the correct security posture for a platform that must be non-negotiably safe. Policy sync overhead is low given the deny list is small and changes infrequently.

---

## Out of Scope for This Change

| Area | Why Deferred |
|------|--------------|
| `provision.sh` | Installs managed-settings.json on the VPS — adjacent provisioning step, separate change |
| Onboarding generator | Generates per-client context — builds on top of this security base |
| `client/` layer | Per-client allow rules and workspace config — layered on top of this deny base |
| MCP connection design | How the agent connects to Supabase/n8n — separate security domain |
| systemd maintenance timers | Operational concern, not security core |
| Central control plane | Multi-client management — future |
| Audit log off-box shipping | camara writes locally first; shipping is a follow-on |
| Autonomy ladder L1–L4 | This change establishes L0 (fixed deny base); per-client allows are a separate change |

---

## Risks

| Risk | Severity | Constraint / Mitigation |
|------|----------|-------------------------|
| managed-settings.json not installed on a live VPS | Critical | provision.sh (separate change) must install it before agent starts |
| `allowManagedHooksOnly` key name wrong at implementation | High | Re-confirm exact spelling against Claude Code settings reference before writing the JSON template |
| `disableBypassPermissionsMode` key name wrong | High | Same — re-confirm at implementation |
| guardia denylist patterns use wrong glob syntax | Medium | Shell glob ≠ Claude Code matcher syntax; test against Claude Code's actual matching behavior in verify phase |
| Audit log writable by `aios` | High | camara must write to a path aios can append to but cannot rewrite; chattr +a or root-owned directory; must be specified in design |
| Hook timeout too short | Medium | guardia does no I/O or network calls; 10s timeout is generous; must be set explicitly in managed-settings hooks config |
| bats-core / shellcheck not installed | Low (blocking for apply) | `brew install bats-core shellcheck` before first apply |
| Pattern matching edge cases in guardia | Medium | Design phase must specify exact match semantics (case-insensitive? substring? prefix?) |

---

## Open Questions for Design Phase

1. **Exact denylist for guardia.sh**: Minimum viable set (sudo, curl, rm -rf /) or expanded? Must align with client use cases.

2. **Audit log format**: JSON Lines vs. plain text? Required fields: timestamp, session_id, tool_name, tool_input summary, permissionDecision, reason. Where does it live?

3. **Audit log integrity**: Is `chattr +a` (append-only inode) sufficient for this slice, or is cryptographic chaining / remote sink required from day one?

4. **Off-box log shipping**: In scope for camara.sh in this change, or strictly deferred? (curl is in the deny list — shipping would need a separate mechanism.)

5. **`disableBypassPermissionsMode` exact key name**: Confirm spelling against Claude Code managed-settings reference.

6. **`allowManagedHooksOnly` exact key name**: Same — confirm at implementation.

7. **managed-settings.json deny list scope**: Should it also cover OS system paths (`/etc/**`, `/usr/**`) as defense in depth, or rely on OS permissions alone?

8. **camara.sh output modification**: Audit-only, or should it mask sensitive output fields via `updatedToolOutput` as a second-layer protection?

9. **guardia scope beyond Bash**: Should guardia also run on Edit/Write matchers, or is managed-settings the sole gate for file write protection?

---

## Testing Strategy

Strict TDD mode is active. All hook logic must have tests before or alongside implementation.

| Test file | Framework | What it covers |
|-----------|-----------|----------------|
| `tests/guardia.bats` | bats-core | Feed dangerous STDIN JSON → assert `permissionDecision: deny`. Feed benign → assert `defer`. Edge-case patterns. |
| `tests/camara.bats` | bats-core | Feed STDIN JSON → assert audit log appended with correct fields. Assert log format is valid JSON. |
| Lint | shellcheck | Both hooks pass shellcheck with no warnings |

Pre-requisite: `brew install bats-core shellcheck` — NOT yet installed.

---

## Ready for Proposal

Yes. The problem is well-bounded, constraints are fully verified, the three artifacts are identified, and the recommended approach (Option C hybrid) has clear rationale. Open questions are concrete and answerable at design/spec time.
