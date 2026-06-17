# Proposal: platform-security-core

**Change**: platform-security-core
**Project**: osgania
**Artifact store**: openspec
**Date**: 2026-06-14
**Status**: proposed

Establish the non-overridable security baseline (the "three locks") that every later OSGANIA change inherits: an operator policy the client agent cannot override, a pre-execution veto, and an append-only audit trail. This is the L0 fixed-deny foundation; no autonomy ladder, onboarding generator, or MCP connection is safe to ship without it.

---

## Why now (intent)

OSGANIA runs one Claude Code CLI agent per client VPS. That agent legitimately needs Bash, Edit, and Read to do useful work, so the risk is not "the agent has tools" — it is that the agent executes a destructive or secret-leaking command through prompt injection, runaway autonomy, or a misconfigured client session.

This change is the **first slice** because it is the foundation: it defines the trust model everything else builds on. The security posture is expressed as **three locks**, each independent so that no single misconfiguration unlocks the platform:

| Lock | Artifact | Role |
|------|----------|------|
| Operator policy | `platform/managed-settings.json` | Highest-precedence deny rules; client/agent cannot override |
| Pre-execution veto | `platform/hooks/guardia.sh` | PreToolUse hook; vetoes dangerous tool calls before they run |
| Audit trail | `platform/hooks/camara.sh` | PostToolUse hook; appends a structured record of every tool call |

This directly serves the non-negotiable principles from `openspec/config.yaml`: operator policy cannot be overridden by the client/agent, secrets never leak, and every action is logged.

---

## Approach

**Option C — defense-in-depth hybrid.** managed-settings deny rules are the PRIMARY gate; guardia.sh is an INDEPENDENT second layer with its own minimal denylist.

Why this and not "let managed-settings be the sole gate":

- A PreToolUse hook returning `permissionDecision: "deny"` blocks the tool **even in `bypassPermissions` mode** and with `--dangerously-skip-permissions`. guardia is therefore NOT redundant with the managed deny rules — it closes a gap the deny rules alone cannot.
- The runtime evaluates the PreToolUse hook BEFORE the managed deny rules, so the two layers have independent failure modes. Both must be misconfigured simultaneously for a dangerous command to slip through.
- `allowManagedHooksOnly: true` makes guardia and camara non-bypassable by the client agent — they cannot be injected, replaced, or disabled from the client/agent side.

The cost is that the denylist lives in two places (managed-settings and guardia) and must stay in sync. This is acceptable because the denylist is small, solid-but-minimal, and changes infrequently.

---

## Scope

### In scope

Three artifacts plus their tests and lint, establishing the L0 fixed-deny base:

| Artifact | What it does |
|----------|--------------|
| `platform/managed-settings.json` (template) | Operator policy: denies secrets-read, `platform/` writes, `sudo`, and `curl`/`wget`; neutralizes bypass mode; forces managed-only hooks |
| `platform/hooks/guardia.sh` (PreToolUse, **Bash matcher only**) | Independent second-layer veto over the minimal denylist |
| `platform/hooks/camara.sh` (PostToolUse) | Appends a structured audit record to a **local append-only** log for every tool call |
| `tests/guardia.bats` | bats-core behavioral tests for guardia |
| `tests/camara.bats` | bats-core behavioral tests for camara |

**Settled decisions** (operator-approved — baked in, not open):

1. **Audit log is LOCAL append-only for v1.** camara.sh writes to a local append-only log (`chattr +a`, root-owned directory; `aios` can append but cannot rewrite). Off-box / remote shipping is OUT of scope — it conflicts with the `Bash(curl *)` deny and belongs to the future central-control-plane change.
2. **guardia.sh runs on the `Bash` matcher only for v1.** File-write protection is handled by managed-settings deny rules plus OS permissions, not guardia. Extending guardia to Edit/Write is explicitly deferred.
3. **Denylist is minimal-but-solid, not exhaustive**: `sudo`, `curl`/`wget`, `rm -rf`, disk-wipe (`dd`, `mkfs`, `wipefs`), reads of `/etc/osgania/secrets/**`, and writes to the `platform/` directory. This covers the bulk of real damage without becoming unmaintainable.

### Out of scope (deferred)

| Deferred | Belongs to |
|----------|-----------|
| `provision.sh` (installs managed-settings.json on the VPS) | Adjacent provisioning change |
| Onboarding generator | Builds on this base |
| `client/` layer (per-client allow rules) | Layered on this deny base |
| MCP connection design (Supabase/n8n) | Separate security domain |
| systemd maintenance timers | Operational, not security core |
| Central control plane | Future multi-client change |
| Audit log off-box shipping | Future central-control-plane change |
| Autonomy ladder L1–L4 | Per-client allows; this change is L0 only |

---

## Success criteria (high-level, testable)

- [ ] **guardia denies** every denylist pattern (`sudo`, `curl`/`wget`, `rm -rf`, `dd`/`mkfs`/`wipefs`, secrets-read, `platform/` writes) with `permissionDecision: "deny"` and a structured reason.
- [ ] **guardia defers** benign commands (`permissionDecision: "defer"`), letting the normal permission flow continue.
- [ ] **camara appends** a structured audit record for every tool call; the log line is valid and parseable.
- [ ] **camara cannot rewrite history**: the audit log is append-only; existing records are not modifiable by the writing identity.
- [ ] **managed-settings.json is a valid policy** that denies secrets-read, `platform/` writes, `sudo`, and `curl`; neutralizes bypass mode; and forces managed-only hooks.
- [ ] **Both hooks pass `shellcheck`** with no warnings.

---

## Risks

| Risk | Severity | How the design is constrained |
|------|----------|-------------------------------|
| managed-settings.json not installed on a live VPS | Critical | Out of scope here; provision.sh (separate change) MUST install it before the agent starts. Principle: operator policy cannot be overridden — but only if present. |
| `allowManagedHooksOnly` / `disableBypassPermissionsMode` key names wrong | High | Re-confirm exact spelling against the Claude Code settings reference at implementation time before writing the JSON. |
| Audit log writable/rewritable by `aios` | High | Principle: every action logged, log integrity preserved. camara MUST write to a path `aios` can append to but not rewrite (`chattr +a` or root-owned dir). |
| guardia denylist uses wrong match semantics | Medium | Shell glob ≠ Claude Code matcher syntax. Design MUST specify exact match semantics; verify phase tests against actual matching behavior. |
| Denylist drift between managed-settings and guardia | Medium | Inherent to Option C. Mitigated by keeping the list small and documenting both locations as a single policy. |
| Hook timeout too short | Low | guardia does no I/O or network; set an explicit generous timeout (e.g., 10s) in the hooks config. |
| bats-core / shellcheck not installed | Blocking for apply | `brew install bats-core shellcheck` before first apply. |

---

## Rollback plan

This change touches `managed-settings.json` (config rule: rollback plan required).

- All five artifacts are **new files** in a greenfield repo; no existing behavior is replaced.
- Nothing in this change is installed onto a live VPS — installation is provision.sh's job (separate change). The artifacts here are templates and scripts under version control.
- Rollback = revert the change set. No live system state is mutated by this change, so revert is clean with no data migration or de-provisioning required.

---

## Open questions carried to spec/design

1. **Audit log format and path**: exact fields (timestamp, session_id, tool_name, tool_input summary, decision, reason), JSON Lines vs. plain text, and the on-disk path.
2. **guardia denylist patterns and match semantics**: exact patterns and whether matching is case-insensitive, substring, or prefix — must align with Claude Code matcher behavior, which differs from shell glob.
3. **Two managed-settings key names to confirm at implementation**: `disableBypassPermissionsMode` and `allowManagedHooksOnly` — verify exact spelling against the Claude Code settings reference before writing the template.

---

## TDD note

Strict TDD is active. bats-core (behavioral tests) and shellcheck (lint) are required and **not yet installed**:

```bash
brew install bats-core shellcheck
```

Install before the first `sdd-apply`. Tests precede or accompany hook implementation; both hooks must pass shellcheck with no warnings.

---

## Next step

Run `sdd-spec` and `sdd-design` (can proceed in parallel) to resolve the three open questions above and define exact patterns, audit format, and the validated managed-settings template.
