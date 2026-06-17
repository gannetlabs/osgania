# Archive Report: vps-provisioning-base

**Change**: vps-provisioning-base (Slice 1 of 2 — the deterministic OS baseline)
**Project**: osgania
**Date**: 2026-06-15
**Status**: ARCHIVED — PASS WITH WARNINGS

---

## Executive Summary

vps-provisioning-base (Slice 1) is now complete, verified, and closed. The change successfully makes the archived `platform-security-core` three locks load-bearing on a fresh Ubuntu VPS through a single, idempotent root-run installer (`provision.sh`). All 11 specification requirements and 27 behavioral scenarios are proven with zero critical issues. One documented warning remains: PV-17 (live CLI install) defers to Slice 2 as a deliberate scope decision (Node/npm absent on fresh OS, installation deferred to vps-provisioning-hardening). The implementation is production-ready, has passed both macOS (134 pass, 21 Linux-gated skip, 0 fail) and real Ubuntu 24.04 hardware (83 pass, 1 justified skip, 0 fail) verification, and is now archived with full traceability.

**Verdict: ARCHIVED — PASS WITH WARNINGS (0 CRITICAL, 1 WARNING — documented scope deferral, 0 SUGGESTION)**

---

## Closure Actions Completed

### 1. Canonical Spec Created
**File**: `openspec/specs/vps-provisioning-base/spec.md`
- All 11 requirements (R1–R11) with sub-requirements documented
- All 27 PV behavioral scenarios (PV-01 through PV-27)
- Scenario-to-requirement mapping
- All 24 decided literals from design.md, encoded verbatim (drift gate active)
- Isolation boundaries documented for each requirement
- Non-goals section (deferred to Slice 2)
- Assumptions section (no unresolved open questions remain)

**Scope**: vps-provisioning-base is a NEW capability, establishing the deterministic OS baseline that makes platform-security-core enforceable. No modified capabilities.

### 2. Change Folder Moved to Archive
**Source**: `openspec/changes/vps-provisioning-base/`
**Destination**: `openspec/changes/archive/2026-06-15-vps-provisioning-base/`

**Artifacts moved** (6 files total):
- `proposal.md` — scope, risks, rollback, success criteria
- `design.md` — architecture decisions (ADR-1 through ADR-4), execution model, idempotency design, verification strategy
- `spec.md` — requirements and scenarios (moved from change folder after canonical spec created)
- `tasks.md` — 36 tasks across 7 phases, environment split (macOS-TDD vs Linux-deferred), review workload
- `verify-report.md` — test evidence (macOS 134 pass; real Linux 83 pass, 1 justified skip), requirement coverage, adversarial-review fixes (11 issues), task completion, W-1 scope deferral
- `explore.md` — investigation of vps-provisioning as a two-slice problem; covers both Slice 1 (base) and Slice 2 (hardening) decisions. Slice 2 will reference this same exploration in its archive.

**Source folder status**: `openspec/changes/vps-provisioning-base/` is now empty and has been removed.

### 3. Archive Report Persisted to Engram
**Topic Key**: `sdd/vps-provisioning-base/archive-report`
**Type**: architecture
**Scope**: project (osgania)

The full archive report (this document) is persisted to engram for cross-session traceability, including observation IDs from all upstream phases.

### 4. Status Memory Updated
**Topic Key**: `sdd/vps-provisioning-base/status`
**Type**: project
**Scope**: project (osgania)

Cached state: Slice 1 ARCHIVED (not just verified); canonical spec at `openspec/specs/vps-provisioning-base/spec.md`; archived folder at `openspec/changes/archive/2026-06-15-vps-provisioning-base/`; next change is Slice 2 (vps-provisioning-hardening).

---

## Test Evidence Summary

### macOS Local Run (this session)
- **Total tests**: 155 (53 provision.bats + 72 platform-security-core + other suites)
- **PASS**: 134 ✓
- **SKIP**: 21 (Linux-gated precondition checks, correct behavior)
- **FAIL**: 0 ✓
- **Exit code**: 0 ✓
- **Shellcheck**: EXIT 0, zero warnings ✓

### Real Ubuntu 24.04.4 Hardware (authoritative for mutations)
- **Box**: disposable VPS, root, PROVISION_TEST_ALLOW_MUTATION=1, real ext4 filesystem
- **Tests run**: 83 pass, 1 justified skip (PV-17 Linux-live, CLI install deferred)
- **FAIL**: 0 ✓
- **Exit code**: 0 ✓
- **Box inspection confirmed exact end-state** (aios UID/GID 9001, nologin, no home; platform tree root:aios 0750; audit.jsonl root:aios 0620 with `a` flag set on ext4)

---

## Scope Deferral (W-1): PV-17 Linux-Live

**Documented, deliberate decision (Option B)**:
- **What**: CLI installation and live Layer-3 (`disableBypassPermissionsMode`) mode-lock validation
- **Why**: Node/npm is not installed on a fresh Ubuntu VPS. Installing a runtime is outside Slice 1's scope (the OS baseline). Slice 2 (vps-provisioning-hardening) will install Node, the Claude Code CLI, and perform live validation with the API key.
- **Evidence**:
  - `spec.md` R9.1: "Slice 1 (the OS baseline) does NOT install the Node/npm runtime; on a fresh box where `npm` is absent, `provision.sh` MUST record — non-fatally — that CLI installation is **deferred to Slice 2**"
  - `spec.md` Non-goals: "Node/npm runtime + Claude CLI installation, and the live Layer-3 (disableBypassPermissionsMode) mode-lock verification — Slice 2"
  - `spec.md` R9.4/R9.5: live mode-lock test is required, but flags UNVERIFIED if unavailable (honesty gate)
  - `verify-report.md` § 6: "This is a DOCUMENTED SCOPE DEFERRAL, not a verification gap"
- **Not a bug**: The stub-based PV-17/PV-20 (mock CLI version checks) pass on macOS, proving the logic is correct.

---

## Critical Security Achievement

**The highest-value outcome**: The audit log is now pre-created and append-only-armed on real ext4 in the host namespace BEFORE any agent can open it.

Evidence from Ubuntu 24.04 hardware:
```
/var/log/osgania/audit.jsonl: root:aios 0620 (rw- -w- ---)
lsattr output: -----a--------e-------  (append-only flag [a] IS SET)
```

This closes the critical gap identified in platform-security-core's design: without this pre-creation + arming, `camara.sh` would fail open on a fresh box and silently drop every audit record, violating the "every tool call produces an audit record" contract (spec R5.5). With this in place (Slice 1), that contract is now enforceable.

---

## Design Literal Drift: ZERO DRIFT

All 24 decided literals from design.md match the implementation exactly:
- `aios` UID/GID: **9001**
- `aios` shell: `/usr/sbin/nologin` (detected, asserted on live box)
- `aios` home: `/nonexistent` (not created)
- Platform tree mode: **`root:aios 0750`**
- Hook files mode: **`root:aios 0750`** (group r-x, execute bit present)
- Operator policy path: `/etc/claude-code/managed-settings.json` with **`root:root 0644`**
- Secrets dir mode: **`root:root 0700`**
- Audit dir mode: **`root:aios 0750`**
- Audit file mode: **`root:aios 0620`** (group write-only, no read)
- `chattr +a` operator: **add-only** (never `-a`, safe for re-runs)
- CLI version floor: **>= v2.1.153**
- `AUDIT_LOG` in production: **NEVER SET**
- `/opt/osgania/client/` in Slice 1: **NOT CREATED** (deferred to onboarding + Slice 2)

**No value was re-derived, modified, or drifted during implementation.** The spec copied all literals verbatim from design.md. Drift gate is satisfied.

---

## Verified Adversarial Fixes

All 11 adversarial-review issues (FIX-1 through FIX-9, NEW-1, NEW-2) are implemented and regression-tested:
- **FIX-1**: lsattr grep on full line (CRITICAL) — fixed with awk field extraction
- **FIX-2**: --check bypassed preconditions (HIGH) — preconditions now called before report_plan
- **FIX-3**: Existing aios attributes not verified (HIGH) — full UID/GID/shell/home verification added
- **FIX-4**: groupadd before UID check (HIGH) — all collision checks run before any mutation
- **FIX-5**: semver_gte crashes (MEDIUM) — handles pre-release, empty, leading zeros
- **FIX-6**: Layer-3 probe classification (MEDIUM) — exit-0 = FAILED (not UNVERIFIED)
- **FIX-7**: Symlink at AUDIT_FILE redirects chattr (MEDIUM) — -L checks added
- **FIX-8**: grep -w sudo false positive (LOW) — exact token match with tr + grep -qxF
- **FIX-9**: Unvalidated REPO_ROOT (LOW) — _validate_repo_root() helper added
- **NEW-1**: Test path fragility (MEDIUM) — BATS_TEST_DIRNAME path resolution
- **NEW-2**: nologin path check ordering (LOW) — moved to pre-mutation block

---

## What Slice 1 Proved vs. What Slice 2 Will Do

### Proven by Slice 1 (this archive)
- ✓ Full idempotent installer on Ubuntu 24.04 (real hardware)
- ✓ All OS-state mutations match spec exactly (users, modes, owners, flags)
- ✓ `chattr +a` append-only flag set on real ext4 in host namespace
- ✓ All 11 requirements + 27 scenarios covered and tested
- ✓ All adversarial-review issues fixed and regression-tested
- ✓ Idempotency verified (re-run does not duplicate, corrupt, or drift)
- ✓ shellcheck clean

### Deferred to Slice 2 (vps-provisioning-hardening)
- [ ] Node/npm runtime installation
- [ ] Claude Code CLI pinned install + live version verification
- [ ] Live Layer-3 (`disableBypassPermissionsMode`) mode-lock test (needs CLI + API key)
- [ ] `DISABLE_AUTOUPDATER=1` runtime persistence (systemd `Environment=`)
- [ ] SSH sealing of `aios` (`DenyUsers`/`AllowUsers` in sshd_config)
- [ ] UFW egress firewall
- [ ] systemd launch unit (`User=aios`, `ReadWritePaths=`)
- [ ] API key delivery (`LoadCredential`)
- [ ] unattended-upgrades posture
- [ ] logrotate under `chattr +a` with pre/post rotation toggle
- [ ] `/opt/osgania/client/` tree (onboarding + Slice 2 systemd ReadWritePaths)

---

## Forward Dependencies for Slice 2

Slice 2 (vps-provisioning-hardening) MUST:
1. Set `Environment=DISABLE_AUTOUPDATER=1` in the systemd unit (or equivalent drop-in) to durably disable CLI auto-update for `aios` runtime invocation — Slice 1 cannot do this (no launch mechanism, no aios home)
2. Never set `Environment=AUDIT_LOG=…` (C-13: would misdirect production logs)
3. NOT drop `CAP_LINUX_IMMUTABLE` in a way that breaks chattr (the `+a` flag is already armed; Slice 2 must not clear it)
4. Create `/opt/osgania/client/` with agent-writable ownership and attach via systemd `ReadWritePaths=`
5. Install Node/npm runtime and Claude Code CLI
6. Run live Layer-3 mode-lock test (needs API key)
7. Add SSH sealing for `aios` in sshd_config

The explore.md file (archived with this change) covers the full vps-provisioning problem space and the forks that Slice 2 must resolve (OD-EGRESS, OD-SYSTEMD, OD-KEY).

---

## Artifacts

| Artifact | Location | Type |
|----------|----------|------|
| Canonical spec | `openspec/specs/vps-provisioning-base/spec.md` | NEW (merged from change folder) |
| Archived proposal | `openspec/changes/archive/2026-06-15-vps-provisioning-base/proposal.md` | MOVED |
| Archived design | `openspec/changes/archive/2026-06-15-vps-provisioning-base/design.md` | MOVED |
| Archived spec | `openspec/changes/archive/2026-06-15-vps-provisioning-base/spec.md` | MOVED |
| Archived tasks | `openspec/changes/archive/2026-06-15-vps-provisioning-base/tasks.md` | MOVED |
| Archived verify-report | `openspec/changes/archive/2026-06-15-vps-provisioning-base/verify-report.md` | MOVED |
| Archived explore | `openspec/changes/archive/2026-06-15-vps-provisioning-base/explore.md` | MOVED (shared with Slice 2) |
| Archive report (engram) | topic_key: `sdd/vps-provisioning-base/archive-report` | NEW |
| Status memory (engram) | topic_key: `sdd/vps-provisioning-base/status` | NEW |

---

## Traceability Chain

**Key observation IDs** (engram artifact chain):
- Proposal: #172
- Design: #173
- Spec: #175
- Tasks: #177
- Testing strategy decision: #178
- Adversarial review (consistency critic): #176
- Verify report: #201

All upstream phases (explore, propose, design, spec, tasks, apply, verify) are persisted in engram and archive, ensuring complete traceability from business intent through verification to closure.

---

## Next Recommended

Start Slice 2 (vps-provisioning-hardening) when ready. The exploration (explore.md, archived here) identifies the fork resolutions Slice 2's proposal must decide:
- **OD-EGRESS**: Allow-all 443 vs Squid domain ACL
- **OD-SYSTEMD**: Minimal unit vs maximal hardening level
- **OD-KEY**: LoadCredential vs apiKeyHelper vs EnvironmentFile

Slice 1's baseline is complete and ready to ship; Slice 2 will complete the provisioning stack with network + process hardening.

---

## Closure Confirmation

- ✓ All 11 requirements proven
- ✓ All 27 scenarios covered
- ✓ No CRITICAL issues
- ✓ W-1 (scope deferral) documented and not blocking
- ✓ Canonical spec created at `openspec/specs/vps-provisioning-base/spec.md`
- ✓ Change folder archived at `openspec/changes/archive/2026-06-15-vps-provisioning-base/`
- ✓ Archive report persisted to engram
- ✓ Status memory updated
- ✓ platform-security-core spec NOT modified (zero boundary crossing)
- ✓ Drift gate satisfied (zero literal drift)

**vps-provisioning-base is ARCHIVED and CLOSED.**
