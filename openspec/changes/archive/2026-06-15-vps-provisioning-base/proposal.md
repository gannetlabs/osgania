# Proposal: vps-provisioning-base

**Change**: vps-provisioning-base (Slice 1 of 2 — the deterministic OS baseline)
**Project**: osgania
**Artifact store**: openspec
**Status**: proposal

## Intent

The archived `platform-security-core` change shipped the "three locks" (managed-settings policy, `guardia.sh` PreToolUse veto, `camara.sh` audit hook) as version-controlled templates that install **nothing** on a live box. They are therefore theoretical: no `aios` user, no platform tree at the hardcoded path, no policy at `/etc/claude-code/`, and — critically — no pre-created append-only audit log. `provision.sh` is the installer that makes them real on a fresh Ubuntu VPS. This slice ships the **deterministic baseline with zero open forks**: the parts that make the three locks load-bearing and are fully grounded in resolved constraints. The single most important step is pre-creating and arming the audit log: with directory mode `0750` the `aios` group can append to an existing file but **cannot create one**, so if the file is absent `camara.sh` fails open and silently drops every audit record — a direct violation of spec **R5.5** ("every tool call MUST produce an audit record").

## Scope

### In Scope
- **aios OS user** — system account, NOT in sudo group, `nologin` shell, no/locked home. (C-08, OD-AIOS)
- **Platform tree at exactly `/opt/osgania/platform/`** — root-owned, read-only to `aios`; `chmod +x` both hooks. The deny rules and hook registrations hardcode this absolute path. (C-05/C-06/C-07/C-12/C-14)
- **Install + verify `jq`** — both hooks need it at runtime; absent on a fresh box. (OD-JQ)
- **Copy `managed-settings.json` → `/etc/claude-code/managed-settings.json`** (the official Linux managed path). (C-04)
- **Create `/etc/osgania/secrets/`** — root-owned, no `aios` read, consistent with the Read-deny rule. (C-09)
- **LOAD-BEARING: audit log pre-create + arm** — idempotently create `/var/log/osgania/` (`0750 root:aios`) and `/var/log/osgania/audit.jsonl` (`0620 root:aios`), then `chattr +a` the file, in the **host namespace BEFORE any agent runs**. Verify the target FS is ext4 (`chattr +a` is a silent no-op on tmpfs/overlayfs). (C-01/C-02/C-03)
- **Pin + verify the Claude Code CLI version**, record it; flag Layer-3 (`disableBypassPermissionsMode`) residual risk if degraded (≤ v2.1.92, issue #44642). (C-11)
- **Guarantee `AUDIT_LOG` stays UNSET** by the install (it exists only for bats test isolation; setting it in prod misdirects logs). (C-13)
- **Idempotency** — safe to re-run: no duplicate user, no `+a` corruption, no perms drift. (C-09 pattern)

### Out of Scope (deferred to Slice 2 = vps-provisioning-hardening)
- **UFW egress firewall** — depends on fork OD-EGRESS (allow-all-443 vs Squid domain ACL).
- **systemd hardening unit + agent launch mechanism** — depends on fork OD-SYSTEMD.
- **API-key delivery** (`apiKeyHelper` / `LoadCredential`) — depends on fork OD-KEY.
- **unattended-upgrades posture** — security-pocket-only vs full; reconcile with CLI `DISABLE_UPDATES`.
- **logrotate-under-chattr** — rotation must toggle `chattr -a/+a`; deferred.
- **Docker/Coolify coexistence** — `ufw-docker` / FORWARD egress; only if Docker is present.

> Boundary note: because Slice 1 does **not** start the agent, the `chattr +a` armed here is already in place before Slice 2's launch unit ever opens the log (the kernel checks the flag only at `open()`).

## Capabilities

### New Capabilities
- `vps-provisioning-base`: deterministic OS provisioning that installs the three-locks artifacts and pre-creates/arms the append-only audit log on a fresh Ubuntu VPS, making the `platform-security-core` contract enforceable. Becomes `openspec/specs/vps-provisioning-base/spec.md`.

### Modified Capabilities
- None. This change installs the existing `platform-security-core` artifacts unchanged; it does not alter their spec-level behavior. (Touching `requiredMinimumVersion` in `managed-settings.json` would cross the archived-change boundary — see Open Questions; out of scope unless design decides otherwise.)

## Approach

A single idempotent root-run `provision.sh` for a fresh Ubuntu VPS. **Detect, do not hardcode** the OS: read `/etc/os-release` and re-verify version-sensitive facts on the live box (systemd present, ext4 for `/var/log`, `useradd`/`adduser` available, `e2fsprogs`/`chattr` available). Target Ubuntu 26.04 LTS, support 24.04 LTS as fallback — 26.04 GA confidence was conflicting across research streams, so liveness checks are authoritative over assumptions. Ordering matters: create `aios` → install tree + hooks + jq → install policy → create secrets dir → **pre-create audit dir+file then `chattr +a` (host namespace, before any agent)** → pin/verify CLI version → assert `AUDIT_LOG` unset. Use idempotent primitives (`install -d`, `[ -f ] ||`, `chattr +` add-only) so re-runs are safe. Because the bats suite explicitly excludes `chattr`/perm-mode checks, this slice carries its own provisioning verification (`stat`, `lsattr`, group membership, `which jq`, `claude --version`).

## Non-Negotiable Principles Referenced

| Principle (openspec/config.yaml) | How this slice honors it |
|----------------------------------|--------------------------|
| Client-facing agent has NO root and is read-only by default | `aios` is a no-sudo `nologin` system account; platform tree root-owned read-only-to-aios; secrets dir denied. |
| Operator policy cannot be overridden by the client/agent | Installs `managed-settings.json` to the managed path at correct ownership so the lock is real, not bypassable. |
| Audit log of every action (camara.sh PostToolUse) | Pre-creates + arms the append-only log so the first `camara` append succeeds — closes the silent-drop gap (R5.5). |
| Secrets never in versioned files, repo, or conversation | Creates `/etc/osgania/secrets/` root-owned, no `aios` read; ships no secret values. |
| Verify product facts against official docs; never guess | OS version detected live; CLI mode-lock floor treated as low-confidence and validated, not assumed. |

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `scripts/provision.sh` (new) | New | The idempotent installer (this slice). |
| `tests/provision.bats` (new) | New | Provisioning verification (`stat`/`lsattr`/group/jq/version) — bats excludes these. |
| `/opt/osgania/platform/` (live VPS) | New | Platform tree install target, root-owned. |
| `/etc/claude-code/managed-settings.json` (live VPS) | New | Operator policy install target. |
| `/etc/osgania/secrets/` (live VPS) | New | Root-owned secrets store, no aios read. |
| `/var/log/osgania/audit.jsonl` (live VPS) | New | Pre-created `0620 root:aios`, `chattr +a` armed. |
| OS user `aios` | New | No-sudo nologin system account. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Audit file not pre-created / wrong mode-owner → camara fails open, silently drops records | Med | **Critical (R5.5)**. `install -d 0750 root:aios` + pre-create `0620` + `chattr +a` before any agent; assert via `stat`/`lsattr`. |
| `chattr +a` armed AFTER the agent opened the FD | Low (Slice 1 doesn't start agent) | Arm before any process opens the log; flag already set before Slice 2's launch unit. |
| Platform tree installed at a prefix ≠ `/opt/osgania/platform/` | Low | Hardcoded path is non-negotiable; provision installs to exactly that path; verify post-install. |
| `chattr +a` no-op on tmpfs/overlayfs `/var/log` | Med | `stat -f /var/log/osgania` must report ext4; abort with a clear error otherwise. |
| Layer-3 mode-lock degraded (CLI ≤ v2.1.92) | Low (v2.1.153 noted installed) | Record installed version; flag residual risk if degraded; Layers 1+2 still hold. Floor is low-confidence — pin above and validate. |
| `jq` absent on fresh VPS → hooks fail silently | Med | Install jq; verify with `which jq`. |
| 26.04-specific facts unconfirmed (systemd version, useradd, passwd-l under sudo-rs) | Med | Detect via `/etc/os-release`; re-verify live; do not hardcode. |
| `passwd -l` does NOT block SSH key login | Low | Out of scope to harden SSH here, but note: locking the password ≠ blocking SSH; SSH posture for `aios` belongs to Slice 2 / sshd config. |
| **No UFW in this slice → no lockout risk this slice** | n/a | Egress firewall is Slice 2; the SSH-lockout-on-`ufw enable` risk does not apply here. |

## Rollback Plan

*(Config rule: required — this change installs `managed-settings.json` and creates the secrets path.)*

Provisioning mutates live VPS state, so rollback is real (unlike `platform-security-core`, which installed nothing). To fully undo a provisioning run:

1. `chattr -a /var/log/osgania/audit.jsonl` (clear the append-only flag — root must do this first or removal fails), then remove `/var/log/osgania/` (preserve `audit.jsonl` if the audit trail must be retained for forensics — append-only logs are intentionally not destroyed on rollback unless explicitly required).
2. Remove `/etc/claude-code/managed-settings.json` (the operator policy).
3. Remove `/etc/osgania/secrets/` (only if empty/seeded by provisioning; never delete real secrets blindly).
4. Remove `/opt/osgania/platform/`.
5. Remove the `aios` user (`userdel aios`); reverse only if provisioning created it.

**Forward-fix path (preferred):** because `provision.sh` is idempotent, re-running it is the normal way to correct a partial or drifted install — it does not duplicate the user, corrupt the `+a` log, or break perms. Full rollback is the escape hatch; idempotent re-run is the day-to-day repair.

## Dependencies

- Archived `platform-security-core` artifacts (`platform/managed-settings.json`, `platform/hooks/{guardia,camara}.sh`) exist and are the install source.
- A fresh Ubuntu VPS (26.04 LTS target, 24.04 LTS fallback) with root access and an ext4 `/var/log`.
- `e2fsprogs` (`chattr`/`lsattr`), `useradd`/`adduser`, `install`, `stat` available (verified live).

## Success Criteria

- [ ] `aios` exists, is NOT in the sudo group, has a `nologin` shell.
- [ ] Platform tree is at exactly `/opt/osgania/platform/`, root-owned, read-only to `aios`; both hooks have execute bit.
- [ ] `jq` is installed and on PATH.
- [ ] `managed-settings.json` is at `/etc/claude-code/managed-settings.json`.
- [ ] `/etc/osgania/secrets/` is root-owned with no `aios` read.
- [ ] `/var/log/osgania/audit.jsonl` exists, mode `0620`, owner `root:aios`, with the `a` (append-only) attribute set; the FS is ext4.
- [ ] The installed Claude Code CLI version is recorded; Layer-3 residual risk is flagged if the version is degraded.
- [ ] `AUDIT_LOG` is unset in the production environment after provisioning.
- [ ] Re-running `provision.sh` is idempotent — no duplicate user, no `+a` corruption, no perms drift.

## Open Questions (for design)

- **OD-PLATFS** — exact owner/mode of `/opt/osgania/platform/`: `root:root 0755` vs `root:aios 0750`. (`aios` must read/execute the hooks; never write.)
- **OD-VERPIN** — version-pin floor and strength: install-pin only vs touching `requiredMinimumVersion` in `managed-settings.json`. The latter **edits the archived `platform-security-core` template and crosses the change boundary** — flag it; the exact safe floor is low-confidence (#44642 is from a GitHub issue, not the changelog).
- **OD-CLIENTFS** — whether `/opt/osgania/client/` is created in this slice at all, and if so, its permissions (the archived design deferred the client tree entirely).
- **OD-AIOS (residual)** — concrete UID/GID and home-dir decision (locked home vs none) for the `aios` account.
