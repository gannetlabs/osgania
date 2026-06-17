# Spec: vps-provisioning-base

**Capability**: vps-provisioning-base (Slice 1 of 2 — the deterministic OS baseline)
**Project**: osgania
**Artifact store**: openspec
**Established**: 2026-06-14
**Status**: canonical
**Scope**: This is the permanent provisioning contract for Slice 1 of vps-provisioning. All future work on provisioning infrastructure inherits from this spec.

This document defines the required end-state after `provision.sh` completes. Every decided value is sourced from design.md (drift gate: if a value here differs from design.md, design.md wins — fix the spec, not the design). Implementation tasks come from `sdd-tasks`; this spec does not describe HOW.

---

## Scope summary

`provision.sh` is a single idempotent root-run installer that mutates OS state on a fresh Ubuntu VPS so that the three-locks artifacts (`managed-settings.json`, `guardia.sh`, `camara.sh`) shipped by `platform-security-core` become load-bearing instead of theoretical. This spec defines the required end-state and behavioral invariants after `provision.sh` completes.

### Out of scope (deferred to Slice 2 — vps-provisioning-hardening)

The following are EXPLICITLY NOT covered by this spec:
- UFW egress firewall configuration
- systemd hardening unit and agent launch mechanism
- API-key delivery (`apiKeyHelper` / `LoadCredential`)
- unattended-upgrades posture
- logrotate-under-chattr rotation
- Docker/Coolify coexistence (`ufw-docker`)
- SSH sealing of the `aios` account (`DenyUsers`, `AllowUsers` in sshd_config) — `passwd -l` is applied here but does NOT block SSH key login; see R2.5
- Creation of `/opt/osgania/client/` (deferred to onboarding + Slice 2)

---

## Security contract cross-reference

This slice is the provisioning enforcement layer for `openspec/specs/platform-security-core/spec.md`. Specific cross-references:

| platform-security-core req | Made enforceable by this slice |
|-----------------------------|-------------------------------|
| R7.2 — audit dir/file ownership and modes (`0750`/`0620`) | R6 of this spec (audit dir + file pre-create) |
| R7.4 — `chattr +a` MUST be set by provisioning | R7 of this spec (audit file arming) |
| R5.5 — every tool call MUST produce an audit record | R6 + R7 of this spec close the silent-drop gap: without the pre-created `+a`-armed file, `camara.sh` fails open |
| R12.1, R12.2 — hooks reference absolute path `/opt/osgania/platform/hooks/` | R3 of this spec (platform tree at the exact hardcoded path) |
| R10.3 — CLI version must be recorded; Layer-3 flagged if degraded | R8 of this spec (CLI version pin and live mode-lock validation) |
| KL-3 — operational note to pin/verify Claude Code version per VPS | R8 of this spec (install-pin + disable auto-update) |

This spec does NOT modify or duplicate any `platform-security-core` requirement. It references them as the obligations this slice satisfies.

---

## Requirements

### R1 — OS preconditions and liveness detection

**R1.1** `provision.sh` MUST detect the OS by parsing `/etc/os-release` (`ID` and `VERSION_ID` fields). It MUST NOT hardcode an OS version string.

**R1.2** `provision.sh` MUST abort with a clear, actionable error message if `ID` is not `ubuntu` or if `VERSION_ID` is not `26.04` or `24.04`. Target is Ubuntu 26.04 LTS; Ubuntu 24.04 LTS is an accepted fallback.

**R1.3** `provision.sh` MUST verify that `systemd` is present (`systemctl --version` exits 0) before proceeding. Rationale: Slice 2's launch unit requires systemd; the foundation is asserted now.

**R1.4** `provision.sh` MUST verify that the target filesystem for `/var/log/osgania/` is **ext4** before running `chattr +a`. `chattr +a` is a **silent no-op on tmpfs/overlayfs** — arming a no-op flag would give false integrity confidence. If the filesystem is not ext4, `provision.sh` MUST abort with a clear error identifying the detected filesystem type.

**R1.4a — ext4 check path ordering.** The ext4 precondition check (phase 0) runs against an **existing ancestor path** such as `/var/log` (or the nearest existing parent of the target), because `/var/log/osgania/` does not yet exist at precondition time. An implementer MUST NOT attempt to `stat -f` the not-yet-created subdir. The post-run verification scenario (PV-14) may use `/var/log/osgania` (same filesystem, subdir now exists after provisioning). Both paths are on the same filesystem — the check is equivalent; the distinction is purely about which path exists at which time.

**Isolation boundary (R1):** These are precondition checks that run before any state mutation. No principal (including root) should proceed past these gates if the preconditions are unmet.

**R1.5** `provision.sh` MUST verify the availability of all required tools before any mutation:
- `chattr` and `lsattr` (from `e2fsprogs`)
- `useradd` or `adduser`
- `install`
- `stat`
- `getent`

If any required tool is absent, `provision.sh` MUST abort with a clear error naming the missing tool.

**R1.6** `provision.sh` MUST verify that `jq` is either already installed or installable via `apt-get` before proceeding past preconditions.

**R1.7** `provision.sh` MUST support a `--check` (dry-run) flag. When invoked with `--check`, it MUST run ONLY the phase-0 precondition checks and report the planned changes (what would be applied) WITHOUT mutating any OS state: no user is created, no file is written, no `chattr` is run, no package is installed. This mode MUST exit 0 on a valid host and is safe to run without root on any host. Scenario PV-25 tests this requirement.

---

### R2 — `aios` system account

**R2.1** A system account named `aios` MUST exist after provisioning, created with `useradd -r` (system account semantics: reserved UID range, no login aging, no spurious home dir).

**R2.2** The `aios` account MUST have:
- UID: **9001** (hardcoded for fleet-wide numeric ownership consistency)
- GID: **9001** (primary group `aios`, GID 9001)
- Shell: detected via the live box (e.g., `command -v nologin` or `getent passwd nobody | cut -d: -f7`) rather than hardcoding `/sbin/nologin`. On the supported Ubuntu targets (24.04 and 26.04) the detected path MUST resolve to `/usr/sbin/nologin` (the Debian/Ubuntu canonical path). `provision.sh` MUST assert that the detected path equals `/usr/sbin/nologin` on supported targets and abort if it does not.
- Home directory: `/nonexistent` — the account record MUST reference `/nonexistent` and the directory MUST NOT be created on the filesystem
- Password: locked via `passwd -l aios`

**R2.3** The `aios` account MUST NOT be a member of the `sudo` group or the `admin` group.

**R2.4** `provision.sh` MUST assert after account creation that `aios` is absent from the `sudo` and `admin` groups.

**R2.5** `passwd -l` locks the password only. It does NOT block SSH key-based login. SSH sealing of the `aios` account (`DenyUsers`, `AllowUsers`, or no `authorized_keys`) is the responsibility of Slice 2 and is out of scope here. `provision.sh` MUST emit a warning in its non-secret summary reminding the operator that the `aios` account is NOT SSH-sealed by Slice 1.

**R2.6** If UID 9001 is already taken by an account whose name is NOT `aios`, `provision.sh` MUST abort with a clear error. It MUST NOT silently overwrite or rename the existing account.

**R2.7** If GID 9001 is already taken by a group whose name is NOT `aios`, `provision.sh` MUST abort with a clear error.

**R2.8** If `aios` already exists (re-run / idempotent case), `provision.sh` MUST verify its UID, GID, shell, and home match the required values (R2.2) and leave it intact. It MUST NOT create a duplicate user.

**Isolation boundary (R2):** `aios` is a no-sudo nologin service identity. It has no root access, no interactive shell, no home directory, and no ability to escalate privileges. The `0750 root:aios` group grant on the platform tree and audit directory (R3, R6) reaches `aios` via its primary group — no secondary group memberships are required.

---

### R3 — Platform tree installation

**R3.1** The directory `/opt/osgania/platform/` MUST exist after provisioning with owner `root`, group `aios`, and mode `0750`.

**R3.2** The directory `/opt/osgania/platform/hooks/` MUST exist after provisioning with owner `root`, group `aios`, and mode `0750`.

**R3.3** The file `/opt/osgania/platform/hooks/guardia.sh` MUST exist after provisioning with owner `root`, group `aios`, and mode `0750`. Mode `0750` carries the execute bit for group (`r-x` for `aios`). No separate `chmod +x` is required; the `install -m 0750` step satisfies this requirement.

**R3.4** The file `/opt/osgania/platform/hooks/camara.sh` MUST exist after provisioning with owner `root`, group `aios`, and mode `0750`. Same mode rationale as R3.3.

**R3.5** The file `/opt/osgania/platform/hooks/guardia.sh` MUST be a copy of `platform/hooks/guardia.sh` from the repository (the source template from `platform-security-core`). On idempotent re-runs, the file MUST be overwritten with the current repository version (content refresh).

**R3.6** The file `/opt/osgania/platform/hooks/camara.sh` MUST be a copy of `platform/hooks/camara.sh` from the repository. Same refresh behavior as R3.5.

**R3.7** `managed-settings.json` MUST NOT be placed under `/opt/osgania/platform/`. The operator policy is installed exclusively at `/etc/claude-code/managed-settings.json` (R4). There MUST be exactly one copy of the policy on the box, avoiding two divergent copies.

**R3.8** The directory `/opt/osgania/client/` MUST NOT be created by `provision.sh`. Its creation is deferred to onboarding and Slice 2.

**Isolation boundary (R3):** `aios` can read and execute files in the platform tree (group `r-x` via `0750`) but CANNOT write to any path under `/opt/osgania/platform/`. The `root` owner with no world access means no other unprivileged account can read the hook source. The managed-settings deny rules `Edit(/opt/osgania/platform/**)` and `Write(/opt/osgania/platform/**)` mirror this at the operator-policy layer (platform-security-core R9.5, R9.6).

---

### R4 — Operator policy installation

**R4.1** The file `/etc/claude-code/managed-settings.json` MUST exist after provisioning with owner `root`, group `root`, and mode `0644`.

**R4.2** `/etc/claude-code/managed-settings.json` MUST be a verbatim copy of `platform/managed-settings.json` from the repository. `provision.sh` MUST NOT modify the file content during installation.

**R4.3** The directory `/etc/claude-code/` MUST exist. If absent, `provision.sh` MUST create it with owner `root`, group `root`, and mode `0755` before installing the policy file.

**R4.4** `provision.sh` MUST verify that `/etc/claude-code/managed-settings.json` is valid JSON after installation (e.g. using `jq . /etc/claude-code/managed-settings.json`).

**Isolation boundary (R4):** `/etc/claude-code/managed-settings.json` is `0644 root:root`. The `aios` agent can read the policy (world-read, which is conventional and correct for `/etc` operator config containing no secrets), but cannot edit or write it. Operator policy is controlled exclusively by root.

---

### R5 — Secrets directory

**R5.1** The directory `/etc/osgania/secrets/` MUST exist after provisioning with owner `root`, group `root`, and mode `0700`.

**R5.2** `provision.sh` MUST NOT write any secret value into `/etc/osgania/secrets/`. Slice 1 creates the directory structure only. Secret delivery belongs to Slice 2.

**R5.3** The directory `/etc/osgania/` MUST exist. If absent, `provision.sh` MUST create it as root-owned with appropriate mode before creating the `secrets/` subdirectory.

**Isolation boundary (R5):** Mode `0700 root:root` gives `aios` (and all other non-root accounts) NO access — no read, no write, no directory traversal. This enforces the platform-security-core guardia deny rule `Read(/etc/osgania/secrets/**)` at the OS layer as well as at the hook layer.

---

### R6 — Audit directory and file pre-creation

**R6.1** The directory `/var/log/osgania/` MUST exist after provisioning with owner `root`, group `aios`, and mode `0750`.

**R6.2** The file `/var/log/osgania/audit.jsonl` MUST exist after provisioning with owner `root`, group `aios`, and mode `0620`.

**R6.3** If `/var/log/osgania/audit.jsonl` does not exist, `provision.sh` MUST create it as an empty file with the correct owner and mode using `install -o root -g aios -m 0620 /dev/null /var/log/osgania/audit.jsonl`. It MUST NOT truncate an existing file.

**R6.4** Mode `0620` means: owner (`root`) has read+write (`rw-`); group (`aios`) has write-only (`-w-`) — no read on the file. This mode PERMITS any write operation including truncation at the OS-permission level; it does NOT prevent overwriting or truncation by itself. Prevention of truncation, overwrite, and deletion is the responsibility of `chattr +a` (R7), which operates at the VFS layer and is a separate, mandatory step. Mode `0620` is required by platform-security-core R7.2 for ownership/access shape; `chattr +a` (R7) is what enforces immutability of existing content.

**R6.5** Mode `0750` on `/var/log/osgania/` gives `aios` (group) `r-x`: it can LIST directory entries and traverse into the directory. `aios` CANNOT create new files in the directory (no group write bit on the dir) and CANNOT read the audit FILE's contents (the file's `0620` group bit is write-only, no read). Intentional: the audit file must be pre-created by root with the correct mode, owner, and `+a` flag. If `aios` could create the file, the flag and mode might be wrong.

**Isolation boundary (R6):** `aios` can append to `/var/log/osgania/audit.jsonl` (group write bit on the file — mode `0620`), which is the minimum required for `camara.sh` to function. On the directory `/var/log/osgania/` (`0750 root:aios`), `aios` has group `r-x`: it can list directory entries and traverse into the directory, but CANNOT create files (no dir write bit) and CANNOT read the audit FILE's contents (the file's group bit is write-only, no read). Truncation, overwrite, and deletion are prevented by `chattr +a` (R7) at the VFS layer — NOT by the `0620` mode alone.

---

### R7 — Audit file append-only arming (`chattr +a`)

**R7.1** `provision.sh` MUST set the Linux append-only inode flag (`chattr +a`) on `/var/log/osgania/audit.jsonl` in the **host namespace**, BEFORE any agent process is running. This is the enforcement mechanism for platform-security-core R7.4.

**R7.2** The `chattr +a` step MUST be executed with the `+` operator (add-only), never `-a` or `=a`. The add-only semantics make re-runs safe: setting a flag that is already set is a no-op; the flag is never cleared by `provision.sh`.

**R7.3** `provision.sh` MUST verify the `+a` flag is present after arming by checking `lsattr /var/log/osgania/audit.jsonl` and asserting that the `a` flag appears in the output.

**R7.4** `chattr +a` MUST be set AFTER the file exists (R6.3) and AFTER the ext4 check passes (R1.4). Ordering is load-bearing.

**R7.5** `provision.sh` MUST arm `chattr +a` in the **host namespace** (not inside a systemd unit, container, or capability-stripped environment). Rationale: the kernel enforces `EXT4_APPEND_FL` only at `open()` — a file descriptor opened BEFORE the flag is set is not subject to append-only. Arming in the host namespace before any agent runs guarantees the flag is set before Slice 2's launch unit ever opens the log FD.

**R7.6** `chattr +a` makes the file's existing content permanently preserved — even root cannot truncate or overwrite the file while the flag is set. To roll back, `chattr -a` must be run first (by root, in the host namespace). `provision.sh` MUST NOT run `chattr -a` on an existing armed file during a re-run.

**Isolation boundary (R7):** After `chattr +a` is set:
- `aios` can only append (Linux enforces this at the VFS layer for all users including root within the append-only constraint)
- Root can clear the flag (`chattr -a`) but this requires explicit deliberate action
- No unprivileged process can remove the `+a` flag
- Rollback requires `chattr -a` before any `rm` of the log file

---

### R8 — `jq` installation

**R8.1** `jq` MUST be installed and on `PATH` after provisioning. Both `guardia.sh` and `camara.sh` require `jq` at runtime; a fresh Ubuntu VPS does not include it.

**R8.2** `provision.sh` MUST verify `jq` presence with `which jq` returning a non-empty path with exit code 0 after installation.

**R8.3** If `jq` is already installed, `provision.sh` MUST skip the installation step (idempotent).

**R8.4** `jq` MUST be installed before any live validation step that invokes `guardia.sh` or `camara.sh` (both require `jq` at runtime). This mirrors the execution model: step 3 (jq installation) MUST complete before step 7 (live mode-lock test) which exercises the hook scripts.

**Isolation boundary (R8):** `jq` is a system package accessible to all users. No special isolation applies. `aios` can invoke `jq` (required for the hooks).

---

### R9 — Claude Code CLI version pin and verification

**R9.1** When the install mechanism (`npm`) is present, `provision.sh` MUST install the Claude Code CLI pinned to a specific version **>= v2.1.153** (the pinned version is the single source of truth; it MUST NOT be "latest-floating"). Slice 1 (the OS baseline) does NOT install the Node/npm runtime; on a fresh box where `npm` is absent, `provision.sh` MUST record — non-fatally — that CLI installation is **deferred to Slice 2** (`vps-provisioning-hardening`), which installs Node + the CLI, delivers the API key, and performs the live Layer-3 verification (R9.4). See Non-goals.

**R9.2** `provision.sh` MUST disable the CLI auto-updater at the provisioning/install context level (e.g., `DISABLE_AUTOUPDATER=1` during the install invocation itself, and any system-wide mechanism available on the target OS). `provision.sh` MUST record the installed version string (via `claude --version`) and the auto-updater-disabled status in its provisioning output. The pinned version MUST NOT drift due to background auto-update at the system level.

**R9.2a — Slice 2 forward dependency (DISABLE_AUTOUPDATER runtime persistence).** Durably setting `DISABLE_AUTOUPDATER=1` for the `aios` runtime invocation is a **Slice 2 forward dependency**. Slice 1 has no launch mechanism (the systemd unit is Slice 2's responsibility), and `aios` has no home directory or `~/.bashrc` to write to. Therefore `DISABLE_AUTOUPDATER=1` for the runtime environment MUST be established by Slice 2's systemd unit via `Environment=DISABLE_AUTOUPDATER=1` or an equivalent drop-in — not by Slice 1. This dependency is recorded in the Forward dependencies section of design.md.

**R9.3** `provision.sh` MUST run `claude --version`, capture the output string, and assert that the installed version is >= v2.1.153. If the detected version is below the floor, `provision.sh` MUST emit a **WARNING** flagging Layer-3 (`disableBypassPermissionsMode`) as a residual risk. This is a warning, not a hard abort — Layers 1 (managed-settings deny rules) and 2 (guardia) still hold; the operator decides. Cross-reference: platform-security-core R10.3 and KL-3.

**R9.4** `provision.sh` MUST run a **live mode-lock test** to validate that `disableBypassPermissionsMode: "disable"` is actually honored by the installed CLI. Acceptable forms:
- Attempt to invoke the CLI with `--dangerously-skip-permissions` against the installed managed policy and assert it is refused, OR
- Use the CLI's effective-policy introspection (if available) to assert the effective `disableBypassPermissionsMode` reads back as `"disable"`

**R9.5** If the live mode-lock test (R9.4) cannot be performed with the available CLI version/interface, `provision.sh` MUST record that the live validation did not run and flag Layer-3 as **UNVERIFIED residual risk** in the provisioning output. It MUST NOT claim Layer-3 works without machine-verifiable evidence.

**R9.6** `provision.sh` MUST NOT modify `platform/managed-settings.json` (the repository template) or `/etc/claude-code/managed-settings.json`. Specifically, it MUST NOT add or change `requiredMinimumVersion` in either file. Version enforcement is operational (install-pin + no auto-update) in this slice; a startup hard-gate belongs to a future explicit `platform-security-core` change.

**Isolation boundary (R9):** The CLI version pin is an operational control enforced by `provision.sh` as the only sanctioned installer. `DISABLE_AUTOUPDATER=1` is non-secret; its install-time use is within Slice 1's scope, but its persistence for the `aios` runtime invocation is a Slice 2 concern (systemd unit `Environment=` — see R9.2a). The live mode-lock test exercises the actual installed binary against the installed policy — it does not rely on the version number alone, because the v2.1.92 no-op floor is LOW confidence (from GitHub issue #44642, not the official changelog).

---

### R10 — `AUDIT_LOG` environment variable guarantee

**R10.1** `provision.sh` MUST NOT set `AUDIT_LOG` in any provisioned environment file, systemd unit drop-in, profile script, or shell rc file.

**R10.2** `provision.sh` MUST assert at the end of its run that `AUDIT_LOG` is not set in the environment it is executing in.

**R10.3** Rationale: `AUDIT_LOG` exists exclusively as a bats test-isolation override for `camara.sh` (platform-security-core R7.1a). In production, `camara.sh` uses the default path `/var/log/osgania/audit.jsonl`. If `AUDIT_LOG` were set in the production environment, `camara.sh` would write audit records to the override path, which may be unprotected, ephemeral, or absent — silently breaking the audit guarantee.

**Isolation boundary (R10):** `AUDIT_LOG` is a production-invisible variable. Any system configuration file that sets it in production scope is a defect. Provision.sh's final assertion (R10.2) catches accidental introduction of this variable during the install.

---

### R11 — Idempotency and collision-abort

**R11.1** Re-running `provision.sh` a second time on an already-provisioned system MUST NOT:
- Create a duplicate `aios` user or group
- Corrupt or clear the `+a` flag on `/var/log/osgania/audit.jsonl`
- Truncate or overwrite `/var/log/osgania/audit.jsonl` if it already exists
- Cause permissions to drift from the required values

**R11.2** Re-running `provision.sh` MUST re-assert and correct any permissions drift. Specifically, `install -d` and `install` invocations MUST re-apply the correct owner, group, and mode on every run — so a box whose permissions were manually changed is corrected by a re-run.

**R11.3** Re-running `provision.sh` MUST refresh the hook file content (R3.5, R3.6) — `guardia.sh` and `camara.sh` are overwritten with the current repository versions on every run. Root owns them so the overwrite is always permitted.

**R11.4** If UID 9001 is taken by a non-`aios` account, `provision.sh` MUST abort (R2.6). If GID 9001 is taken by a non-`aios` group, `provision.sh` MUST abort (R2.7). These are collision-abort conditions, not silent-overwrite conditions.

**R11.5** `chattr +a` MUST be applied with `+` (add-only) semantics (R7.2). On re-run, adding an already-set flag is a no-op — the audit trail is never disturbed.

**R11.6** The audit file MUST use a presence guard: `[ -f /var/log/osgania/audit.jsonl ] || install …`. On re-run, if the file exists, it is NOT recreated. Rationale: `install` would truncate the existing file (failing anyway under `+a`), but the presence guard prevents the attempt.

**Isolation boundary (R11):** Idempotency is a property of the installer (root-level), not of `aios`. The three idempotency hazards are: (1) duplicate user/group, (2) audit truncation, (3) permissions drift. R11.1–R11.6 address all three.

---

## Behavioral Scenarios

Scenarios are written for `bats-core` (`tests/provision.bats`). Assertions against live OS state (owner, mode, `+a`) are guarded by `PROVISION_TEST_ALLOW_MUTATION=1 && EUID==0`; without the guard they MUST `skip` with a clear message. The ext4/chattr assertions are only meaningful on a real ext4-backed root target (see design.md verification approach). A `--check` dry-run mode (R1.7) is exercisable without root on any host.

---

### PV-01 — `aios` user created with correct UID/GID/shell

**Requirement**: R2.1, R2.2

```
GIVEN provision.sh has run to completion on a fresh Ubuntu 24.04 or 26.04 VPS
WHEN `getent passwd aios` is queried
THEN the entry exists
 AND the UID field is 9001
 AND the GID field is 9001
 AND the shell field is /usr/sbin/nologin
      (provision.sh detects the nologin path live; on supported Ubuntu targets
       it MUST resolve to /usr/sbin/nologin — the assertion is against that value)
 AND the home directory field is /nonexistent

WHEN `stat /nonexistent` is run
THEN it exits with a non-zero code (the directory MUST NOT exist)
```

---

### PV-02 — `aios` not in sudo group

**Requirement**: R2.3, R2.4

```
GIVEN provision.sh has run to completion
WHEN `id -nG aios` is run
THEN the output does NOT contain the token "sudo"
 AND the output does NOT contain the token "admin"
```

---

### PV-03 — UID/GID 9001 collision with non-`aios` account causes abort

**Requirement**: R2.6, R2.7

```
GIVEN a system where UID 9001 is taken by a user named "collide"
WHEN provision.sh is run
THEN provision.sh exits with a non-zero exit code
 AND stderr contains a message identifying the UID collision
 AND no `aios` account is created
 AND no filesystem state is mutated
```

---

### PV-04 — GID 9001 collision with non-`aios` group causes abort

**Requirement**: R2.7

```
GIVEN a system where GID 9001 is taken by a group named "other"
WHEN provision.sh is run
THEN provision.sh exits with a non-zero exit code
 AND stderr contains a message identifying the GID collision
 AND no `aios` account is created
 AND no filesystem state is mutated
```

---

### PV-05 — Platform tree owner, group, and mode

**Requirement**: R3.1, R3.2

```
GIVEN provision.sh has run to completion
WHEN `stat -c '%U:%G %a' /opt/osgania/platform` is run
THEN the output is "root:aios 750"

WHEN `stat -c '%U:%G %a' /opt/osgania/platform/hooks` is run
THEN the output is "root:aios 750"
```

---

### PV-06 — Hook files owner, group, mode, and execute bit

**Requirement**: R3.3, R3.4

```
GIVEN provision.sh has run to completion
WHEN `stat -c '%U:%G %a' /opt/osgania/platform/hooks/guardia.sh` is run
THEN the output is "root:aios 750"

WHEN `stat -c '%U:%G %a' /opt/osgania/platform/hooks/camara.sh` is run
THEN the output is "root:aios 750"

WHEN `test -x /opt/osgania/platform/hooks/guardia.sh` is run
THEN exit code is 0

WHEN `test -x /opt/osgania/platform/hooks/camara.sh` is run
THEN exit code is 0
```

---

### PV-07 — No `managed-settings.json` copy under platform/

**Requirement**: R3.7

```
GIVEN provision.sh has run to completion
WHEN `test -f /opt/osgania/platform/managed-settings.json` is run
THEN exit code is non-zero (file MUST NOT exist)

WHEN `find /opt/osgania/platform -name 'managed-settings.json'` is run
THEN the output is empty
```

---

### PV-08 — No `/opt/osgania/client/` created

**Requirement**: R3.8

```
GIVEN provision.sh has run to completion
WHEN `test -d /opt/osgania/client` is run
THEN exit code is non-zero (directory MUST NOT exist)
```

---

### PV-09 — Operator policy installed at correct path with correct mode

**Requirement**: R4.1, R4.2, R4.4

```
GIVEN provision.sh has run to completion
WHEN `stat -c '%U:%G %a' /etc/claude-code/managed-settings.json` is run
THEN the output is "root:root 644"

WHEN `jq . /etc/claude-code/managed-settings.json` is run
THEN exit code is 0
 AND stdout is non-empty (valid JSON)
```

---

### PV-10 — Secrets directory mode and ownership

**Requirement**: R5.1, R5.2

```
GIVEN provision.sh has run to completion
WHEN `stat -c '%U:%G %a' /etc/osgania/secrets` is run
THEN the output is "root:root 700"

WHEN the directory is examined for any files written by provision.sh
THEN it is empty (provision.sh writes no secret values)
```

---

### PV-11 — Audit directory owner, group, and mode

**Requirement**: R6.1, R6.5

```
GIVEN provision.sh has run to completion
WHEN `stat -c '%U:%G %a' /var/log/osgania` is run
THEN the output is "root:aios 750"
```

---

### PV-12 — Audit file owner, group, and mode

**Requirement**: R6.2, R6.4

```
GIVEN provision.sh has run to completion
WHEN `stat -c '%U:%G %a' /var/log/osgania/audit.jsonl` is run
THEN the output is "root:aios 620"
```

---

### PV-13 — Audit file has `chattr +a` flag set

**Requirement**: R7.1, R7.3

```
GIVEN provision.sh has run to completion
WHEN `lsattr /var/log/osgania/audit.jsonl` is run
THEN the output contains the flag character "a" in the attribute field
 AND exit code is 0
```

---

### PV-14 — Target filesystem is ext4

**Requirement**: R1.4, R7.5 (ordering dependency)

```
GIVEN provision.sh has run to completion
WHEN `stat -f -c %T /var/log/osgania` is run
THEN the output indicates an ext4-family filesystem
```

---

### PV-15 — Non-ext4 filesystem causes abort before `chattr +a`

**Requirement**: R1.4

```
GIVEN a system where /var/log is on a tmpfs or overlayfs filesystem
WHEN provision.sh is run
THEN provision.sh exits with a non-zero exit code before reaching the chattr +a step
 AND stderr identifies the non-ext4 filesystem type
 AND /var/log/osgania/audit.jsonl is NOT created
```

---

### PV-16 — `jq` is on PATH after provisioning

**Requirement**: R8.1, R8.2

```
GIVEN provision.sh has run to completion
WHEN `which jq` is run
THEN exit code is 0
 AND stdout contains a non-empty file path
```

---

### PV-17 — CLI version is recorded and within range

**Requirement**: R9.1, R9.3

```
GIVEN provision.sh has run to completion
WHEN `claude --version` is run
THEN exit code is 0
 AND the version string parses as a semantic version
 AND the version is >= v2.1.153
```

---

### PV-18 — CLI auto-update is disabled at install/system level; runtime persistence is a Slice 2 forward dependency

**Requirement**: R9.2, R9.2a

```
GIVEN provision.sh has run to completion
WHEN the provisioning summary output is examined
THEN the output records the installed CLI version string (from `claude --version`)
 AND the output records that DISABLE_AUTOUPDATER was set during the install invocation
 AND any system-wide auto-update mechanism available on the target OS is disabled

NOTE: Durable setting of DISABLE_AUTOUPDATER=1 for the aios runtime invocation
is NOT asserted here — it is a Slice 2 forward dependency (systemd unit
Environment= or drop-in). Slice 1 has no launch mechanism and aios has no
home directory or ~/.bashrc to write to. The provisioning output MUST include
a note identifying this forward dependency for the operator.
```

---

### PV-19 — Layer-3 mode-lock live validation result is recorded

**Requirement**: R9.4, R9.5

```
GIVEN provision.sh has run to completion
WHEN the provisioning summary output is examined
THEN it contains an explicit statement about Layer-3 (disableBypassPermissionsMode) status:
  EITHER "Layer-3: VERIFIED" (live test confirmed it is honored)
  OR "Layer-3: UNVERIFIED — live test could not run" (live probe unavailable)

AND in no case does the output claim Layer-3 is verified without a successful live probe
```

---

### PV-20 — CLI version below floor emits WARNING (not abort)

**Requirement**: R9.3

```
GIVEN a system where the installed claude CLI version is below v2.1.153
WHEN provision.sh is run
THEN provision.sh does NOT abort (exits 0, continues provisioning)
 AND stderr or stdout contains a WARNING message
 AND the WARNING message identifies Layer-3 residual risk
 AND the installed version string is included in the output
```

---

### PV-21 — `AUDIT_LOG` is not set in the provisioned environment

**Requirement**: R10.1, R10.2

```
GIVEN provision.sh has run to completion
WHEN the shell environment is inspected (e.g. `env | grep AUDIT_LOG`)
THEN AUDIT_LOG is not present in the output
 AND exit code of the grep is non-zero (variable not set)
```

---

### PV-22 — Idempotent re-run produces no duplicate user

**Requirement**: R11.1, R11.2

```
GIVEN provision.sh has been run once and aios exists with UID/GID 9001
WHEN provision.sh is run a second time
THEN `getent passwd aios` returns exactly one entry
 AND `id -u aios` returns 9001
 AND exit code of provision.sh is 0
```

---

### PV-23 — Idempotent re-run does not corrupt the audit log

**Requirement**: R11.1, R11.5, R11.6

```
GIVEN provision.sh has been run once
  AND /var/log/osgania/audit.jsonl exists with inode N and contains content C
WHEN provision.sh is run a second time
THEN `stat -c %i /var/log/osgania/audit.jsonl` returns N (same inode — file not recreated)
 AND the file content is unchanged (content C is preserved)
 AND `lsattr /var/log/osgania/audit.jsonl` still shows the "a" flag
```

---

### PV-24 — Idempotent re-run corrects permissions drift

**Requirement**: R11.2

```
GIVEN provision.sh has been run once
  AND an operator manually changes the mode of /opt/osgania/platform to 0755
WHEN provision.sh is run a second time
WHEN `stat -c '%a' /opt/osgania/platform` is checked
THEN the mode is restored to 750
```

---

### PV-25 — Dry-run (`--check`) mode reports plan without mutating state

**Requirement**: R1.7

```
GIVEN provision.sh is invoked with the --check flag on any host
WHEN provision.sh runs
THEN exit code is 0
 AND stdout/stderr describe the provisioning plan (what would be applied)
 AND no user is created, no file is written, no chattr is run
 AND `getent passwd aios` returns no entry (or the pre-existing state is unchanged)
```

---

### PV-26 — Missing required tool causes abort before any mutation

**Requirement**: R1.5

```
GIVEN a system where `chattr` is not installed
WHEN provision.sh is run
THEN provision.sh exits with a non-zero exit code during phase 0 (preconditions)
 AND stderr identifies "chattr" as the missing tool
 AND no user is created
 AND no directory or file is written
```

---

### PV-27 — Audit file append-only protects existing content

**Requirement**: R7.1, R7.6

```
GIVEN provision.sh has run to completion
  AND /var/log/osgania/audit.jsonl has chattr +a set
  AND the file contains at least one line of content
WHEN an attempt is made to truncate the file (e.g. `> /var/log/osgania/audit.jsonl`)
THEN the truncation FAILS (the kernel blocks it due to +a)
 AND the original content is preserved
```

---

## Scenario-to-requirement map

| Scenario | Requirements |
|----------|-------------|
| PV-01 | R2.1, R2.2 |
| PV-02 | R2.3, R2.4 |
| PV-03 | R2.6 |
| PV-04 | R2.7 |
| PV-05 | R3.1, R3.2 |
| PV-06 | R3.3, R3.4 |
| PV-07 | R3.7 |
| PV-08 | R3.8 |
| PV-09 | R4.1, R4.2, R4.4 |
| PV-10 | R5.1, R5.2 |
| PV-11 | R6.1, R6.5 |
| PV-12 | R6.2, R6.4 |
| PV-13 | R7.1, R7.3 |
| PV-14 | R1.4, R7.5 |
| PV-15 | R1.4 |
| PV-16 | R8.1, R8.2 |
| PV-17 | R9.1, R9.3 |
| PV-18 | R9.2 |
| PV-19 | R9.4, R9.5 |
| PV-20 | R9.3 |
| PV-21 | R10.1, R10.2 |
| PV-22 | R11.1, R11.2 |
| PV-23 | R11.1, R11.5, R11.6 |
| PV-24 | R11.2 |
| PV-25 | R1.7 |
| PV-26 | R1.5 |
| PV-27 | R7.1, R7.6 |

Total scenarios: **27** (PV-01 through PV-27)

---

## Decided literals encoded verbatim (drift check)

The following concrete values are sourced from design.md and encoded verbatim. If any value here differs from design.md, design.md is the authoritative source — correct this spec, not the design.

| Item | Spec value | design.md source |
|------|-----------|-----------------|
| `aios` UID | 9001 | ADR-4 |
| `aios` GID | 9001 | ADR-4 |
| `aios` shell | `/usr/sbin/nologin` (detected live; asserted == this value on Ubuntu 24.04/26.04) | ADR-4 |
| `aios` home (record) | `/nonexistent` | ADR-4 |
| Home directory created | No | ADR-4 (`--no-create-home`) |
| `aios` in sudo group | No | ADR-4 |
| Password locked | Yes (`passwd -l`) | ADR-4 |
| `passwd -l` blocks SSH key login | No — explicit caveat | ADR-4 |
| Platform dir path | `/opt/osgania/platform/` | ADR-1, component map |
| Platform dir mode | `root:aios 0750` | ADR-1 |
| `hooks/` dir mode | `root:aios 0750` | ADR-1 |
| `guardia.sh` mode | `root:aios 0750` | ADR-1 |
| `camara.sh` mode | `root:aios 0750` | ADR-1 |
| `managed-settings.json` copy under `platform/` | None (not placed there) | ADR-1 |
| `/opt/osgania/client/` in Slice 1 | Not created | ADR-3 |
| Operator policy path | `/etc/claude-code/managed-settings.json` | component map |
| Operator policy mode | `root:root 0644` | component map, boundaries table |
| Secrets dir path | `/etc/osgania/secrets/` | component map |
| Secrets dir mode | `root:root 0700` | component map, boundaries table |
| Secrets values written | None | ADR, S-1..S-5 |
| Audit dir path | `/var/log/osgania/` | component map |
| Audit dir mode | `root:aios 0750` | component map, boundaries table |
| Audit file path | `/var/log/osgania/audit.jsonl` | component map |
| Audit file mode | `root:aios 0620` | component map, boundaries table |
| `chattr +a` operator | `+a` (add-only) | idempotency table |
| `chattr +a` namespace | Host namespace, before any agent | execution model |
| `chattr +a` timing | Before any `open()` by an agent | execution model |
| Target FS for audit dir | ext4 (abort if not ext4) | phase 0 preconditions |
| `jq` required | Yes, installed via apt if absent | component map |
| CLI version floor | >= v2.1.153 | ADR-2 |
| `requiredMinimumVersion` touched | No | ADR-2 |
| Auto-update disabled | `DISABLE_AUTOUPDATER=1` | ADR-2 |
| Live mode-lock test | Required; flag UNVERIFIED if unavailable | ADR-2 |
| `AUDIT_LOG` set by provision.sh | Never | C-13, S-4 |
| `AUDIT_LOG` unset assertion | At end of provision.sh run | execution model phase 8 |

---

## Assumptions

No open questions remain at spec time. All four open questions (OD-PLATFS, OD-VERPIN, OD-CLIENTFS, OD-AIOS) were resolved by the design phase. The decided literals above are authoritative; this spec encodes them without re-derivation.

---

## Non-goals (reiterated for contract clarity)

- Firewall configuration (UFW, iptables) — Slice 2
- systemd unit for agent launch — Slice 2
- SSH access control for `aios` — Slice 2 (`passwd -l` is applied but does not block key-based SSH)
- logrotate under `chattr +a` — Slice 2
- API key delivery — Slice 2
- Node/npm runtime + Claude CLI installation, and the live Layer-3 (`disableBypassPermissionsMode`) mode-lock verification — Slice 2. Slice 1 records/flags CLI state only (non-fatal); the live mode-lock test also requires the API key, which Slice 2 delivers.
- Docker/Coolify coexistence — Slice 2 (conditional)
- `/opt/osgania/client/` tree — onboarding + Slice 2
- Modifying `platform/managed-settings.json` or adding `requiredMinimumVersion` — a future explicit `platform-security-core` change
- unattended-upgrades posture — Slice 2
