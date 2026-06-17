# Design: vps-provisioning-base

**Change**: vps-provisioning-base (Slice 1 of 2 — the deterministic OS baseline)
**Project**: osgania
**Artifact store**: openspec
**Date**: 2026-06-14
**Status**: design
**Depends on**: proposal.md (required, APPROVED), explore.md (constraints C-01..C-14 + verified facts), platform-security-core spec.md (the contract this slice makes enforceable)

This document is the HOW at the architectural level. It resolves the **four open questions** the proposal left for design (OD-PLATFS, OD-VERPIN, OD-CLIENTFS, OD-AIOS), records architecture decisions as ADRs (decision + rationale + alternatives + consequences), and fixes the **exact, concrete values** the spec must encode. Implementation tasks come next (`sdd-tasks`); this design does not list per-file steps.

> **Drift gate.** In the prior change (platform-security-core) the spec and design drifted on the `disableBypassPermissionsMode` key shape and required painful reconciliation. To prevent a repeat, every decided value here is stated as a single unambiguous literal (owner, group, octal mode, path, version string, UID/GID). The spec phase MUST copy these literals verbatim; it MUST NOT re-derive or "improve" them. If a value looks wrong, change it HERE first, then propagate — never let spec and design hold two different numbers.

---

## Quick path (what was decided)

| # | Open question | Decision (one concrete line) |
|---|---------------|------------------------------|
| OD-PLATFS | Owner/mode of `/opt/osgania/platform/` and contents | `root:aios 0750` for the tree and `hooks/`; hook `*.sh` files `root:aios 0750` (r-x to group, +x present); no `managed-settings.json` copy lives under `platform/` (it goes only to `/etc/claude-code/`). World has NO access. |
| OD-VERPIN | CLI version-pin strategy | **Option (a): install-pin only.** Pin+install a specific version, disable auto-update (`DISABLE_AUTOUPDATER=1`), record `claude --version`, run a **live mode-lock test**. Do **NOT** touch `requiredMinimumVersion` in the archived template (no boundary crossing). Pin target floor: **>= v2.1.153** (the version platform-security-core verified installed; well above the low-confidence v2.1.92 no-op floor from issue #44642). |
| OD-CLIENTFS | Create `/opt/osgania/client/` now? | **Defer entirely.** Slice 1 does NOT create the client tree. It is owned by onboarding (populates context) + Slice 2 (systemd `ReadWritePaths`). Creating an empty writable tree now would be dead, unmanaged state. |
| OD-AIOS | `aios` account shape | System account via `useradd -r`; shell `/usr/sbin/nologin`; **no functional home** (`--home-dir /nonexistent --no-create-home`); **hardcoded UID/GID 9001** for fleet consistency; primary group `aios` GID 9001; `passwd -l` applied (with the explicit caveat that it does NOT block SSH key login — SSH posture is Slice 2). |

The provisioning-flow diagram (ordering + dependencies) is in the **Execution model** section; this slice has **no agent-to-app communication** (it is an installer) — see the **Sequence diagram** section for why the config-rule sequence diagram is replaced by a provisioning-flow diagram.

---

## Architecture at a glance

### What this slice is

`provision.sh` is a **single, idempotent, root-run installer** for a fresh Ubuntu VPS. It is not a service, not a long-running process, and has no runtime/agent communication. Its only job is to mutate OS state so that the already-shipped three-locks artifacts (`managed-settings.json`, `guardia.sh`, `camara.sh`) become **load-bearing** instead of theoretical.

It turns five preconditions from "assumed by the contract" into "true on the box":

1. A no-sudo `aios` system account exists.
2. The platform tree is installed at exactly `/opt/osgania/platform/`, root-owned, read+execute-only to `aios`.
3. The operator policy is at `/etc/claude-code/managed-settings.json`.
4. The denied secrets directory `/etc/osgania/secrets/` exists, root-only.
5. **The audit log is pre-created AND `chattr +a`-armed in the host namespace BEFORE any agent can open it** — the single highest-value, highest-risk step (R5.5).

### Component map (install targets vs install sources)

```
   repo (install SOURCE)                          live VPS (install TARGET)
   ─────────────────────                          ─────────────────────────
   platform/managed-settings.json   ──copy──►     /etc/claude-code/managed-settings.json   (root:root 0644)
   platform/hooks/guardia.sh        ──install──►  /opt/osgania/platform/hooks/guardia.sh    (root:aios 0750, +x)
   platform/hooks/camara.sh         ──install──►  /opt/osgania/platform/hooks/camara.sh     (root:aios 0750, +x)

   (no source — created by provision.sh)
                                    ──create──►    aios system account (UID/GID 9001, nologin, no home, no sudo)
                                    ──create──►    /opt/osgania/platform/                    (root:aios 0750)
                                    ──create──►    /opt/osgania/platform/hooks/              (root:aios 0750)
                                    ──create──►    /etc/osgania/secrets/                     (root:root 0700)
                                    ──create──►    /var/log/osgania/                         (root:aios 0750)
                                    ──create──►    /var/log/osgania/audit.jsonl              (root:aios 0620, chattr +a)
                                    ──install──►   jq (apt)                                  (system package)
                                    ──pin/verify─► claude (CLI)                              (>= v2.1.153, auto-update off)
```

### Boundaries (isolation contract — what each principal can do after provisioning)

| Resource | Owner:Group / Mode | `aios` capability | Rationale |
|----------|--------------------|--------------------|-----------|
| `/opt/osgania/platform/` (+ `hooks/`) | `root:aios 0750` | read + traverse + execute hooks; **cannot write** | Operator layer, read-only to agent (config.yaml). Hooks invoked AS `aios` by the runtime, so `aios` needs r-x; root-owned blocks tampering. |
| `/opt/osgania/platform/hooks/*.sh` | `root:aios 0750` | read + execute; **cannot write** | Hook scripts run as `aios`; need +x and read. Root-owned + group-only (not world) = least privilege. |
| `/etc/claude-code/managed-settings.json` | `root:root 0644` | read only (it is operator policy the runtime reads) | World-readable policy is fine and conventional for `/etc`; it contains no secret. `aios` cannot edit (also denied by `Edit/Write(/opt/osgania/platform/**)` for the repo path, and OS perms here). |
| `/etc/osgania/secrets/` | `root:root 0700` | **NO access** (no read, no traverse) | Secrets store. `aios` must never read; policy `Read(/etc/osgania/secrets/**)` + guardia substring deny mirror this. Slice 1 writes NO secret values. |
| `/var/log/osgania/` | `root:aios 0750` | traverse + list entries (`r-x` on dir); **CANNOT read audit file contents** (file is group write-only, `0620`); **cannot create files** | Group `r-x` on the dir lets `aios` list entries and traverse; no dir write bit so `aios` cannot create files. The file's group bit is write-only (`0620`) so `aios` cannot read audit contents. File must be pre-created by root so its mode/owner/`+a` are correct. |
| `/var/log/osgania/audit.jsonl` | `root:aios 0620` + `chattr +a` | **append only**; cannot truncate/overwrite/delete | `camara.sh` (running as `aios`) appends one line per tool call. `+a` makes append the only mutation even for root. |
| `aios` account | UID/GID 9001, nologin, no home | not in sudo group; cannot escalate | "Client-facing agent has NO root" (config.yaml). |

---

## OD-PLATFS — platform tree ownership and mode

### ADR-1 — `/opt/osgania/platform/` is `root:aios 0750` (group read-execute), NOT world-readable `root:root 0755`

- **Decision.** The platform directory, its `hooks/` subdirectory, and the two hook `*.sh` files are all owned `root:aios` with mode **`0750`**. Concretely:
  - `/opt/osgania/platform/` → `root:aios 0750`
  - `/opt/osgania/platform/hooks/` → `root:aios 0750`
  - `/opt/osgania/platform/hooks/guardia.sh` → `root:aios 0750` (the `5` on group provides r-x; the execute bit C-12/R13.2 requires is present)
  - `/opt/osgania/platform/hooks/camara.sh` → `root:aios 0750`
  - **No `managed-settings.json` copy lives under `platform/`.** The policy is installed only to `/etc/claude-code/managed-settings.json` (C-04). The repo template stays in the repo; provision.sh copies it to `/etc/claude-code/` and does NOT also place a copy under `/opt/osgania/platform/`. This avoids two divergent copies of the policy on the box.

- **Why `0750 root:aios` over `0755 root:root`.** The runtime invokes the hooks **as the `aios` user** (the agent's account), so `aios` must be able to read and execute `guardia.sh`/`camara.sh`. Two ways to grant that:
  - `root:root 0755` — world r-x. Simplest, and `aios` (as "other") gets r-x. But it makes the hook source **world-readable to every account on the box**. On a single-purpose VPS there are few other accounts today, but least-privilege says: grant the capability to the principal that needs it (`aios`, via the group), not to the whole world.
  - `root:aios 0750` — group r-x, **no world access**. `aios` is in group `aios` (its primary group), so it gets r-x; nobody else does. Root still owns and is the only writer.
  Both satisfy the functional requirement (aios can read+execute). `0750 root:aios` is **strictly tighter** with zero functional cost, so least-privilege selects it. This also mirrors the audit-tree pattern (`/var/log/osgania/` is `root:aios 0750`), keeping one consistent ownership model across the operator-owned, agent-readable trees.

- **Why hook files are `0750` not `0550`.** `0550` (no owner write) would make even root unable to overwrite the file without a `chmod` first, which fights idempotent re-install (provision.sh re-copies the hook on re-run). `0750` keeps owner (root) writable for clean re-install while denying group/world write. `aios` group still gets only r-x.

- **Consequences / accepted costs.**
  - `aios` MUST be its own primary group for the `0750` group grant to reach it; OD-AIOS sets primary group `aios` GID 9001 — these two decisions are coupled.
  - Any future non-`aios` account that must run the hooks would need to be added to group `aios`; acceptable, and more explicit than world-readable.
  - The execute bit is **inside** the `0750` (the `0` for owner-as-root-write is `7`, group `5` = r-x). provision.sh sets the mode explicitly with `install -m 0750`; it does not rely on a separate `chmod +x`, so the spec's R13.2 "execute permission" is satisfied by the mode literal, not by an additional step.

- **Rejected — `root:root 0755` (world r-x).** Functionally equivalent for `aios` but leaks hook source to all accounts; violates least-privilege for no benefit.
- **Rejected — `root:aios 0710` (group execute-only, no read).** A script needs **read** to be interpreted by `bash` (the kernel reads the `#!` line, then `bash` reads the file). Execute-without-read fails for interpreted scripts. So `0710` would break the hooks. `0750` (r-x) is the minimum that works.

---

## OD-VERPIN — Claude Code CLI version-pin strategy

### ADR-2 — Install-pin + disable auto-update + live mode-lock test; do NOT modify the archived template

- **Decision: Option (a).** This slice pins the CLI **at install time** to a specific version, **disables auto-update**, **records** the running version, and **validates** that Layer-3 mode-lock actually works with a **live test**. It does **NOT** add or change `requiredMinimumVersion` inside `managed-settings.json` — that key lives in the archived `platform-security-core` template, and editing it would cross that change's boundary (Modified Capabilities = None per the proposal). The managed hard-gate (`requiredMinimumVersion`) is left for a **separate, explicit change** to platform-security-core if/when a startup gate is wanted.

- **Concrete pinned-version target.** Floor = **>= v2.1.153**. Rationale for the number: platform-security-core's verify note (spec R10.3 "Verification note 2026-06-14") records v2.1.153 as installed and 61 versions past the known-affected v2.1.92. The v2.1.92 no-op is **LOW confidence** — it comes from GitHub issue #44642, not the official changelog — so we do NOT treat v2.1.92 as a trustworthy floor; we pin **well above** it. provision.sh pins the exact version it installs (a single literal, e.g. the latest available >= v2.1.153 at provision time) and records that exact string.

- **How provision.sh pins, disables update, verifies, and validates.**
  1. **Install-pin.** Install a specific version, not "latest-floating". Two acceptable mechanisms depending on the install channel available on the box (detected, not hardcoded): (i) the official installer invoked with an explicit version argument, or (ii) the apt package pinned to an exact version (`claude-code=<exact>`). The chosen exact version string is the single source of truth.
  2. **Disable auto-update.** Set the CLI auto-updater off during the install invocation (`DISABLE_AUTOUPDATER=1`) and via any system-wide mechanism available on the target OS, so the pin cannot drift. This env var is non-secret. **Slice 2 forward dependency:** durably setting `DISABLE_AUTOUPDATER=1` for the `aios` runtime invocation is out of scope for Slice 1 — Slice 1 has no launch mechanism and `aios` has no home directory or `~/.bashrc`. It MUST be established by Slice 2's systemd unit via `Environment=DISABLE_AUTOUPDATER=1` or an equivalent drop-in. Out of scope here: OS-level unattended-upgrades posture (Slice 2 OD-PATCH) — but provision.sh MUST NOT let an OS package manager silently upgrade the CLI past the pin.
  3. **Verify the running version.** `claude --version`, capture the string, assert it parses and is **>= v2.1.153**; record it (the provisioning test asserts the recorded version is present and within range). If the version is **below** the floor, provision.sh emits a clear **WARNING** flagging Layer-3 residual risk (not a hard abort — Layers 1+2 still hold; the operator decides), consistent with the proposal's "flag residual risk if degraded".
  4. **Live mode-lock validation.** Because the v2.1.92 floor is low-confidence, do NOT trust the version number alone. provision.sh (or the paired provisioning test) runs a **live check** that `disableBypassPermissionsMode: "disable"` is actually honored: attempt to enter bypass mode / `--dangerously-skip-permissions` against the installed managed policy and assert it is refused. If the CLI exposes a machine-readable settings/effective-policy introspection, assert the effective `disableBypassPermissionsMode` reads back as `"disable"`. If neither live probe is available on the installed CLI, record that the live validation could not run and flag Layer-3 as **unverified residual risk** in the provisioning output (honesty gate — never claim it works without evidence).

- **Why NOT modify the template (Option b).** Adding `requiredMinimumVersion` to `/etc/claude-code/managed-settings.json` would require either (i) editing the archived repo template (changes platform-security-core's shipped artifact → boundary crossing, and the spec's MS-07/R10 set is pinned to the current JSON shape) or (ii) installing a policy that differs from the versioned template (drift between repo and box — the exact class of bug that caused the prior reconciliation pain). Both are worse than an install-pin for a single-purpose box where provision.sh is the only installer. The hard-gate is a real future improvement but it belongs to a deliberate platform-security-core change with its own ADR, not smuggled into the provisioning baseline.

- **Consequences.**
  - The CLI version is enforced **operationally** (install-pin + no auto-update + provisioning assertion), not **declaratively** (no startup gate). If someone manually upgrades/downgrades the CLI outside provision.sh, only a re-run of provision.sh (or the live test) catches it. Accepted: provision.sh is the only sanctioned mutator of the box.
  - Layer-3 confidence rests on the **live test**, not the version number — which is the correct posture given the low-confidence floor.
  - A future platform-security-core change can add `requiredMinimumVersion` for a true startup gate without conflicting with this slice.

- **Rejected — Option (b): add `requiredMinimumVersion` to managed-settings.json now.** Crosses the archived-change boundary; introduces repo↔box drift risk; couples the provisioning baseline to a template edit. Deferred to an explicit platform-security-core change.
- **Rejected — trust the version number alone (skip the live test).** The v2.1.92 floor is from an issue, not the changelog (low confidence). A version >= floor is necessary but NOT sufficient evidence that mode-lock works. The live test is the only honest validation.

---

## OD-CLIENTFS — `/opt/osgania/client/` creation

### ADR-3 — Do NOT create the client tree in Slice 1; defer entirely to onboarding + Slice 2

- **Decision.** Slice 1 creates **no** `/opt/osgania/client/` tree. The per-client writable workspace is created and owned by the **onboarding generator** (which populates client context from `intake.yaml`) and made writable to the agent by **Slice 2's systemd unit** via `ReadWritePaths=`. provision.sh leaves `/opt/osgania/client/` absent.

- **Rationale.**
  - **No consumer in Slice 1.** Slice 1 does not start the agent (proposal boundary note) and Slice 2 owns the launch unit + `ReadWritePaths`. An empty `client/` directory created now would be **dead, unmanaged state**: nothing reads or writes it, and its correct shape (owner, mode, subdirs) depends on decisions Slice 2/onboarding own.
  - **Avoids premature ownership lock-in.** If Slice 1 guessed a mode/owner for `client/`, onboarding/Slice 2 would likely have to change it — re-introducing exactly the kind of cross-slice drift the drift gate warns against. The archived platform-security-core design already **deferred the client tree entirely** (ADR-002 rejected placing the audit log under `client/`); this slice respects that deferral.
  - **The audit log does NOT need it.** ADR-002 of platform-security-core fixed the audit path at `/var/log/osgania/audit.jsonl`, explicitly NOT under `client/`. So nothing load-bearing in Slice 1 depends on `client/` existing.

- **Consequences.**
  - Slice 2 / onboarding MUST create `/opt/osgania/client/` with the agent-writable ownership the launch unit expects. Recorded here as a forward dependency so it is not lost.
  - provision.sh's precondition checks and tests assert the platform tree, secrets dir, and audit tree — NOT `client/`.

- **Rejected — create a minimal writable workspace now (e.g. `/opt/osgania/client/ root:aios 0750`).** Creates unmanaged state with no consumer, pre-empts Slice 2/onboarding ownership, and risks a mode/owner mismatch that a later slice must undo. No benefit in Slice 1.

---

## OD-AIOS — `aios` account shape

### ADR-4 — System account `useradd -r`, nologin, no home, hardcoded UID/GID 9001, password locked

- **Decision (concrete).**
  - **Account type:** system account created with `useradd -r` (reserved-range semantics, no aging, no per-user group surprises). Equivalent `adduser --system --group` is acceptable only if it yields the same end state (system UID, nologin, the explicit GID), but `useradd -r` is the primary mechanism because it lets us set the exact UID/GID/shell/home in one call deterministically.
  - **Shell:** `/usr/sbin/nologin` (the Debian/Ubuntu canonical nologin path; provision.sh detects it via the live box rather than hardcoding `/sbin/nologin`).
  - **Home directory:** **no functional home** — `--home-dir /nonexistent --no-create-home`. The account needs no home; a home dir is attack surface and writable state we do not want for a service identity. (If a future tool requires `$HOME`, Slice 2 can introduce a locked, root-owned home — not Slice 1.)
  - **UID/GID:** **hardcoded to 9001** for both, with primary group `aios` (GID 9001). Concretely: `groupadd -g 9001 aios` then `useradd -r -u 9001 -g 9001 -s /usr/sbin/nologin --home-dir /nonexistent --no-create-home aios`.
  - **Sudo:** NOT in `sudo` (or `admin`) group — never added. provision.sh asserts `aios` is absent from sudoers/sudo group post-create (C-08, spec R2.1 rationale).
  - **Password:** `passwd -l aios` (locked). **Explicit caveat (verified gotcha):** `passwd -l` locks the *password* but does **NOT** block SSH **key** login. SSH posture for `aios` (e.g. `DenyUsers aios` / `AllowUsers` in `sshd_config`, or no authorized_keys) belongs to **Slice 2 / sshd hardening** and is OUT OF SCOPE here. provision.sh states this in its output so the operator is not lulled into thinking the account is SSH-sealed.

- **Why hardcode UID/GID 9001 (fleet consistency) instead of letting the system assign.**
  - OSGANIA is **one VPS per client** — a fleet of boxes. If `aios` gets a system-assigned UID, the number can differ box-to-box (depends on what else claimed system UIDs first). The audit log and platform tree are `root:aios`; backups, forensic tooling, and any cross-box automation that compares numeric ownership become inconsistent across the fleet if the UID drifts.
  - A fixed, documented UID/GID makes every box identical at the numeric-ownership level — easier to reason about, audit, and restore. **9001** is chosen as a memorable value comfortably inside the system range and unlikely to collide with distro-reserved low system UIDs.
  - **Consequence / accepted risk:** provision.sh MUST handle the case where UID/GID 9001 is **already taken** by a different account on a non-fresh box. Idempotency design (below) addresses this: if `getent passwd 9001` / `getent group 9001` resolves to a NON-`aios` name, provision.sh **aborts with a clear error** rather than clobbering an unrelated account. On a truly fresh box (the target) 9001 is free.

- **Why `useradd -r` (system) over a regular account.** A regular account gets login aging, a created home, and a UID in the human range — none of which a service identity should have. System accounts are the correct shape for a non-interactive runtime identity (config.yaml: agent is not a human user).

- **Consequences.**
  - Primary group `aios` GID 9001 is what makes OD-PLATFS's `0750 root:aios` group grant reach the runtime — the two ADRs are coupled (stated in ADR-1).
  - No home means no `~/.claude` under `aios` by default; if the CLI needs a config/cache dir, Slice 2's launch unit must provide an explicit writable path via `ReadWritePaths`/`StateDirectory` (forward dependency, not Slice 1's concern).

- **Rejected — let the system assign UID/GID.** Causes fleet-wide numeric-ownership drift; harms cross-box auditing/backup/restore. The marginal simplicity is not worth the inconsistency for a fleet product.
- **Rejected — give `aios` a real home (`/home/aios` or `/opt/osgania/aios`).** Adds writable state and attack surface a service identity does not need in Slice 1. Deferred to Slice 2 only if a concrete tool requires `$HOME`.
- **Rejected — rely on `passwd -l` for SSH sealing.** Verified false: `passwd -l` does not block key-based SSH. Real SSH sealing is sshd config = Slice 2.

---

## Execution model and ordering

provision.sh runs as **root** and executes these ordered phases. Order is load-bearing where noted; the rest is grouped for clean dependency flow.

```
provision.sh  (root, host namespace, single run, idempotent)
│
├─ 0. PRECONDITION / LIVENESS CHECKS  ───────────  abort early with clear errors
│     • OS via /etc/os-release (ID=ubuntu; VERSION_ID detected, NOT hardcoded; 26.04 target, 24.04 fallback)
│     • systemd present (systemctl --version)            [Slice 2 needs it; assert now]
│     • required tools: install, stat, useradd/adduser, getent, chattr/lsattr (e2fsprogs), jq-or-apt, claude-or-installer
│     • /var/log target FS is ext4  (stat -f -c %T /var/log)   ← chattr +a is a SILENT NO-OP on tmpfs/overlayfs
│           └─ if NOT ext4 → ABORT (arming a no-op append-only flag would give false integrity confidence)
│
├─ 1. CREATE GROUP + USER  (OD-AIOS)
│     • getent group  9001 → if taken by non-"aios" ABORT; else groupadd -g 9001 aios   (|| already exists)
│     • getent passwd 9001 → if taken by non-"aios" ABORT
│     • id aios &>/dev/null || useradd -r -u 9001 -g 9001 -s /usr/sbin/nologin --home-dir /nonexistent --no-create-home aios
│     • passwd -l aios   (idempotent; lock is add-only in effect)
│     • assert aios NOT in sudo/admin group
│           └─ MUST run before any chown to root:aios (the group must exist first)
│
├─ 2. INSTALL PLATFORM TREE + HOOKS  (OD-PLATFS)
│     • install -d -o root -g aios -m 0750 /opt/osgania/platform
│     • install -d -o root -g aios -m 0750 /opt/osgania/platform/hooks
│     • install -o root -g aios -m 0750 platform/hooks/guardia.sh /opt/osgania/platform/hooks/guardia.sh
│     • install -o root -g aios -m 0750 platform/hooks/camara.sh  /opt/osgania/platform/hooks/camara.sh
│           └─ mode 0750 already carries +x (C-12 / R13.2 satisfied by the literal mode, no separate chmod)
│
├─ 3. INSTALL jq  (OD-JQ)
│     • which jq || apt-get install -y jq     (verify with `which jq` after)
│
├─ 4. INSTALL OPERATOR POLICY  (C-04)
│     • install -d -o root -g root -m 0755 /etc/claude-code
│     • install -o root -g root -m 0644 platform/managed-settings.json /etc/claude-code/managed-settings.json
│           └─ no second copy under /opt/osgania/platform/ (single source of truth on the box)
│
├─ 5. CREATE SECRETS DIR  (C-09)   ← root-only, NO aios access; writes NO secret value
│     • install -d -o root -g root -m 0700 /etc/osgania/secrets
│
├─ 6. ★ PRE-CREATE + ARM AUDIT LOG ★  (C-01/C-02/C-03)  ← HIGHEST VALUE, ORDER-CRITICAL
│     • install -d -o root -g aios -m 0750 /var/log/osgania
│     • [ -f /var/log/osgania/audit.jsonl ] || install -o root -g aios -m 0620 /dev/null /var/log/osgania/audit.jsonl
│     • chattr +a /var/log/osgania/audit.jsonl          ← MUST be in the HOST namespace, BEFORE any agent open()
│     • verify: lsattr shows 'a'; stat shows 0620 root:aios
│           └─ the kernel checks EXT4_APPEND_FL only at open(); arming here (Slice 1, no agent running)
│              guarantees the flag is set before Slice 2's launch unit ever opens the FD
│
├─ 7. PIN + VERIFY + LIVE-TEST CLI  (OD-VERPIN)
│     • install-pin a specific version (>= v2.1.153); disable auto-update (DISABLE_AUTOUPDATER=1)
│     • record `claude --version`; assert >= floor (WARN + flag Layer-3 residual risk if below)
│     • live mode-lock test: assert disableBypassPermissionsMode is honored (or flag UNVERIFIED if no probe)
│
└─ 8. POST-CONDITION ASSERTIONS  (no secret printed; AUDIT_LOG must be UNSET)
      • assert env AUDIT_LOG is unset in the provisioned runtime env  (C-13: setting it misdirects prod logs)
      • print a non-secret summary (paths, owners, modes, version, Layer-3 status)
```

### Why the order matters

- **Group/user (1) before any `chown`/`install -g aios` (2,6).** `install -g aios` fails if the `aios` group does not yet exist. Creating the principal first is a hard dependency.
- **★ Arm `chattr +a` (6) in the host namespace, before any agent runs.** The kernel enforces `EXT4_APPEND_FL` **only at `open()`** — a file descriptor opened before the flag is set is NOT subject to append-only (existing-FD bypass). Slice 1 does not start the agent, so arming here guarantees the flag is already set before Slice 2's launch unit ever opens the log. Arming it later (e.g. inside a capability-stripped systemd unit) risks the unit dropping `CAP_LINUX_IMMUTABLE`, after which even root in that context cannot set/clear `+a`. Host-namespace arming in Slice 1 sidesteps that entirely.
- **ext4 check (0) before arming (6).** `chattr +a` is a **silent no-op** on tmpfs/overlayfs. Arming a no-op flag would give false integrity confidence (operator believes the log is tamper-proof when it is not). Aborting on non-ext4 is the honest posture.
- **Policy install (4) is independent of the audit arming** but is placed before the CLI pin (7) so the live mode-lock test (7) reads the freshly-installed policy.
- **AUDIT_LOG-unset assertion (8) last**, after everything is in place, so the final state is verified holistically.

---

## Idempotency design

provision.sh is **safe to re-run** (the proposal's day-to-day repair path). Each step uses an idempotent primitive:

| Step | Primitive | Re-run behavior |
|------|-----------|-----------------|
| Group create | `getent group 9001` guard + `groupadd \|\| true` | No duplicate group; abort only if 9001 belongs to a non-`aios` name. |
| User create | `id aios &>/dev/null \|\|` guard | No duplicate user; existing `aios` left intact. |
| Password lock | `passwd -l` | Locking an already-locked password is a no-op. |
| Dirs (`platform/`, `hooks/`, `secrets/`, `/var/log/osgania/`) | `install -d -o … -g … -m …` | Creates if absent; **re-asserts owner+mode every run** → fixes perms drift. |
| Hook files + policy | `install -o … -g … -m …` (copy) | Overwrites with correct content+owner+mode each run (root owns, so write is permitted) → fixes drift, refreshes content. |
| Audit FILE create | `[ -f ] \|\| install … /dev/null …` | Creates **only if absent** → never truncates an existing audit trail. |
| `chattr +a` | `chattr +a` (the `+` operator is **add-only**) | Setting an already-set flag is a no-op → no `+a` corruption. |
| jq | `which jq \|\| apt-get install` | Installs only if missing. |
| CLI pin | version-equality check before re-install | Re-installs only if the running version ≠ pinned version. |

**The three idempotency hazards and how they are avoided:**
1. **Duplicate user/group** → `id`/`getent` guards before create.
2. **`+a` corruption / audit truncation** → audit file is `[ -f ] ||` (never recreated if present); `chattr +a` is add-only (never toggled off). The existing append-only trail is never disturbed on re-run.
3. **Perms drift** → `install -d`/`install` re-assert owner+group+mode on every run, so a box whose perms were manually changed is corrected back to the contract by a re-run.

> **Note on `chattr +a` and re-running `install` on the audit file.** Because the audit FILE step is `[ -f ] ||`, provision.sh never re-`install`s over an existing, `+a`-armed audit file (which would fail anyway — `install` truncates, and `+a` blocks truncation even for root). The dir step re-asserting `0750 root:aios` on `/var/log/osgania/` is safe (the dir is not `+a`). This is why the file uses a presence guard while the dir does not.

---

## Liveness / precondition checks (detail)

All checks run in **phase 0** and abort with a clear, actionable error before any mutation:

| Check | Mechanism | Abort reason if it fails |
|-------|-----------|--------------------------|
| OS is Ubuntu, version detected | parse `/etc/os-release` (`ID`, `VERSION_ID`) | Not Ubuntu, or unsupported version (target 26.04, fallback 24.04; never hardcode — detect and branch). |
| systemd present | `systemctl --version` exits 0 | Slice 2 launch unit needs systemd; assert the foundation now. |
| ext4 for `/var/log/osgania` | `stat -f -c %T /var/log` (or the nearest existing ancestor of the target — the subdir `/var/log/osgania/` does NOT exist yet at precondition time) reports ext4 family. Post-run PV-14 re-checks using `/var/log/osgania` (same filesystem, subdir now exists). | `chattr +a` is a silent no-op on tmpfs/overlayfs → false integrity. Refuse to arm. |
| `chattr`/`lsattr` available | `command -v chattr lsattr` (e2fsprogs) | Cannot arm/verify append-only. |
| `useradd` or `adduser` available | `command -v useradd \|\| command -v adduser` | Cannot create the `aios` account. |
| `install`, `stat`, `getent` available | `command -v …` | Cannot set deterministic owner/mode or query identities. |
| `jq` installable | `which jq \|\| apt-get -s install jq` (simulate) | Hooks fail at runtime without jq. |
| CLI installable/pinnable | install channel detected (installer or apt) | Cannot pin/verify the CLI. |

Version-sensitive facts are **re-verified live** (the explore honesty gate): do not assume 26.04 is GA — detect `VERSION_ID`, branch, and re-check `useradd`/`passwd`/nologin path on the actual box.

---

## Verification approach (testing a root-mutating installer)

The platform-security-core bats suite **excludes** chattr/perm-mode checks (spec R7 testability boundary: "Do NOT add bats scenarios that verify chattr or file-system permission modes"). Therefore this slice **carries its own** provisioning verification, `tests/provision.bats` (bats-core, the project's canonical runner).

### What `tests/provision.bats` asserts (end-state, post-run)

| Assertion | Command | Target value |
|-----------|---------|--------------|
| `aios` exists, system account, nologin, no sudo | `getent passwd aios`; `id -u aios`; `id -nG aios` | UID 9001, GID 9001, shell `/usr/sbin/nologin`, NOT in `sudo`/`admin`. |
| Platform tree owner/mode | `stat -c '%U:%G %a' /opt/osgania/platform` (+ `hooks/`) | `root:aios 750`. |
| Hook files owner/mode + executable | `stat -c '%U:%G %a' …/hooks/{guardia,camara}.sh` | `root:aios 750`; execute bit present. |
| jq present | `which jq` | non-empty path, exit 0. |
| Policy installed | `stat -c '%U:%G %a' /etc/claude-code/managed-settings.json`; `jq . <file>` parses | `root:root 644`, valid JSON. |
| Secrets dir locked | `stat -c '%U:%G %a' /etc/osgania/secrets` | `root:root 700`. |
| Audit dir | `stat -c '%U:%G %a' /var/log/osgania` | `root:aios 750`. |
| Audit file owner/mode | `stat -c '%U:%G %a' /var/log/osgania/audit.jsonl` | `root:aios 620`. |
| Audit file append-only armed | `lsattr /var/log/osgania/audit.jsonl` | the `a` flag is present. |
| FS is ext4 | `stat -f -c %T /var/log/osgania` | ext4 family. |
| CLI version recorded + in range | `claude --version` | parses; `>= v2.1.153`; Layer-3 status flagged. |
| `AUDIT_LOG` unset | env check | `AUDIT_LOG` is not set in the provisioned runtime env. |
| Idempotency | run provision.sh twice; assert single `aios`, audit file unchanged (same inode + content), perms identical | no duplicate user, no `+a` corruption, no drift. |

### How it is tested SAFELY (this is harder than pure-function bats)

provision.sh mutates **real root-owned system state** (creates users, `chattr +a`, writes `/etc`, `/opt`, `/var/log`). It cannot be run against a developer's machine. Strategy (layered, in priority order):

1. **Disposable target (primary).** Run provision.sh + `tests/provision.bats` inside a **throwaway Ubuntu 26.04/24.04 VM or container that is privileged enough for `chattr +a`** — i.e. a real ext4-backed VM, or a container with `--cap-add LINUX_IMMUTABLE` on an ext4 volume (NOT the default overlayfs, which makes `chattr +a` a no-op — the ext4 precondition check itself guards this). The CI/dev runs the suite there, never on the host. This is the only environment where the chattr/perm assertions are meaningful.
2. **`--check` / `--dry-run` mode (secondary, host-safe) — normative requirement R1.7.** provision.sh MUST support a `--check` flag (spec R1.7) that runs **only phase 0 (preconditions) + reports the planned changes** it WOULD apply, mutating nothing: no user created, no file written, no `chattr` run, no package installed. This is safe to run anywhere (including the dev host) and lets a human or CI validate the precondition logic and the planned end-state without root mutation. The dry-run path is itself unit-testable with bats (PV-25: assert it prints the plan and exits 0 without touching the FS).
3. **Root-required tests gated behind an env flag (tertiary).** The mutating assertions in `tests/provision.bats` are guarded by an env flag (e.g. `PROVISION_TEST_ALLOW_MUTATION=1` AND `EUID==0`); without it, those scenarios `skip` with a clear message. This prevents an accidental `bats tests/` on a real box from mutating it, while still allowing the disposable-target run to exercise them.

> **Honest note:** the perm/chattr assertions are only **meaningful on a real ext4 root target**. On a dev host (no root, overlayfs) they are skipped. CI MUST run path (1) for the assertions to have value; path (2) is the everyday host-safe check.

Every bash file (provision.sh) gets a **paired shellcheck lint task** (config.yaml `rules.tasks`). `tests/provision.bats` is the canonical `bats tests/` suite member for this slice.

---

## Secret-leak surface review (config rule: flag every place secrets could leak)

Slice 1 writes **NO secret values**. But it creates the secrets directory and arms the audit log, so the leak surfaces must be flagged explicitly:

| # | Surface | Risk in Slice 1 | Mitigation in this design |
|---|---------|-----------------|---------------------------|
| S-1 | `/etc/osgania/secrets/` | A wrong owner/mode would let `aios` read future secrets. | Created `root:root 0700` — **no `aios` read, no traverse**. Consistent with policy `Read(/etc/osgania/secrets/**)` deny + guardia substring deny. Slice 1 seeds NO secret value into it. |
| S-2 | provision.sh stdout/logs | The installer could print a secret it touched. | Slice 1 handles **no secret values** at all (no API key delivery — that is Slice 2 OD-KEY). The final summary prints only paths, owners, modes, the CLI version, and Layer-3 status — never a secret. **provision.sh MUST NOT echo, log, or `set -x`-trace any secret** (it has none to leak, and must keep it that way). |
| S-3 | The audit log being armed | If a secret ever reaches the audit log it becomes append-only and permanent. | Slice 1 writes nothing into `audit.jsonl` (it pre-creates it empty). camara (platform-security-core) already **redacts**: `tool_response` body is never logged, only `exit_code` (R6.3, ADR-004). Cross-reference: the redaction guarantee is camara's; Slice 1 just arms an empty file. provision.sh must NOT write any seed line containing data. |
| S-4 | `AUDIT_LOG` env var | Setting it in the provisioned env would misdirect prod logs (not a secret leak, but a contract violation that could route audit data to an unprotected path). | C-13: provision.sh asserts `AUDIT_LOG` is **UNSET** in the provisioned runtime env; never sets it. |
| S-5 | Version-pin env (`DISABLE_AUTOUPDATER`) | Non-secret, but must not be confused with a secret-bearing env. | It is a plain boolean toggle; no secret value. Documented as non-secret. |

**Conclusion:** Slice 1 introduces **one new secret-relevant artifact** (`/etc/osgania/secrets/`), created root-only with no `aios` access and no seeded value. No secret is committed, echoed, logged, or written to the audit log in this slice.

---

## Sequence diagram (config rule)

The config rule `rules.design` asks for **sequence diagrams for agent-to-app communication flows**. **This slice has NO agent-to-app communication** — `provision.sh` is a one-shot root installer that runs before any agent exists and exchanges no messages with any application. Stating that explicitly to satisfy the rule honestly rather than inventing a flow.

In its place, the **provisioning-flow diagram** (steps + ordering dependencies) is the relevant artifact. The ASCII flow in **Execution model and ordering** above is that diagram; the dependency edges that matter are:

```
preconditions(0) ──must pass──▶ everything
group/user(1)    ──must exist──▶ chown root:aios in (2) and (6)
ext4 check(0)    ──gate──▶ chattr +a (6)
audit pre-create+arm(6) ──before──▶ [Slice 2 launch unit open()]   (existing-FD bypass guard)
policy install(4) ──before──▶ live mode-lock test (7)
```

The only "communication" Slice 1 has is **provision.sh → the OS** (syscalls: useradd, install, chattr, apt, claude install/verify) and **provision.sh → operator** (the non-secret summary on stdout). No app, no agent, no network protocol.

---

## No modification to archived artifacts

This slice ships `scripts/provision.sh` + `tests/provision.bats` and **installs the existing platform-security-core artifacts unchanged**. It does NOT modify:

- `platform/managed-settings.json` (the repo template) — installed verbatim to `/etc/claude-code/`.
- `platform/hooks/guardia.sh`, `platform/hooks/camara.sh` — installed verbatim.
- The archived `platform-security-core` spec/design.

The **only** decision that came close to a boundary crossing is OD-VERPIN's `requiredMinimumVersion`; **ADR-2 explicitly rejects** touching the template and uses an install-pin instead. No boundary is crossed by this slice.

---

## How each non-negotiable principle is satisfied (config.yaml)

| Principle | Satisfied by |
|-----------|--------------|
| Client-facing agent has NO root and is read-only by default | `aios` is a no-sudo nologin system account (ADR-4); platform tree `root:aios 0750` read-only to `aios` (ADR-1); secrets dir `0700` denied (S-1). |
| Operator policy cannot be overridden by the client/agent | managed-settings.json installed `root:root 0644` to `/etc/claude-code/` (only root writes); CLI pinned + mode-lock live-tested (ADR-2) so Layer 3 is real, not no-op. |
| Audit log of every action | Audit file pre-created `0620 root:aios` + `chattr +a` armed in host namespace before any agent open() (step 6) → camara's first append succeeds, closing the silent-drop gap (R5.5). |
| Secrets never in versioned files, repo, or conversation | Secrets dir `root:root 0700`, no `aios` read; Slice 1 ships/echoes/logs NO secret value (S-1..S-5). |
| Verify product facts against official docs; never guess | OS version detected live (not hardcoded); CLI mode-lock validated with a live test, not assumed; v2.1.92 floor treated as LOW confidence and pinned above (ADR-2). |
| Per-client isolation | One VPS per client is a provisioning property; deterministic UID/GID 9001 keeps the fleet's numeric ownership consistent (ADR-4). |
| Brain vs apps separation / MCP least-privilege | Out of scope for Slice 1 (no agent runtime, no MCP); not regressed. |

---

## Rollback plan (config rule: required — installs managed-settings.json and creates the secrets path)

provision.sh mutates live VPS state, so rollback is real. To fully undo a run:

1. `chattr -a /var/log/osgania/audit.jsonl` (root must clear the flag FIRST or removal fails), then optionally remove `/var/log/osgania/`. **Append-only logs are intentionally NOT destroyed on rollback** unless forensic retention is explicitly waived.
2. Remove `/etc/claude-code/managed-settings.json` (operator policy).
3. Remove `/etc/osgania/secrets/` **only if empty/seeded by provisioning** — never delete real secrets blindly.
4. Remove `/opt/osgania/platform/`.
5. `userdel aios` + `groupdel aios` — reverse only if provisioning created them (do not delete a pre-existing `aios`).

**Forward-fix path (preferred):** because provision.sh is idempotent, **re-running it** is the normal repair for a partial/drifted install — no duplicate user, no `+a` corruption, no perms drift. Full rollback is the escape hatch; idempotent re-run is the day-to-day repair.

---

## Forward dependencies recorded (so they are not lost)

| Owner | Dependency |
|-------|------------|
| Slice 2 (vps-provisioning-hardening) | systemd launch unit with `User=aios`, `ReadWritePaths=` for the client workspace + `/var/log/osgania`; MUST set `Environment=DISABLE_AUTOUPDATER=1` (or equivalent drop-in) to durably disable the CLI auto-updater for the `aios` runtime invocation — Slice 1 cannot do this (no launch mechanism, no aios home); MUST NOT set `Environment=AUDIT_LOG=…` (C-13); MUST NOT drop `CAP_LINUX_IMMUTABLE` in a way that breaks chattr; SSH sealing of `aios` via sshd (`passwd -l` is not enough — ADR-4); UFW egress; OD-PATCH unattended-upgrades reconciled with the CLI pin; logrotate-under-chattr. |
| Onboarding generator (future) | Create `/opt/osgania/client/` (the per-client writable tree) with agent-writable ownership; populate client context from intake.yaml (ADR-3 deferred it). |
| platform-security-core (future explicit change) | If a startup hard-gate is wanted, add `requiredMinimumVersion` to managed-settings.json — its own ADR, not this slice (ADR-2). |

---

## Checklist (reviewer can confirm)

- [ ] OD-PLATFS resolved: `/opt/osgania/platform/`, `hooks/`, and `*.sh` all `root:aios 0750`; no policy copy under platform/.
- [ ] OD-VERPIN resolved: install-pin only (>= v2.1.153), auto-update off, version recorded, **live** mode-lock test; archived template NOT modified.
- [ ] OD-CLIENTFS resolved: `/opt/osgania/client/` NOT created in Slice 1 (deferred to onboarding + Slice 2).
- [ ] OD-AIOS resolved: `useradd -r`, nologin, no home, UID/GID 9001 hardcoded, `passwd -l` with the SSH-key caveat stated.
- [ ] Execution order documented with WHY (esp. `chattr +a` in host namespace before any agent open()).
- [ ] Idempotency primitives listed per step + the three hazards addressed.
- [ ] Preconditions/liveness checks listed (OS detect, systemd, ext4, tool presence) with abort reasons.
- [ ] Verification approach: tests/provision.bats assertions + the safe-testing strategy for a root-mutating installer (disposable target / --check / env-gated root tests).
- [ ] Every secret-leak surface flagged (S-1..S-5).
- [ ] Sequence-diagram rule answered honestly (no agent-to-app comms; provisioning-flow diagram provided).
- [ ] No archived artifact modified (OD-VERPIN explicitly avoids the only boundary crossing).
- [ ] Rollback plan present.

## Next step

Run `sdd-spec` to encode the concrete decided values above into `openspec/specs/vps-provisioning-base/spec.md` (Given/When/Then, RFC-2119, explicit isolation boundary per feature), then `sdd-tasks`. The spec MUST copy these literals verbatim (drift gate): `root:aios 0750` (platform tree + hooks + *.sh), `root:root 0644` (policy), `root:root 0700` (secrets), `root:aios 0750` (audit dir), `root:aios 0620` + `chattr +a` (audit file), UID/GID **9001**, shell `/usr/sbin/nologin`, no home, CLI floor **>= v2.1.153** with a live mode-lock test, and **no** `/opt/osgania/client/` creation in this slice.
