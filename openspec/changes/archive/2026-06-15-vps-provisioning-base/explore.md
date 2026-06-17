# Exploration: vps-provisioning

**Change**: vps-provisioning
**Date**: 2026-06-14
**Artifact store**: openspec
**Status**: exploration (investigate & compare only — no proposal, no final decisions)

---

## Why This Slice / Why Now

The archived `platform-security-core` change shipped the "three locks" of the OSGANIA security model as **version-controlled templates and scripts** — `platform/managed-settings.json`, `platform/hooks/guardia.sh`, and `platform/hooks/camara.sh`. It explicitly installed **nothing on a live system**: the design's rollback section states "Nothing is installed on a live VPS by this change" and "Installation of `managed-settings.json` to `/etc/claude-code/` and `chattr +a` on the audit log are **provision.sh's** job (separate change)" (`design.md` Boundaries / Rollback).

So today the three locks are real code but they are **not load-bearing on any VPS**. The runtime contract assumes a set of OS-level preconditions that no script yet creates:

- A non-root `aios` user with no sudo.
- The platform tree installed at the exact absolute path `/opt/osgania/platform/` that the deny rules hardcode.
- managed-settings.json installed at `/etc/claude-code/managed-settings.json` so the runtime even discovers the policy.
- A pre-created, append-only audit log at `/var/log/osgania/audit.jsonl`.
- A pinned, verified Claude Code CLI version so Layer-3 mode-lock is not a silent no-op.
- A real egress gate, because guardia's `curl`/`wget` deny is defense-in-depth, not network containment.

`provision.sh` is the script that turns the three locks from "code in a repo" into "enforced on a fresh Ubuntu VPS." It is the natural next slice: every later capability (autonomy ladder, onboarding generator, MCP wiring) assumes a provisioned, hardened box. Until provision.sh exists, the security baseline is theoretical.

---

## Current State

### What exists (the three locks, as templates only)

| Path | Role | Status |
|------|------|--------|
| `platform/managed-settings.json` | Operator policy: deny rules + `disableBypassPermissionsMode: "disable"` + `allowManagedHooksOnly: true` + hook registration | Template in repo; NOT installed |
| `platform/hooks/guardia.sh` | PreToolUse (Bash) — vetoes `sudo`/`curl`/`wget`/secrets-path | Implemented; `chmod +x` in repo |
| `platform/hooks/camara.sh` | PostToolUse (`*`) — appends one JSON-Lines audit record per tool call | Implemented; `chmod +x` in repo |
| `tests/` | bats behavioral suites for both hooks | Exist (per `config.yaml` canonical `bats tests/`) |
| `openspec/config.yaml` | SDD config; non-negotiable principles | Present |

The three locks map to three layers (`design.md` defense-in-depth diagram):
- **Layer 1** — managed-settings `permissions.deny` rules (Bash matchers + Read/Edit/Write path denies).
- **Layer 2** — `guardia.sh` PreToolUse hook (independent denylist; `permissionDecision: deny` is documented-unbypassable even in `bypassPermissions`).
- **Layer 3** — `permissions.disableBypassPermissionsMode: "disable"` mode-lock + `allowManagedHooksOnly: true`.
- **Audit** — `camara.sh` PostToolUse on `*` writing append-only JSON Lines.

### What platform-security-core explicitly DEFERS to provision.sh

The archived change records these as cross-change provisioning contracts (NOT code defects):

- **Audit pre-creation + append-only**: "the directory mode is `0750` (group `aios` has r-x, NOT write)… `aios` **cannot create** `/var/log/osgania/audit.jsonl`… `provision.sh` MUST pre-create the file… If provision.sh does not do this, camara's first append on a fresh system will fail and fall through to fail-open (R5.4), silently dropping the record. This directly violates R5.5" (`design.md` Q1). Confirmed in `camara.sh` lines 55-62: `if [[ ! -w "$AUDIT_LOG" ]]; then … return 0` — a nonexistent file is not writable, so camara warns to stderr and drops the record.
- **`chattr +a`**: spec **R7.4** — "set on the log file by the provisioning step (provision.sh, separate change)."
- **File-system ownership/modes (R7.2)**: out-of-scope for the bats suite; "set by provision.sh."
- **CLI version pin/verify (KL-3 / R10.3)**: a verify-phase runtime check the provisioning layer must satisfy.
- **OS read-only default**: `design.md` principles table — "OS read-only default is the provisioning layer; this change does not regress it."
- **Installation of managed-settings.json + the platform tree** onto `/etc/claude-code/` and `/opt/osgania/platform/`.

### Inherited dependencies carried forward (non-negotiable)

1. **Audit pre-creation (C-01 + C-02 + C-03)**: provision.sh MUST pre-create `/var/log/osgania/audit.jsonl` (`root:aios`, dir `0750` / file `0620`) AND set `chattr +a` BEFORE the first agent run, or camara fails open and silently drops every audit record — violating the "every tool call produces an audit record" contract (spec R5.5).
2. **KL-3 (C-11)**: pin/verify the Claude Code CLI version per VPS so Layer-3 `disableBypassPermissionsMode` actually works (reported no-op in v2.1.92, `anthropics/claude-code#44642`).

---

## What provision.sh Must Do

Grounded ONLY in the mapped code constraints. Exact paths/modes quoted from the codebase.

### 1. Create the `aios` OS user with NO sudo (C-08)

`config.yaml` non-negotiable: "Client-facing agent has NO root and is read-only by default." Spec R2.1 rationale: "`aios` has no root; any `sudo` invocation indicates privilege escalation." provision.sh MUST ensure `aios` is not in sudoers. **Open**: UID/GID, home dir, shell, system-vs-regular account are unspecified by any file.

### 2. Install the platform tree at EXACTLY `/opt/osgania/platform/` (C-07 + C-14)

The deny rules `Edit(/opt/osgania/platform/**)` and `Write(/opt/osgania/platform/**)` (`managed-settings.json` lines 9-10) are **absolute paths**. Any other install prefix makes the deny rules target a non-existent path and leaves the real files unprotected. The tree must be root-owned and read-only to `aios` (`config.yaml`: "platform/ (operator layer, read-only to agent)").

### 3. Register hooks with ABSOLUTE VPS paths (C-05 + C-06)

managed-settings.json already hardcodes:
- `PreToolUse` / matcher `Bash` → `/opt/osgania/platform/hooks/guardia.sh`, timeout 10 (lines 18-27).
- `PostToolUse` / matcher `*` → `/opt/osgania/platform/hooks/camara.sh`, timeout 10 (lines 29-38).

The runtime CWD is the client workspace, not `platform/`, so relative paths would silently fail. provision.sh must guarantee the binaries live at exactly those paths.

### 4. Make both hooks executable (C-12)

`chmod +x` on `/opt/osgania/platform/hooks/{guardia,camara}.sh` (spec R13.2). Without the execute bit the runtime hook invocation fails silently, collapsing Layer 2 and the audit trail.

### 5. Install managed-settings.json to the managed path (C-04)

Copy `platform/managed-settings.json` → `/etc/claude-code/managed-settings.json` (the official Linux managed path, confirmed in CLI docs: `https://code.claude.com/docs/en/settings`). The repo file is the template only.

### 6. Pre-create the audit log dir + file, then arm append-only (C-01 + C-02 + C-03)

From the audit-log contract (`design.md` Q1 path-and-integrity table; spec R7.2/R7.4) and verified Linux behavior:

- Directory `/var/log/osgania/` — `root:aios`, mode `0750` (owner rwx, group `aios` r-x, **NO group write**). Because group lacks write, `aios` cannot create files here — this is intentional and is precisely why the file must be pre-created. (POSIX: creating a directory entry needs BOTH write+execute on the dir; `https://wpollock.com/AUnix1/FilePermissions.htm`.)
- File `/var/log/osgania/audit.jsonl` — `root:aios`, mode `0620` (owner rw, group `aios` **write-only**, other none). Must exist as an empty file before the agent runs. `aios` can append but cannot truncate/overwrite/delete.
- `chattr +a /var/log/osgania/audit.jsonl` AFTER creation — sets `EXT4_APPEND_FL` (inode flag 0x20); the kernel then only allows `O_APPEND` opens, **even for root** (`https://manpages.debian.org/trixie/e2fsprogs/chattr.1.en.html`). Idempotent: the `+` operator only adds the flag.

Recommended idempotent pattern (verified): `install -d -m 0750 -o root -g aios /var/log/osgania`; `[ -f … ] || install -m 0620 -o root -g aios /dev/null /var/log/osgania/audit.jsonl`; `chattr +a …`; verify with `lsattr`.

### 7. Create the denied secrets directory (C-09)

`/etc/osgania/secrets/**` is denied at policy level (`Read(/etc/osgania/secrets/**)`, `managed-settings.json` line 8) and at hook level (`guardia.sh` line 199: `if [[ "$cmd" == *"/etc/osgania/secrets"* ]]` — substring without trailing slash, to also catch directory references). provision.sh should create this directory root-owned with no read for `aios`, so OS-level and policy-level protections are consistent.

### 8. Leave `AUDIT_LOG` UNSET in production (C-13)

`camara.sh` line 40: `AUDIT_LOG="${AUDIT_LOG:-/var/log/osgania/audit.jsonl}"`. The env var exists solely for bats test isolation (spec R7.1a). If provision.sh or a systemd unit sets it, production logs are misdirected. **This is a direct constraint on any systemd unit provision.sh writes** — do NOT put `Environment=AUDIT_LOG=…` in it.

### 9. Pin AND verify the Claude Code CLI version (C-11)

CLI v2.1.92 had a confirmed report that `disableBypassPermissionsMode` had no effect (`anthropics/claude-code#44642`; spec R10.3, KL-3; `design.md` ADR-006 caveat). provision.sh (and/or the verify phase) MUST document the installed version and flag Layer-3 degradation as a **residual risk** if the version is at or below v2.1.92. Defense-in-depth (Layers 1+2) still holds if Layer 3 is degraded. As of the design date, v2.1.153 is noted as installed and assumed functional.

### 10. Install an egress firewall (C-10)

Spec R2.2 rationale and `guardia.sh` lines 97-99: "real network containment is the egress firewall and the managed-settings deny rules… this case-insensitive match is defense-in-depth only." The three-locks design treats the OS firewall as the **authoritative** network gate. The exact ruleset is unspecified — see the egress fork below.

---

## Ubuntu 26.04 Facts — Confidence and Honesty Note (non-negotiable #7)

> **HONESTY GATE.** Some research streams disagree about whether Ubuntu 26.04 is even released. This MUST be treated as an open decision, not a settled fact.

- The **Ubuntu/provisioning research stream** reports, with **high confidence and citations**, that **Ubuntu 26.04 LTS "Resolute Raccoon" is GA as of 2026-04-23**, kernel 7.0, systemd `259.5-0ubuntu3`, sudo-rs default, OpenSSH 10.2p1 (no DSA), rust-coreutils default, cgroup v1 removed, last release with SysV-init compat (`https://documentation.ubuntu.com/release-notes/26.04/`, `https://canonical.com/blog/canonical-releases-ubuntu-26-04-lts-resolute-raccoon`, `https://packages.ubuntu.com/resolute/systemd`).
- **BUT the firewall and append-only-FS research streams explicitly state the opposite caveat**: "Ubuntu 26.04 (Noble successor) was **not released as of the knowledge cutoff (August 2025)**. These commands are verified against Ubuntu 24.04 LTS (Noble Numbat)." These two streams flag **low/medium confidence** on 26.04-specifics.

**Resolution for this exploration**: the Ubuntu version is an **OPEN DECISION (OD-VER)**, NOT a settled fact. The high-confidence 26.04 claims come with their own re-verification asks (systemd point version, useradd/adduser 26.04 manpage, passwd-l under sudo-rs). The 24.04 LTS fallback is itself high-confidence (`https://ubuntu.com/about/release-cycle`). provision.sh must:
1. Detect the live OS version at runtime (`lsb_release` / `/etc/os-release`) rather than hardcoding assumptions.
2. Re-verify version-sensitive facts on the live box: `apt-cache policy systemd`, `systemctl --version`, `man useradd`, `uname -r`, `stat -f /var/log/osgania` (filesystem type must be ext4 for `chattr +a`), `dpkg -l e2fsprogs`.

Facts that are **OS-version-stable** (verified against kernel/VFS/POSIX, unchanged across LTS) and can be relied on regardless of the version decision:
- `chattr +a` inode-flag semantics, existing-FD bypass, root-can-still-clear behavior.
- POSIX directory permission semantics (0750 denies group create).
- systemd hardening directive semantics (the directives are stable; only minimum-version availability matters — `LoadCredential=` ≥247, `LoadCredentialEncrypted=` ≥250, `ProtectProc=` ≥247, `ProcSubset=`/`ProtectProc=invisible` need kernel ≥5.8).
- UFW command syntax and stateful conntrack behavior ("stable across Ubuntu LTS releases").

---

## Approaches & Forks Compared

### Fork A — Egress containment: domain vs IP (the hard one)

UFW/iptables operate at L3/L4 (IP+port); they **cannot match domain names** (`https://dev.to/danyson/firewall-egress-filtering-with-ufw-2038`). `api.anthropic.com` sits behind Cloudflare's CDN with continuously rotating IPs. The agent MUST reach the Anthropic API, so `PrivateNetwork=yes` / full block is not viable. This produces a genuine four-way fork:

| Option | Mechanism | Pros | Cons / honest tradeoff |
|--------|-----------|------|------------------------|
| **A. Allow-all 443** | `ufw default deny outgoing` + `ufw allow out 443/tcp` (plus 53/udp+tcp, 123/udp, 80/tcp for apt) | Simplest; robust; no CDN-IP churn problem; works today | Permits egress to **any** HTTPS host → no exfiltration protection by destination. Stops accidental non-HTTPS egress only. |
| **B. ipset + cron DNS pin** | resolve allowlisted FQDNs periodically into an ipset matched by iptables | Network-layer enforcement by IP | **Brittle for CDN APIs**: Cloudflare anycast IPs rotate within minutes; race window between TTL expiry and cron refresh; bypassable via hardcoded IPs. Allowing *all* Cloudflare CIDRs ≈ Option A anyway. **Not recommended as sole control.** |
| **C. Squid forward proxy (domain ACL)** | All egress via local Squid; ACL allowlist by CONNECT/SNI hostname; UFW denies direct 443, allows only Squid listener; agent uses `HTTP_PROXY` | **Only approach that reliably enforces FQDN egress** without IP pinning | Operational complexity; Squid sees SNI but doesn't decrypt (full SSL-bump needs a private CA on every client — significant). Must verify the Anthropic SDK honors `HTTPS_PROXY` incl. streaming. |
| **D. dnsmasq allowlist** | resolve only allowlisted FQDNs; combine with ipset population | Catches accidental/misconfigured egress | **Incomplete alone**: bypassable by hardcoded IPs and DoH. Defense-in-depth layer only, never standalone. |

**Honest read (from the research stream's own recommendation)**: for a VPS agent calling `api.anthropic.com` + MCP endpoints on a CDN, the pragmatic baseline is **Option A** (default-deny egress + allow 443 broadly + essential ports), optionally layered with **D** for accidental-egress hygiene. Adopt **C (Squid)** only if strict domain-level egress enforcement is a hard requirement — it is the only architecture that actually delivers it, at real operational cost. **B is explicitly not recommended** for CDN-backed APIs. This is a real product/threat-model fork, not a technical detail — it belongs in the proposal.

**Docker/Coolify wrinkle (medium confidence on egress)**: Docker rewrites iptables; published container **inbound** ports bypass UFW (PREROUTING/FORWARD) and need `ufw-docker` (`https://github.com/chaifeng/ufw-docker`). The egress streams say host+container **egress** still goes through OUTPUT/FORWARD and is governed by default-deny — but this is rated **medium confidence**. If Coolify or any Docker workload runs on the same box, `ufw default deny forward` + explicit `ufw route allow` (or DOCKER-USER rules) is required for container egress, and this interaction must be verified live.

### Fork B — systemd hardening level for the agent process

How is the agent launched, and how locked-down should the unit be? (`open_questions`: "No file specifies how the Claude Code CLI agent process is launched.")

| Option | Posture | Pros | Cons |
|--------|---------|------|------|
| **B1. Login shell / no unit** | agent runs in an interactive/login session as `aios` | matches CLI's terminal-session design; apiKeyHelper + env-var auth apply (terminal CLI only) | no resource ceilings, no sandbox, no auto-restart, no kernel/namespace hardening; OS hardening relies entirely on user perms + firewall |
| **B2. Minimal systemd unit** | `User=aios`, `Restart=on-failure`, basic `ProtectSystem`, `NoNewPrivileges` | supervision + restart + light sandbox; small blast radius for misconfig | leaves most hardening directives on the table |
| **B3. Maximal systemd hardening** | full set: `ProtectSystem=strict` + `ReadWritePaths=`, `CapabilityBoundingSet=`, `SystemCallFilter=@system-service` + denies, `RestrictAddressFamilies=`, `ProtectKernel*`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, resource ceilings | strongest OS containment; `systemd-analyze security` target <5.0 | high risk of breaking the agent: it spawns subprocesses (git, shells, compilers); **JIT runtimes break under `MemoryDenyWriteExecute=yes`** (Node/V8 needs W+X — the CLI is likely Node-based); syscall filter may need `@process`/clone/execve; may need `AF_NETLINK` for DNS; must profile with `strace`/`systemd-analyze` first |

**Critical interactions to flag now, not at apply time:**
- **`ProtectSystem=strict` makes the whole FS read-only except /dev,/proc,/sys.** The agent's writable paths (client workspace, and `/var/log/osgania` for camara) MUST be in `ReadWritePaths=` or it fails `EROFS` on first write. (`https://linux-audit.com/systemd/settings/units/readwritepaths/`)
- **The audit log + systemd interact dangerously with `chattr +a` capabilities.** If the unit drops `CAP_LINUX_IMMUTABLE` from root-prefixed setup, even root inside that context cannot set/clear `+a`. provision.sh must run the `chattr +a` step in the **host namespace**, not inside a capability-stripped unit (`https://www.man7.org/linux/man-pages/man7/capabilities.7.html`).
- **`AUDIT_LOG` must NOT be set in the unit** (C-13). This is the single most important systemd constraint we already know.
- **Existing-FD bypass**: `chattr +a` only checks at `open()`. The flag MUST be armed BEFORE the agent process opens the log — i.e., provision.sh arms it before the unit ever starts.

**Honest read**: B3 is the right *direction* for a single-purpose hardened box (26.04's systemd 259 supports all directives), but it MUST be introduced incrementally with live profiling, because the agent is a subprocess-spawning, likely-JIT runtime. A reasonable proposal stance: ship B2 first with a clear path to B3, gated on `systemd-analyze security` + a runtime smoke test.

### Fork C — API key delivery (if a systemd unit is chosen)

If the agent runs under systemd, how does the Anthropic key reach it without leaking?

| Option | Leak surface | Note |
|--------|--------------|------|
| `Environment=KEY=…` | **worst** — visible in `systemctl show`, world-readable unit, `/proc/PID/environ` | NEVER for secrets |
| `EnvironmentFile=` (0600 root:root) | secret in `/proc/PID/environ`, inherited by children | acceptable fallback if the app *requires* env vars |
| `LoadCredential=` (systemd ≥247) | not in `/proc/environ`, non-swappable, not inherited | **preferred**; agent reads `$CREDENTIALS_DIRECTORY/<id>` |
| `LoadCredentialEncrypted=` (≥250, TPM-bound) | encrypted at rest | strongest for keys at rest; 26.04 has TPM-FDE GA |
| `apiKeyHelper` (CLI-native) | helper invoked by `/bin/sh`, prints key to stdout; root:root 0700 wrapper calling a secrets manager | CLI-native path; **note**: ignored if `ANTHROPIC_API_KEY`/`AUTH_TOKEN` env vars are set (precedence #3/#4) — scrub those from the agent env |

This fork is **downstream of Fork B** (only matters if a unit is chosen) and is partly out of scope (secrets management is its own domain per `config.yaml`), but it must be named because `apiKeyHelper` is referenced in `config.yaml` ("one API key per client workspace") yet absent from managed-settings.json — an open question for provisioning.

### Fork D — CLI version enforcement: soft pin vs hard gate

KL-3 demands the version be pinned/verified. Two enforcement strengths (CLI docs `https://code.claude.com/docs/en/settings`, `https://code.claude.com/docs/en/setup`):

| Option | Mechanism | Strength |
|--------|-----------|----------|
| **Install-pin only** | `install.sh \| bash -s <version>` or `apt-get install claude-code=<v>`; `DISABLE_UPDATES` env to freeze | prevents drift but no startup gate |
| **Managed hard gate** | `requiredMinimumVersion` (+`requiredMaximumVersion`) in managed-settings.json → CLI **exits at startup** if out of range; `DISABLE_UPDATES`; verify `claude --version` + GPG-verify the release manifest (fingerprint `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE`) | hard enforcement; the real KL-3 satisfier |

**Honesty caveat (low confidence)**: the *exact* version where `disableBypassPermissionsMode` became reliable is **NOT confirmed in official changelogs**. The v2.1.92 no-op is from the GitHub issue, not the docs (the docs only confirm a v2.1.126 protected-path behavior change). So the *value* of the pin (which minimum version to require) is itself an open question — recommendation from the research: pin well above v2.1.126 and validate mode-lock with a live test before deploying. Adding `requiredMinimumVersion` to managed-settings.json is a **change to the platform-security-core template**, which crosses the change boundary — flag it.

### Fork E — Auto-patching posture

`unattended-upgrades` is pre-installed on Ubuntu. For a hardened single-purpose box the research recommends **security-pocket-only** via a drop-in (never edit `50unattended-upgrades` directly), e.g. allow only `${distro_id}:${distro_codename}-security` and comment out `-updates` (`https://documentation.ubuntu.com/security/security-updates/`). Tradeoff: security-only minimizes churn/regression risk but leaves non-security bugs unpatched; full updates patch more but raise the chance an update restarts the agent or shifts behavior. Lower-stakes than A/B but it is a real posture decision and interacts with the version-pin (an unattended upgrade of the CLI would violate the pin — hence `DISABLE_UPDATES` for the CLI specifically while still patching the OS).

---

## Open Decisions

These are NOT decided here (exploration only). They feed the proposal/design.

- **OD-VER — Ubuntu version**: 26.04 LTS (high-confidence-GA per one stream, but flagged unreleased/low-confidence by two others) vs 24.04 LTS fallback. Resolve by OS detection + live re-verification, not hardcoding.
- **OD-EGRESS — egress model**: A (allow-all 443) vs C (Squid domain ACL), with D as an optional defense-in-depth layer; B rejected for CDN APIs. Threat-model dependent.
- **OD-SYSTEMD — launch + hardening level**: login-shell vs minimal unit vs maximal-hardened unit; and the exact `ReadWritePaths` set. Depends on how the CLI is actually run and whether it is JIT/Node.
- **OD-KEY — API key delivery**: `LoadCredential`/`LoadCredentialEncrypted` vs `EnvironmentFile` vs `apiKeyHelper` wrapper. Downstream of OD-SYSTEMD; partly a secrets-management concern.
- **OD-VERPIN — version enforcement**: install-pin only vs managed `requiredMinimumVersion` hard gate (the latter edits the platform-security-core template). Plus the open question of *which* minimum version (low-confidence on the exact safe floor).
- **OD-AIOS — aios account shape**: UID/GID, system-vs-regular, home dir, shell (`nologin`?), SSH posture (note: `passwd -l` does NOT block SSH key login — needs `AllowUsers`/`DenyUsers` too).
- **OD-CLIENTFS — `/opt/osgania/client/` permissions**: what `aios` may write in the per-client tree (design deferred this entirely).
- **OD-PLATFS — `/opt/osgania/platform/` ownership/mode**: `root:root` vs `root:aios`, `0755` vs `0750`.
- **OD-JQ — jq as a system package**: both hooks require `jq` at runtime; if absent the hooks fail. provision.sh likely must install it (host `jq` is present in dev per `config.yaml`, but the VPS is fresh).
- **OD-LOGROTATE — audit rotation**: rotation must use prerotate `chattr -a` / postrotate `chattr +a` + recreate (copytruncate and rename are blocked by `+a`); accept the unprotected rotation window, or use an alternate sink (remote syslog) for true tamper-evidence.
- **OD-DOCKER — Coolify/Docker coexistence**: is Docker/Coolify even on these boxes? If so, egress-via-FORWARD and `ufw-docker` for inbound must be handled (egress-not-bypassed claim is medium confidence — verify).
- **OD-PATCH — auto-upgrade posture**: security-only drop-in vs full unattended-upgrades; reconcile with CLI `DISABLE_UPDATES`.

---

## Risks

| Risk | Severity | Note / mitigation |
|------|----------|-------------------|
| Audit file not pre-created (or wrong mode/owner) → camara fails open silently | **Critical** | Direct R5.5 violation. `install -d 0750 root:aios` + pre-create file `0620` + `chattr +a` BEFORE first run. Add a provisioning test (`lsattr`, `stat`). |
| `chattr +a` armed AFTER the agent opened the FD | **High** | Existing-FD bypass: kernel checks only at `open()`. Arm `+a` before the unit/agent starts. |
| systemd unit drops `CAP_LINUX_IMMUTABLE`, breaking `chattr` | High | Run the chattr step in host namespace, not inside a stripped unit. Verify `systemctl show … cap`. |
| `AUDIT_LOG` accidentally set in the unit/env | High | C-13: leave unset; production logs would be misdirected. Lint the unit for it. |
| Platform tree installed at a prefix ≠ `/opt/osgania/platform/` | High | Deny rules + hook commands hardcode the absolute path; mismatch silently unprotects files / breaks hooks. |
| Layer-3 mode-lock degraded (CLI ≤ v2.1.92 bug) | High | Pin + verify version; flag residual risk if degraded; Layers 1+2 still hold. **Exact safe floor is low-confidence** — validate with a live mode-lock test. |
| Egress model too weak (allow-all 443) for the actual threat model | High (model-dependent) | If exfiltration-by-destination matters, A is insufficient → Squid (C). Decide at proposal. |
| `chattr +a` no-op on tmpfs/overlayfs `/var/log` | Medium | Verify `stat -f /var/log/osgania` shows ext4 on the live box. |
| `MemoryDenyWriteExecute=yes` crashes the (likely Node/JIT) agent | Medium | Profile before enabling; may need to drop this directive in B3. |
| `ufw enable` before allowing SSH 22 → lockout | Medium | Always `ufw allow in 22/tcp` before enable; ordering bug is unrecoverable without console. |
| `jq` absent on fresh VPS → hooks fail silently | Medium | Install jq as a system package; verify in provisioning test. |
| Docker/Coolify bypasses UFW (inbound) / FORWARD egress assumptions wrong | Medium (egress claim is medium-confidence) | `ufw-docker` for inbound; verify container egress path live if Docker present. |
| 26.04-specific facts (systemd point version, useradd/adduser, passwd-l under sudo-rs) unconfirmed | Medium | Re-verify on the live box; do not hardcode. |
| Logrotate unprotected window (chattr -a → +a) | Low/Medium | Add postrotate `lsattr` safety check/alert; accept window or use remote sink. |
| `passwd -l` does not block SSH key login | Low | If `aios` must never be SSH-accessible, add `DenyUsers`/`AllowUsers` in sshd_config. |
| SysV-init compat removed in 26.10; cgroup v1 gone in 26.04 | Low | Write native systemd units now; audit any cgroup-v1 container deps before 26.04. |

---

## Recommended First Slice / Direction

**Direction**: split provision.sh into an inner *security-baseline core* (the parts that make the already-shipped three locks load-bearing, with zero unresolved forks) and a deferred *network/process-hardening* layer (the parts that hinge on real forks: egress model and systemd level).

**Recommended first slice — "make the three locks real" (no fork resolution required):**
1. Create the `aios` user with no sudo (C-08) — using OS detection; document the account shape decision (OD-AIOS) but default to a locked `nologin` service account.
2. Install the platform tree to exactly `/opt/osgania/platform/` (C-07, C-14), root-owned read-only-to-`aios`; `chmod +x` both hooks (C-12); install `jq` (OD-JQ).
3. Install `platform/managed-settings.json` → `/etc/claude-code/managed-settings.json` (C-04).
4. Create `/etc/osgania/secrets/` root-owned, no `aios` read (C-09).
5. **Pre-create the audit dir+file and arm `chattr +a`** (C-01/C-02/C-03), idempotently, in the host namespace, BEFORE any agent run — the single highest-value, highest-risk step. Add a provisioning test (`stat`, `lsattr`) since the bats suite explicitly excludes these (`design.md`: "Do NOT add bats scenarios that verify chattr").
6. Pin + verify the CLI version and record it (C-11); flag Layer-3 residual risk if degraded.
7. Guarantee `AUDIT_LOG` stays unset in whatever launch mechanism is chosen (C-13).

This slice is fully grounded in resolved constraints, makes the security baseline actually enforced, and is independently testable. **Deliberately deferred to a follow-on slice (because they require deciding OD-EGRESS and OD-SYSTEMD):** the egress firewall ruleset, the systemd hardening unit + API-key delivery, the auto-patch posture, logrotate, and any Docker/Coolify coexistence. Those carry genuine product/threat-model tradeoffs and should not be smuggled into the baseline before the proposal resolves the forks.

The egress decision (Fork A) and the systemd hardening level (Fork B) are the two questions the proposal MUST answer first, because they dominate the design of the second slice.

