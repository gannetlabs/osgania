# Spec: vps-provisioning-hardening-2a ("Run the agent")

**Change**: `vps-provisioning-hardening-2a` (Slice 2, sub-slice 2a)
**Project**: osgania
**Artifact store**: openspec
**Established**: 2026-06-15
**Status**: spec
**Depends on**: `vps-provisioning-base` (canonical, Slice 1), `platform-security-core` (canonical, L0 baseline)
**Implements**: proposal.md, design.md (ADR-1 SUPERSEDED; ADR-2/ADR-4 unchanged; ADR-3/ADR-5 amended; ADR-6/ADR-7 new — all literals copied verbatim, drift gate)

> 2a extends a Slice-1-provisioned box with a Node/CLI runtime, a hardened systemd launch unit, `ANTHROPIC_API_KEY` delivery via a systemd `LoadCredential` wrapper, and a live defense-in-depth probe. It does NOT alter any Slice-1 / `platform-security-core` deny rule, hook, `disableBypassPermissionsMode`, `chattr +a` arming, or `CAP_LINUX_IMMUTABLE`.

> **PIVOT (2026-06-16) — normative.** `apiKeyHelper` (original HA-05) is ABANDONED: Claude Code CLI 2.1.153 cannot spawn it as the non-root `aios` user (design ADR-1 superseded by ADR-6; engram `architecture/apikeyhelper-aios-auth-blocker`). Post-pivot: (a) the key is delivered as `ANTHROPIC_API_KEY` by a root-owned `ExecStart` wrapper `/opt/osgania/platform/bin/agent-run.sh` (HA-08); (b) 2a does NOT modify `managed-settings.json` — it only verifies R9–R12 are intact (HA-05); (c) `UnsetEnvironment` scrubs only `ANTHROPIC_AUTH_TOKEN` (HA-06); (d) the live probe verifies guardia denies under bypass, not flag-refusal (HA-09); (e) a NEW requirement HA-15 adds a guardia env-dump denial (speed-bump mitigation, design ADR-7). HA-08-S4 (helper read) is OBSOLETE and replaced by a wrapper scenario.

---

## Scope summary

`provision-agent.sh` is a root-run idempotent installer that runs AFTER `provision.sh` on a Slice-1-provisioned Ubuntu 24.04/26.04 box. It establishes:

1. Node.js >= 18 runtime, `apt-mark hold nodejs npm`
2. Claude Code CLI pinned at `@anthropic-ai/claude-code@2.1.153`
3. Client workspace `/opt/osgania/client/` (`aios:aios 0700`)
4. Launch wrapper at `/opt/osgania/platform/bin/agent-run.sh` (`root:root 0755`) — exports `ANTHROPIC_API_KEY` from `$CREDENTIALS_DIRECTORY`, then `exec`s the pinned CLI
5. Read-only structural verification that `/etc/claude-code/managed-settings.json` is UNCHANGED (R9–R12 intact) — 2a does NOT write to it (post-pivot)
6. Two systemd unit files (`osgania-agent.service` + `osgania-agent.timer`) with the full B2+ directive set (`ExecStart`=wrapper)
7. Live defense-in-depth probe (guardia denies a forbidden command under `--dangerously-skip-permissions`) classified VERIFIED / UNVERIFIED / FAILED
8. guardia env-dump denial category (HA-15) — denies the obvious env-dump verbs/paths while allowing benign forms

### Out of scope — explicitly deferred to 2b

- UFW egress firewall (default-deny-egress + allow rules)
- SSH sealing of `aios` (`DenyUsers` drop-in)
- unattended-upgrades drop-in (security-pocket-only + Node hold reconciliation)
- logrotate under `chattr +a`
- Docker/Coolify coexistence (`ufw-docker`)
- Tightening systemd hardening to B3
- TPM-encrypted key at rest (`LoadCredentialEncrypted` — D5 v2 future milestone)

---

## Cross-reference to inherited contracts

This spec BUILDS ON and does NOT modify the following canonical contracts:

| Contract | What 2a depends on | 2a extension |
|----------|-------------------|--------------|
| `platform-security-core` R9–R12 | Six `permissions.deny[]` entries, `permissions.allow == []`, `permissions.defaultMode == "default"`, `permissions.disableBypassPermissionsMode == "disable"`, `allowManagedHooksOnly == true`, guardia PreToolUse/Bash/timeout 10, camara PostToolUse/*/timeout 10 | **Post-pivot: adds NOTHING.** 2a does NOT modify `managed-settings.json`; it only VERIFIES all R9–R12 keys are intact (read-only structural assert). |
| `platform-security-core` R1–R4 (guardia) | guardia.sh hook interface (R1), denylist categories R2.1–R2.6, reason structure (R3), non-functional (R4) | Adds ONE new denylist category (env-dump, HA-15) extending R2 in `guardia.sh` (live artifact). MUST NOT alter R2.1–R2.6, R1, R3, or R4. |
| `platform-security-core` R5.5 | Every tool call produces an audit record (camara.sh append) | The launch unit MUST keep `ReadWritePaths` containing `/var/log/osgania` so camara can append under `ProtectSystem=strict`. |
| `vps-provisioning-base` R5.1 | `/etc/osgania/secrets/` is `root:root 0700` | 2a wires this path via `LoadCredential`; never reads or writes the key value in the script. |
| `vps-provisioning-base` R7.1/R7.5 | `chattr +a` armed on `/var/log/osgania/audit.jsonl` in host namespace | 2a MUST NOT clear `chattr +a`; `lsattr` MUST still show `a` after a run. |
| `vps-provisioning-base` R9.1 | CLI install is Slice 2 forward dependency | 2a is that dependency's fulfillment. |
| `vps-provisioning-base` R9.2a | `DISABLE_AUTOUPDATER=1` runtime persistence is Slice 2 forward dependency | Discharged here by `Environment=DISABLE_AUTOUPDATER=1` in the systemd unit. |
| `vps-provisioning-base` R10.1 | `AUDIT_LOG` MUST NOT be set in any provisioned unit or env file | 2a unit MUST NOT contain `AUDIT_LOG=`. |

**Archived spec text of `platform-security-core` is NOT rewritten.** This spec carries the normative cross-references — post-pivot 2a "does NOT modify `managed-settings.json`; MUST NOT alter any R9–R12 key" (verified by HA-05-S2/S3), and "extends `guardia.sh` with ONE env-dump denylist category (HA-15); MUST NOT alter R2.1–R2.6" (verified by HA-15 scenarios + guardia regression).

---

## Decided literals encoded verbatim (drift gate)

All values below are sourced from design.md. If any value here differs from design.md, design.md wins — correct this spec, not the design.

| Item | Spec value | design.md source |
|------|-----------|-----------------|
| CLI npm package | `@anthropic-ai/claude-code@2.1.153` (exact pin) | ADR-2 |
| CLI version floor | `>= 2.1.153` | ADR-2 |
| Node version floor | `>= 18` | ADR-1 execution step 1 |
| Client workspace path | `/opt/osgania/client/` | ADR-3/ADR-4 |
| Client workspace mode | `aios:aios 0700` | ADR-3/ADR-4 |
| Launch wrapper path (installed) | `/opt/osgania/platform/bin/agent-run.sh` | ADR-6 |
| Launch wrapper mode | `root:root 0755` | ADR-6 |
| Launch wrapper body (key export) | `export ANTHROPIC_API_KEY` then `ANTHROPIC_API_KEY="$(cat "${CREDENTIALS_DIRECTORY}/anthropic-api-key")"` then `exec /usr/bin/claude "$@"` | ADR-6 |
| managed-settings.json modification by 2a | **NONE** (post-pivot) — read-only structural verify; no `apiKeyHelper` key, no write | ADR-1 SUPERSEDED / ADR-6 |
| LoadCredential unit directive | `LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key` | ADR-3 |
| UnsetEnvironment directive | `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` (only — `ANTHROPIC_API_KEY` is intentionally SET by the wrapper, MUST NOT be unset) | ADR-3 amended |
| systemd unit type | `Type=oneshot` | ADR-3 |
| systemd unit user | `User=aios` | ADR-3 |
| systemd unit group | `Group=aios` | ADR-3 |
| WorkingDirectory | `/opt/osgania/client` | ADR-3 |
| StateDirectory | `osgania-agent` → `/var/lib/osgania-agent` | ADR-4 |
| StateDirectoryMode | `0700` | ADR-3 |
| HOME env (unit) | `Environment=HOME=%S/osgania-agent` | ADR-4 |
| XDG_CONFIG_HOME env (unit) | `Environment=XDG_CONFIG_HOME=%S/osgania-agent` | ADR-4 |
| XDG_CACHE_HOME env (unit) | `Environment=XDG_CACHE_HOME=%S/osgania-agent` | ADR-4 |
| XDG_DATA_HOME env (unit) | `Environment=XDG_DATA_HOME=%S/osgania-agent` | ADR-4 |
| XDG_STATE_HOME env (unit) | `Environment=XDG_STATE_HOME=%S/osgania-agent` | ADR-4 / SC-5 |
| DISABLE_AUTOUPDATER (unit) | `Environment=DISABLE_AUTOUPDATER=1` | ADR-3 |
| ExecStart | `/opt/osgania/platform/bin/agent-run.sh -p` (the wrapper; only arg is `-p`; no `--bare`) | ADR-3 amended / ADR-6 |
| `--bare` in ExecStart OR wrapper `exec` | FORBIDDEN on both — causes invariant abort | ADR-3 amended |
| `MemoryDenyWriteExecute` | EXCLUDED (Node V8 JIT incompatible) | ADR-3 |
| `AUDIT_LOG=` in unit | FORBIDDEN | base R10.1 |
| `Environment=ANTHROPIC_API_KEY` in unit | FORBIDDEN — the literal key value must never appear in the world-readable unit file / `systemctl show` / journal; the wrapper sets it at runtime from tmpfs | ADR-3 amended / ADR-6 |
| ProtectSystem | `ProtectSystem=strict` | ADR-3 |
| ReadWritePaths | `ReadWritePaths=/opt/osgania/client /var/log/osgania` | ADR-3 |
| NoNewPrivileges | `NoNewPrivileges=yes` | ADR-3 |
| PrivateTmp | `PrivateTmp=yes` | ADR-3 |
| ProtectHome | `ProtectHome=yes` | ADR-3 |
| ProtectKernelTunables | `ProtectKernelTunables=yes` | ADR-3 |
| ProtectKernelModules | `ProtectKernelModules=yes` | ADR-3 |
| ProtectControlGroups | `ProtectControlGroups=yes` | ADR-3 |
| RestrictAddressFamilies | `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | ADR-3 |
| CapabilityBoundingSet | `CapabilityBoundingSet=` (empty — all caps dropped) | ADR-3 |
| RestrictNamespaces | `RestrictNamespaces=yes` | ADR-3 |
| RestrictSUIDSGID | `RestrictSUIDSGID=yes` | ADR-3 |
| LockPersonality | `LockPersonality=yes` | ADR-3 |
| LimitCORE | `LimitCORE=0` (no core dumps — a core would contain `ANTHROPIC_API_KEY`) | ADR-3 / TMH-5 |
| SystemCallFilter | `SystemCallFilter=~@reboot @swap @mount @clock @debug @module @raw-io @obsolete` (deny-form) | ADR-3 |
| Timer cadence (placeholder) | `OnCalendar=daily` `RandomizedDelaySec=3600` `Persistent=true` | ADR-3 |
| Timer cadence ownership | DEFERRED — autonomy-ladder change owns the real schedule | ADR-3 |
| Defense-in-depth probe (permissionMode) | run, as `aios` under the production runtime env, `wrapper -p --output-format stream-json --verbose --dangerously-skip-permissions '<benign prompt>'`; parse `permissionMode` from the stream-json `init` event | ADR-5 re-amended (Phase-4) |
| Probe VERIFIED condition | `permissionMode` = `default` (or any non-`bypassPermissions` mode) despite the flag → managed `disableBypassPermissionsMode` neutralized bypass; no Bash tool runs without approval | ADR-5 |
| Probe UNVERIFIED condition | no `init` event (empty/unparseable output — key/CLI/wrapper absent or auth error) — NEVER reported VERIFIED | ADR-5 |
| Probe FAILED condition | `permissionMode` = `bypassPermissions` → CLI honored the flag; managed disable NOT in effect, Layer-3 outer wall broken | ADR-5 |
| Probe safety / guardia coverage | benign prompt, no tool action, no secret printed (oracle is CLI-reported `permissionMode`). guardia's denylist (inner layer) is proven by host-safe `guardia.bats` (R2.x + HA-15) | ADR-5 |
| Precondition: Slice-1 check | `aios` uid/gid 9001, `/etc/claude-code/managed-settings.json` valid, audit `+a` armed | design execution step 0 |
| guardia env-dump: deny verbs | `printenv` (any); `env` as a dump (alone / options-only `-i`/`-0`/`-u VAR` with no command / piped); bare `set` (no flag arg); bare `declare`/`typeset` (no arg); `declare -p` / `typeset -p` / `local -p`; `export -p`; `compgen -v` / `compgen -e` / `compgen -A variable` / `compgen -A export` | ADR-7 |
| guardia env-dump: deny path | reads of the proc-environ path — ERE `/proc/(self\|[0-9]+\|\$\$\|\$BASHPID\|\$\{[^}]*\})/environ` (self / numeric / `$$` / `$BASHPID` / `${...}`), tool-agnostic | ADR-7 |
| guardia env-dump: MUST allow (no false-positive) | `set -e`/`set -u`/`set -x`/`set +e`/`set -o pipefail`; `declare -i`/`declare -a`/`declare x=1`; `export FOO=bar`; `env FOO=bar cmd`; `env -u FOO cmd`; `env -i cmd` | ADR-7 |
| guardia env-dump: step position | step 7.5 — AFTER R2.5 (secrets) + R2.6 (platform), immediately BEFORE the default defer; first-match-wins so inherited categories keep their reason | ADR-7 / ICP-01 |
| guardia env-dump: reason prefix | `[guardia] denied: env-dump — …` | ADR-7 / PSC R3.1 |
| guardia env-dump: scope | speed-bump; does NOT (and must not) block interpreters or bash-native indirection reading the env (`python`/`node`/`awk ENVIRON`/`echo $VAR`/`${!name}`/`p=…;cat $p`) | ADR-7 |
| guardia bash-native egress deny | deny `/dev/tcp` and `/dev/udp` substrings (bash network pseudo-device — a curl/wget-free exfil channel); cheap defense-in-depth | ADR-7 / TMH-2 |

---

## Requirements

### HA-01 — Preconditions gate

**HA-01.1** `provision-agent.sh` MUST verify the following Slice-1 end-state before any mutation:
- `getent passwd aios` returns an entry with UID 9001 and GID 9001
- `/etc/claude-code/managed-settings.json` exists and is valid JSON (`jq . …` exits 0)
- `lsattr /var/log/osgania/audit.jsonl` contains the `a` flag

**HA-01.2** If any precondition fails, `provision-agent.sh` MUST abort with exit code > 0 and a message naming the failed gate. No filesystem or package mutation MUST occur before all preconditions pass.

**HA-01.3** `provision-agent.sh` MUST verify `systemd` is present (`systemctl --version` exits 0) before proceeding.

**HA-01.4** `provision-agent.sh` MUST support a `--check` (dry-run) flag. When invoked with `--check`, it MUST run ONLY precondition checks and report the planned changes WITHOUT mutating any state.

**Isolation boundary (HA-01):** Precondition checks run before any mutation. Root-level installer; no principal proceeds past these gates when any condition is unmet.

---

### HA-02 — Node.js runtime and package hold

**HA-02.1** Node.js MUST be present with version >= 18 after `provision-agent.sh` completes. If the distro-packaged Node version is >= 18 (Ubuntu 24.04 ships 18.19.1), the distro package MUST be used. If it is below 18, NodeSource 20.x LTS MUST be added and installed.

**HA-02.2** `npm` MUST be present after provisioning.

**HA-02.3** `provision-agent.sh` MUST run `apt-mark hold nodejs npm` to prevent OS package upgrades from silently moving the runtime. The hold MUST be applied as an add-only operation (re-running is a no-op).

**HA-02.4** The Node install step MUST be idempotent: if Node >= 18 is already installed, the apt step MUST be skipped.

**Isolation boundary (HA-02):** The runtime hold is a system-level control enforced by apt. `aios` cannot modify package holds. The hold protects the runtime under the pinned CLI.

---

### HA-03 — Claude Code CLI pin

**HA-03.1** The Claude Code CLI MUST be installed at the exact version `@anthropic-ai/claude-code@2.1.153` (not floating, not "latest"). The npm install command MUST be `npm install -g @anthropic-ai/claude-code@2.1.153`.

**HA-03.2** `provision-agent.sh` MUST verify the installed version by running `claude --version`, parsing the output, and asserting the reported version is >= `2.1.153`. If the parsed version is below `2.1.153`, `provision-agent.sh` MUST abort with a non-zero exit code.

**HA-03.3** The CLI install step MUST be idempotent: if `claude --version` already reports `2.1.153`, the `npm install -g` step MUST be skipped; the CLI MUST NOT be reinstalled unnecessarily.

**HA-03.4** `provision-agent.sh` MUST record the installed CLI version string in its provisioning summary output (non-secret).

**Isolation boundary (HA-03):** The CLI is installed globally by root. `aios` can execute it but cannot modify the global npm installation. Version drift is blocked by `DISABLE_AUTOUPDATER=1` in the systemd unit (HA-05) and by `apt-mark hold` on the underlying runtime (HA-02).

---

### HA-04 — Client workspace

**HA-04.1** The directory `/opt/osgania/client/` MUST exist after `provision-agent.sh` completes with owner `aios`, group `aios`, and mode `0700`.

**HA-04.2** The workspace MUST be created using `install -d -o aios -g aios -m 0700 /opt/osgania/client`. This command re-asserts owner and mode on every run (idempotent).

**HA-04.3** `aios` MUST be the only non-root principal with any access to `/opt/osgania/client/` (mode `0700` — no group or world bits).

**Isolation boundary (HA-04):** `/opt/osgania/client/` is the ONLY path under `/opt` where `aios` may write. The systemd unit's `ReadWritePaths=/opt/osgania/client /var/log/osgania` explicitly lists it; all other paths are read-only under `ProtectSystem=strict`.

---

### HA-05 — Launch wrapper and managed-settings preservation (post-pivot)

> **PIVOT:** the apiKeyHelper (original HA-05) is abandoned (design ADR-1 SUPERSEDED → ADR-6). HA-05 now governs the launch wrapper and the requirement that 2a leaves `managed-settings.json` UNCHANGED.

**HA-05.1** The file `/opt/osgania/platform/bin/agent-run.sh` MUST exist after `provision-agent.sh` completes with owner `root`, group `root`, and mode `0755`. Its content MUST be (semantically):

```sh
#!/usr/bin/env bash
# /opt/osgania/platform/bin/agent-run.sh — root:root 0755
set -euo pipefail
: "${CREDENTIALS_DIRECTORY:?CREDENTIALS_DIRECTORY is not set — agent-run.sh must run under systemd LoadCredential}"
export ANTHROPIC_API_KEY
ANTHROPIC_API_KEY="$(tr -d '[:space:]' < "${CREDENTIALS_DIRECTORY}/anthropic-api-key")"
[[ -n "$ANTHROPIC_API_KEY" ]] || { printf 'agent-run.sh: API key file is empty or whitespace-only\n' >&2; exit 1; }
exec /usr/bin/claude "$@"
```

**HA-05.1a — Key normalization (auth-critical).** The wrapper MUST strip all whitespace from the credential before use (`tr -d '[:space:]'`): a valid Anthropic key contains no whitespace, so this is lossless and tolerates a trailing `\n`, a CRLF `\r` (Windows-pasted key), or surrounding spaces — preventing the SAME opaque 401 the apiKeyHelper produced. If the key is empty/whitespace-only after stripping, the wrapper MUST exit non-zero (fail closed), NOT authenticate with an empty key. The operator contract: the credential file contains the raw key only (no comments, no second key, no internal whitespace).

**HA-05.2** The wrapper MUST be installed using `install -o root -g root -m 0755` from the repo template `platform/bin/agent-run.sh`. `aios` MUST NOT be able to write to this file (mode `0755` gives `aios` r-x only; the root owner makes it non-writable by `aios`).

**HA-05.3** Post-pivot, `provision-agent.sh` MUST NOT write to `/etc/claude-code/managed-settings.json`. No `apiKeyHelper` key (or any other key) is added. The live policy file MUST be byte-identical before and after a 2a run.

**HA-05.4 — Wrapper `--bare` invariant (load-bearing):** The wrapper MUST `exec /usr/bin/claude "$@"` and MUST NOT contain the token `--bare`. The wrapper MUST source the key exclusively from `"${CREDENTIALS_DIRECTORY}/anthropic-api-key"` and MUST NOT hardcode a key path or read a key from any other location. `provision-agent.sh` MUST lint the wrapper content (and the assembled ExecStart, HA-06.2) before install; if `--bare` is present in either, it MUST abort with exit code > 0.

**HA-05.5** `provision-agent.sh` MUST validate (read-only) that `/etc/claude-code/managed-settings.json` is present and valid JSON using `jq . …` (exits 0). It MUST NOT rewrite the file.

**HA-05.6 — Structural invariant (R9–R12 unchanged, read-only):** `provision-agent.sh` MUST assert that ALL of the following are present in the live `managed-settings.json` (a read-only verification — 2a makes no change, so the pre-run and post-run JSON MUST be identical):
- `permissions.deny[]` contains exactly the 6 entries defined in `platform-security-core` R9.1–R9.6: `Bash(sudo *)`, `Bash(curl *)`, `Bash(wget *)`, `Read(/etc/osgania/secrets/**)`, `Edit(/opt/osgania/platform/**)`, `Write(/opt/osgania/platform/**)`
- `permissions.allow` is an empty array (`[]`)
- `permissions.defaultMode` equals `"default"`
- `permissions.disableBypassPermissionsMode` equals `"disable"`
- `allowManagedHooksOnly` equals `true`
- A PreToolUse hook for `Bash` points to `/opt/osgania/platform/hooks/guardia.sh` with timeout 10
- A PostToolUse hook for all tools points to `/opt/osgania/platform/hooks/camara.sh` with timeout 10

If any of these assertions fail, `provision-agent.sh` MUST abort with exit code > 0 and identify the failed assertion. There MUST be NO structural difference between the pre-run and post-run JSON (no `apiKeyHelper`, no added key).

**HA-05.7** Neither the archived repository template `platform/managed-settings.json` NOR the live `/etc/claude-code/managed-settings.json` is modified by 2a.

**Isolation boundary (HA-05):** `managed-settings.json` is `0644 root:root`; `aios` can read it but cannot write it; 2a does not touch it. The wrapper `agent-run.sh` is `0755 root:root` — `aios` can read and execute it but cannot write it (also under `Edit/Write(/opt/osgania/platform/**)` deny + guardia R2.6). The key value never appears in the wrapper script source, the unit file, or any committed file — the wrapper reads it at runtime from `$CREDENTIALS_DIRECTORY` (a per-unit private tmpfs created by systemd's `LoadCredential`). **Post-pivot the key DOES enter the agent's process environment** as `ANTHROPIC_API_KEY` once the wrapper `export`s it (the accepted ADR-6 trade-off); the env-dump speed-bump for that surface is HA-15.

---

### HA-06 — systemd service unit (osgania-agent.service)

**HA-06.1** The file `/etc/systemd/system/osgania-agent.service` MUST exist after `provision-agent.sh` completes and MUST contain EXACTLY the following directive set (assembled declaratively, written atomically):

```ini
[Unit]
Description=OSGANIA client agent (headless Claude Code run)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=aios
Group=aios
WorkingDirectory=/opt/osgania/client
StateDirectory=osgania-agent
StateDirectoryMode=0700
Environment=DISABLE_AUTOUPDATER=1
Environment=HOME=%S/osgania-agent
Environment=XDG_CONFIG_HOME=%S/osgania-agent
Environment=XDG_CACHE_HOME=%S/osgania-agent
Environment=XDG_DATA_HOME=%S/osgania-agent
Environment=XDG_STATE_HOME=%S/osgania-agent
LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key
UnsetEnvironment=ANTHROPIC_AUTH_TOKEN
ExecStart=/opt/osgania/platform/bin/agent-run.sh -p
ProtectSystem=strict
ReadWritePaths=/opt/osgania/client /var/log/osgania
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
LimitCORE=0
SystemCallFilter=~@reboot @swap @mount @clock @debug @module @raw-io @obsolete
```

**HA-06.2 — The `--bare` invariant (load-bearing, post-pivot binds in TWO places):** The `ExecStart` line MUST match `^ExecStart=/opt/osgania/platform/bin/agent-run.sh -p$` exactly (the only argument is `-p`) and MUST NOT contain the token `--bare`. Additionally, the installed wrapper MUST `exec /usr/bin/claude "$@"` with no `--bare` (HA-05.4). `provision-agent.sh` MUST assert BOTH constraints by linting the assembled unit string AND the wrapper content BEFORE writing/installing. If `--bare` appears in either, `provision-agent.sh` MUST abort with exit code > 0. Rationale: `--bare` skips managed-settings and all hooks, silently disabling Layers 1 and 2 of the entire security model; post-pivot the wrapper is the entrypoint, so the token must be absent from both the ExecStart line and the wrapper's `exec`.

**HA-06.3 — Forbidden tokens (verified by unit-content assertion):** The assembled unit file MUST NOT contain any of the following tokens:
- `--bare` (see HA-06.2)
- `MemoryDenyWriteExecute` (Node V8 JIT incompatible — explicitly excluded)
- `AUDIT_LOG=` (production-invisible variable; setting it would redirect camara output — base R10.1)
- `Environment=ANTHROPIC_API_KEY` (the LITERAL key value must never sit in the world-readable unit file / `systemctl show` / journal; the wrapper sets `ANTHROPIC_API_KEY` at runtime from the tmpfs credential — see HA-08)

**HA-06.4** `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` MUST appear in the unit (on its own `UnsetEnvironment=` directive or sharing one). `ANTHROPIC_API_KEY` MUST NOT be listed on any `UnsetEnvironment=` directive — post-pivot the wrapper intentionally sets it, so unsetting it is wrong. Rationale: `ANTHROPIC_AUTH_TOKEN` is scrubbed as defense-in-depth (a stray OAuth-style token could otherwise take precedence over the key); `ANTHROPIC_API_KEY` is the delivery mechanism and must survive.

**HA-06.5** After writing the unit file, `provision-agent.sh` MUST run `systemctl daemon-reload` before enabling or starting any unit.

**HA-06.6** After the defense-in-depth probe (HA-09, step 7), `provision-agent.sh` MUST run `systemctl enable osgania-agent.timer` **WITHOUT `--now`** (idempotent — enabling an already-enabled unit is a no-op). It MUST NOT use `--now` and MUST NOT `systemctl start` the service or timer during provisioning, so the in-script probe's `claude` invocation never races a timer-triggered service run that shares `/var/lib/osgania-agent` (SC-2). The service unit itself MUST NOT be separately `enable`d (the timer activates it at its scheduled cadence).

**HA-06.7** `StateDirectory=osgania-agent` causes systemd to create and own `/var/lib/osgania-agent` as `aios:aios 0700` on every start (auto-created, idempotent, survives reboots). `Environment=HOME=%S/osgania-agent`, `Environment=XDG_CONFIG_HOME=%S/osgania-agent`, `Environment=XDG_CACHE_HOME=%S/osgania-agent`, and `Environment=XDG_DATA_HOME=%S/osgania-agent` MUST all be present to redirect ALL CLI config/cache/data writes to this writable state directory under `ProtectSystem=strict`. `XDG_RUNTIME_DIR` is intentionally not set (see ADR-4 rationale).

**Isolation boundary (HA-06):**
- `aios` runs with zero capabilities (`CapabilityBoundingSet=` empty) — it cannot bind ports below 1024, change ownership, or manipulate `CAP_LINUX_IMMUTABLE`. The host-armed `chattr +a` on the audit log (R7.5 of vps-provisioning-base) remains intact because `aios` has no capability to clear it.
- `ProtectSystem=strict` makes the entire filesystem read-only except: `/opt/osgania/client`, `/var/log/osgania` (via `ReadWritePaths`), `/var/lib/osgania-agent` (via `StateDirectory`), and private tmp (via `PrivateTmp`).
- The API key is injected into `$CREDENTIALS_DIRECTORY` (private tmpfs, per-unit, non-swappable) via `LoadCredential` and is never written to the unit file or any committed file. **Post-pivot the wrapper exports it as `ANTHROPIC_API_KEY`, so it DOES appear in the agent's `/proc/<pid>/environ` and is inherited by Bash-tool children** — the accepted ADR-6 trade-off, mitigated by single-tenancy + Layer-1 `curl`/`wget` deny + the HA-15 env-dump speed-bump + the 2b egress firewall (the real exfil wall).
- `NoNewPrivileges=yes` prevents any setuid/setgid execution by the agent or its children.
- The unit MUST NOT set `AUDIT_LOG`, so `camara.sh` writes to the default path `/var/log/osgania/audit.jsonl` (armed with `chattr +a`).

---

### HA-07 — systemd timer unit (osgania-agent.timer)

**HA-07.1** The file `/etc/systemd/system/osgania-agent.timer` MUST exist after `provision-agent.sh` completes and MUST contain:

```ini
[Unit]
Description=OSGANIA agent cadence (PLACEHOLDER — autonomy-ladder owns the real schedule)

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

**HA-07.2** The timer cadence (`OnCalendar=daily`, `RandomizedDelaySec=3600`, `Persistent=true`) is a PLACEHOLDER. The real autonomy/workload schedule is DEFERRED to the future autonomy-ladder change. 2a ships the placeholder and MUST NOT claim it is the final schedule.

**HA-07.3** `provision-agent.sh` MUST enable the timer (`systemctl enable osgania-agent.timer`, **no `--now`**) AFTER the probe, and MUST NOT invoke `systemctl start osgania-agent.service` (or `--now`) during provisioning. The first real cadence run happens at the next `OnCalendar` tick (or via a deliberate operator `systemctl start`).

> **Behavior note — why no `--now` (SC-2):** `Persistent=true` + a first `enable --now` on a fresh install (no prior stamp) would make systemd trigger `osgania-agent.service` IMMEDIATELY — concurrent with the in-script defense-in-depth probe (step 7), which runs its own `claude` as `aios` over the same `/var/lib/osgania-agent` HOME/XDG tree. The CLI is not guaranteed concurrency-safe over one config/cache tree, so that race could make the probe inconclusive or spuriously fail the service. Dropping `--now` (and running the probe first) eliminates the race AND avoids a confusing key-absent "service failed" line in the journal during a normal provision. The timer is still `enabled` (HA-07-S2); only the immediate auto-start is removed.

**Isolation boundary (HA-07):** The timer is the sole activation mechanism for the agent service. Changing the schedule requires root access to edit the unit file and reload systemd. `aios` cannot modify unit files under `/etc/systemd/system/`.

---

### HA-08 — API-key delivery and env scrub

**HA-08.1** The API key MUST be injected into the unit via `LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key`, landing in the per-unit private tmpfs `$CREDENTIALS_DIRECTORY`. The launch wrapper (HA-05.1) reads it from there and `export`s it as `ANTHROPIC_API_KEY`, then `exec`s the CLI. The key value MUST NOT appear in:
- The unit file itself (no `Environment=ANTHROPIC_API_KEY=<value>` — HA-06.3)
- The wrapper script source, the `provision-agent.sh` script, or its stdout
- `systemctl show`, the journal, or any committed/versioned file

> **Accepted exposure (ADR-6, NOT a violation of HA-08.1):** once the wrapper `export`s the key, `ANTHROPIC_API_KEY` IS present in the agent process's `/proc/<pid>/environ` and is inherited by Bash-tool children. This is the deliberate post-pivot trade-off; HA-08.1 forbids the key in *files*, not in the *live runtime environment*. The runtime exposure is mitigated by HA-15 (env-dump speed-bump) + tenancy + the 2b egress firewall.

**HA-08.2** `provision-agent.sh` MUST NOT write any secret value to `/etc/osgania/secrets/anthropic-api-key` or any path under `/etc/osgania/secrets/`. The secrets directory structure is created by Slice 1 (vps-provisioning-base R5.1/R5.2); the key value is supplied by the operator out-of-band.

**HA-08.3** `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` MUST appear in the service unit (see HA-06.4), and `ANTHROPIC_API_KEY` MUST NOT be unset. Rationale: `ANTHROPIC_AUTH_TOKEN` is scrubbed so a stray OAuth-style token cannot take precedence over the key; `ANTHROPIC_API_KEY` is the delivery mechanism (set by the wrapper) and must survive.

**HA-08.4** The wrapper `/opt/osgania/platform/bin/agent-run.sh` MUST source the key exclusively from `"${CREDENTIALS_DIRECTORY}/anthropic-api-key"`, whitespace-strip and non-empty-check it (HA-05.1a), `export` it as `ANTHROPIC_API_KEY`, and then `exec /usr/bin/claude "$@"`. The wrapper MUST NOT read the key from any other environment variable, hardcode a key path, or write the key to any file. The wrapper inherits `$CREDENTIALS_DIRECTORY` because systemd sets it in the unit's main-process environment via `LoadCredential`, and the wrapper IS the unit's main process (`ExecStart`). The CLI then authenticates from `ANTHROPIC_API_KEY` in `-p` mode (the documented headless/non-root auth path; confirmed working as `aios`). [If a future Claude Code version changes `ANTHROPIC_API_KEY` precedence/handling, this requirement MUST be re-verified before upgrading the CLI pin.]

**HA-08.5** `provision-agent.sh` MUST NOT use `set -x` in any code path that could trace a credential value. The script never reads the key value directly; the wrapper reads it at runtime inside the unit.

**HA-08.6** `provision-agent.sh` MUST assert at the end of its run that `AUDIT_LOG` is not set in the executing environment (mirrors vps-provisioning-base R10.2).

**Isolation boundary (HA-08):** Key-leak surface:
- The key file stays `0700 root:root` (Slice-1 R5.1) + `Read(/etc/osgania/secrets/**)` deny (platform-security-core R9.4 / guardia R2.5) — double deny at OS + policy layers.
- `LoadCredential` creates a per-unit private tmpfs credential at `$CREDENTIALS_DIRECTORY`; this PATH is not `/proc/<pid>/environ`. The key VALUE, however, enters the agent's environment once the wrapper exports it (HA-08.1 accepted-exposure note) and is inherited by Bash-tool children.
- `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` scrubs the alternate token before the wrapper runs; `ANTHROPIC_API_KEY` is set fresh by the wrapper.
- The wrapper is `root:root 0755` — aios cannot swap it (also under `Edit/Write(/opt/osgania/platform/**)` deny + guardia R2.6).
- The agent cannot trivially print its own environment: HA-15 denies the obvious env-dump verbs/paths (speed-bump — interpreters still bypass it; containment of exfil is tenancy + 2b egress).
- The audit log (camara) only records `exit_code`, never `tool_response` body (platform-security-core R6.3).

---

### HA-09 — Live defense-in-depth probe (bypass neutralization)

> **RE-AMENDED (design ADR-5, Phase-4 hardware verification, 2026-06-16):** the prior two-marker probe could NEVER reach VERIFIED on CLI 2.1.153 — and Phase-4 found WHY, refuting the earlier "mode-lock is a no-op" assumption: managed-settings `disableBypassPermissionsMode: "disable"` DOES take effect. Under `--dangerously-skip-permissions` the stream-json `init` event reports `permissionMode: "default"` (NOT `bypassPermissions`), so the agent cannot bypass approvals; in headless `-p` every Bash tool call then DEFERS (no approver), and the forbidden command can never execute (the benign liveness command can't either — which is exactly why the marker oracle was permanently UNVERIFIED). The probe now tests this OUTER guarantee deterministically via `permissionMode`. guardia (the inner denylist layer) is verified independently by the host-safe `guardia.bats` matchers, since no Bash tool can execute live to exercise it.

**HA-09.1 — permissionMode probe.** As the final active (probing) step of `provision-agent.sh`, before the provisioning summary (step 8), the script MUST run — as `aios`, under the production runtime env (`HOME`/`XDG_*` → `/var/lib/osgania-agent`), with `--dangerously-skip-permissions --output-format stream-json --verbose` and a benign prompt that needs no tool use — and parse the `permissionMode` field from the stream-json `system`/`init` event. The oracle is the parsed `permissionMode`, NOT any tool execution; model refusal, the CLI bash sandbox, and headless permission-deferral therefore cannot confound it.

**HA-09.2** The probe result MUST be classified exactly as one of three states (from `permissionMode`) and recorded in the provisioning summary:
- **VERIFIED**: `permissionMode` is `default` (or any non-`bypassPermissions` mode) DESPITE `--dangerously-skip-permissions` — the managed `disableBypassPermissionsMode` neutralized the bypass flag, so the agent cannot skip permissions and no Bash tool runs without an approval that headless `-p` lacks. The forbidden command cannot execute; guardia is the second (denylist) layer behind that.
- **UNVERIFIED**: no `init` event was observed (empty/unparseable output — key absent at `/etc/osgania/secrets/anthropic-api-key`, `claude` not installed, wrapper missing, or an auth error). The probe could not determine the mode. Residual risk — same gate as vps-provisioning-base PV-19.
- **FAILED**: `permissionMode` is `bypassPermissions` — the CLI honored `--dangerously-skip-permissions`, i.e. the managed `disableBypassPermissionsMode` is NOT in effect. The Layer-3 outer wall is broken. MUST be surfaced loudly as a hard finding requiring operator action.

**HA-09.3** `provision-agent.sh` MUST NOT claim VERIFIED without a positive non-`bypassPermissions` `permissionMode` from the `init` event. An absent/empty `permissionMode` (no init event) MUST be UNVERIFIED, never VERIFIED — a missing init event is inconclusive, not a pass. (guardia's denylist correctness, the inner layer, is asserted separately by the host-safe `guardia.bats` matchers — R2.x + HA-15 — because under the neutralized-bypass policy no live Bash tool can execute to exercise it end-to-end.)

**HA-09.4** If the probe result is FAILED, `provision-agent.sh` MUST exit with a non-zero exit code and identify the failure explicitly.

**Isolation boundary (HA-09):** The probe runs as `aios` under the same HOME/XDG settings as the production unit, exercising the actual installed CLI against the actual installed managed policy. The benign prompt performs no tool action and needs no filesystem write, so the probe is non-destructive and discloses no secret — the oracle is the CLI's own reported `permissionMode`, captured from the agent's stdout into a shell variable, never written to the journal.

---

### HA-10 — Idempotency

**HA-10.1** Every step of `provision-agent.sh` MUST be safe to re-run on an already-2a-provisioned box and MUST exit 0. Specifically:
- `apt install` / NodeSource: guarded by version check (skip if Node >= 18 present)
- `apt-mark hold`: add-only (re-running is a no-op)
- `npm install -g @anthropic-ai/claude-code@2.1.153`: skipped if `claude --version` already reports `2.1.153`
- `install -d -o aios -g aios -m 0700 /opt/osgania/client`: re-asserts owner and mode every run
- `install -o root -g root -m 0755 …/agent-run.sh`: re-asserts mode every run (overwrites with current content)
- managed-settings.json: read-only structural verify only — NO write, so re-runs leave it byte-identical
- Unit file writes: written declaratively (overwrite-in-place, followed by daemon-reload)
- `systemctl enable osgania-agent.timer` (no `--now`, runs after the probe): no-op when already enabled

**HA-10.2** A re-run MUST NOT restart or stop the timer or service if it is already running correctly. `systemctl enable` is idempotent; `systemctl daemon-reload` is safe to re-run.

**HA-10.3** The Slice-1 invariants listed in HA-11 MUST all be intact after any re-run of `provision-agent.sh`.

**Isolation boundary (HA-10):** Idempotency is a property of `provision-agent.sh` as root. The unit files are written declaratively; on re-run they are simply overwritten with the same content.

---

### HA-11 — Slice-1 invariants preserved

**HA-11.1** After `provision-agent.sh` completes (first run or re-run), ALL of the following MUST be true:
- `getent passwd aios` returns UID 9001, GID 9001, shell `/usr/sbin/nologin`, home `/nonexistent`
- `/etc/osgania/secrets/` is `root:root 0700`
- `lsattr /var/log/osgania/audit.jsonl` shows the `a` flag
- `AUDIT_LOG` is not set in the executing environment
- `CAP_LINUX_IMMUTABLE` is not cleared by any 2a operation
- `aios` is absent from `sudo` and `admin` groups

**HA-11.2** `provision-agent.sh` MUST NOT run `chattr -a` on the audit log for any reason.

**HA-11.3** `provision-agent.sh` MUST NOT modify or delete `/etc/osgania/secrets/anthropic-api-key` or any other file under `/etc/osgania/secrets/`.

**HA-11.4** `provision-agent.sh` MUST NOT add `aios` to any group it was not already a member of.

**Isolation boundary (HA-11):** The Slice-1 security contract is immutable from 2a's perspective. 2a is an additive layer; its rollback (see HA-12) returns the box to the exact Slice-1 end-state.

---

### HA-12 — Rollback

**HA-12.1** A complete rollback of 2a MUST be possible by performing the following steps in order (documented for operator use; not automated by `provision-agent.sh`):
1. `systemctl disable --now osgania-agent.timer osgania-agent.service`
2. Remove `/etc/systemd/system/osgania-agent.service` and `/etc/systemd/system/osgania-agent.timer`, then `systemctl daemon-reload`
3. Remove the wrapper `/opt/osgania/platform/bin/agent-run.sh`. **managed-settings.json needs NO change** — post-pivot 2a never modified it. (The guardia env-dump category is additive defense-in-depth; reverting it is optional, only for a byte-identical Slice-1 restore.)
4. `npm uninstall -g @anthropic-ai/claude-code`
5. (Optional) `apt-mark unhold nodejs npm`
6. `rm -rf /opt/osgania/client/`

**HA-12.2** During rollback, the operator MUST NOT:
- Run `chattr -a` on `/var/log/osgania/audit.jsonl`
- Delete `/etc/osgania/secrets/` or the key file within (that is the operator's revocable credential)
- Modify any `platform-security-core` R9–R12 key, hook registration, `disableBypassPermissionsMode`, or `CAP_LINUX_IMMUTABLE` arming

**HA-12.3** After rollback, the box MUST be in the verified Slice-1 end-state (vps-provisioning-base canonical spec), not below it.

**Isolation boundary (HA-12):** Rollback is a privileged root operation. The operator controls when and whether to roll back. The audit log is permanently preserved (append-only); prior agent activity is not erasable by rollback.

---

### HA-14 — File structure

**HA-14.1** The following files MUST exist in the repository after this change is applied:

```
scripts/
  provision-agent.sh       — the 2a installer (steps 0–8; reworked for the pivot)
platform/
  bin/
    agent-run.sh           — launch wrapper template (installed root:root 0755; ADR-6)
                             [anthropic-key.sh REMOVED — apiKeyHelper obsolete, ADR-1 superseded]
  hooks/
    guardia.sh             — PSC hook, EXTENDED with the env-dump denylist category (HA-15)
  systemd/
    osgania-agent.service  — service unit template (ADR-3 amended: ExecStart=wrapper)
    osgania-agent.timer    — timer unit template (placeholder cadence)
tests/
  provision-agent.bats     — host-safe + Linux-deferred scenarios (reworked for the pivot)
  guardia.bats             — PSC guardia scenarios, EXTENDED with HA-15 env-dump regression
```

`platform/bin/anthropic-key.sh` MUST be removed (obsolete; ADR-1 superseded by ADR-6).

**HA-14.2** `provision-agent.sh`, `platform/bin/agent-run.sh`, and `platform/hooks/guardia.sh` MUST pass `shellcheck -s bash` with no warnings or errors.

**HA-14.3** `provision-agent.sh` MUST have execute permission; the installed wrapper `agent-run.sh` MUST be executable (`install … -m 0755`).

---

### HA-15 — guardia env-dump denial (pivot mitigation; extends PSC R2)

> Speed-bump mitigation for the K-2/K-7 env-key exposure introduced by ADR-6. Implemented in `platform/hooks/guardia.sh` (a new ordered denylist step in the R2 idiom); extends PSC R2 WITHOUT rewriting the archived PSC spec; does NOT alter R2.1–R2.6.

**HA-15.1** `guardia.sh` MUST deny (emit `permissionDecision: "deny"`) a Bash command whose effect is to print/dump the process environment, for these forms:
- `printenv` (any invocation — its sole purpose is printing environment variables)
- `env` used as a dump: `env` alone, `env` followed only by options (`-0`/`--null`/`-i`/`-u VAR`) with NO following command word, or `env` immediately piped/redirected. `--null` is the GNU long-form synonym of `-0` and MUST be covered. (NOT `env FOO=bar cmd`, `env -u FOO cmd`, `env -i cmd`, `env --unset=FOO cmd`, `env --ignore-environment cmd` — see HA-15.3.)
- bare `set` (prints all shell variables and functions) — `set` with NO following token, or followed only by `;`/`|`/`&`/redirection (incl. `set > file`). (NOT `set -…`/`set +…`/`set -o …`/`set -- …` — see HA-15.3.)
- bare `declare` / bare `typeset` (no arguments — dumps ALL variables+values, exactly like bare `set`), including the redirect form `declare > file` / `typeset > file`
- `declare -p`, `typeset -p`, `local -p`, `export -p`, `readonly -p` (print variable / exported / readonly definitions including values), INCLUDING fused short-flag clusters that contain `p` (e.g. `declare -px`, `declare -pf`, `declare -ip`) — any such cluster still prints definitions. These print-flag matchers MUST be anchored to command position (start-of-command or after `|`/`;`/`&`) so the flag appearing inside quoted argument text does NOT false-positive (see HA-15.3).
- `compgen -v`, `compgen -e`, `compgen -A variable`, `compgen -A export`, and fused single-char clusters containing `v`/`e` (`compgen -ve`/`-ev`) (enumerate variable / exported-variable names — `-A variable`/`-A export` are exact synonyms of `-v`/`-e` and MUST be covered)

**HA-15.1a — Matcher precision (the matchers MUST be expressible in guardia's no-shell-parser model).** guardia does substring/ERE token matching (PSC R4, no shell parsing). The `set`/`env`/`declare`/`typeset` distinctions therefore MUST be specified as concrete EREs the implementer can encode, and exercised by BOTH deny and allow scenarios (HA-15-S1/S3). The load-bearing rule: deny only the *dump* form (leading token followed by EOL / `;`/`|`/`&`/redirection, OR the explicit `-p`/`-v`/`-e`/`-A variable`/`-A export` print flags) and NEVER the option-setting form (a following `-`/`+`flag for `set`, an `IDENTIFIER=` or following command word for `env`, a `-i`/`-a`/`x=…` for `declare`). If a form cannot be cleanly distinguished, it MUST be moved to allow (fail-open for usability), per the speed-bump scope (HA-15.6).

**HA-15.2** `guardia.sh` MUST deny any Bash command that reads a process-environ path, matched by the ERE `/proc/(self|thread-self|[0-9]+|\$\$|\$BASHPID|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]*\})(/task/[^/]+)?/environ` — i.e. `/proc/self/environ`, `/proc/thread-self/environ`, `/proc/<numeric-pid>/environ`, `/proc/$$/environ`, `/proc/$BASHPID/environ`, a bare-variable pid `/proc/$PPID/environ` (and any `/proc/$VAR/environ`), `/proc/${...}/environ`, and the per-thread alias `/proc/<pid>/task/<tid>/environ`. This is tool-agnostic (covers `cat`, `xxd`, `strings`, `tr`, `head`, `mapfile`, here-strings — any reader that NAMES the path), mirroring the R2.5 secrets-path approach.

> **Honest limit (HA-15.6 applies):** this catches reads that NAME the environ path, including a bare-variable pid (`/proc/$PPID/environ`), `thread-self`, and the `/task/<tid>/` alias. It still does NOT catch a true variable-indirection read where the literal path never appears (`p=/proc/self/environ; cat "$p"`) or a command-substitution pid (`/proc/$(pgrep claude)/environ`) — the same "shell-level indirection out of scope" non-goal PSC already declares for guardia. The literal placeholder `/proc/<pid>/environ` used elsewhere in this doc is DOCUMENTATION shorthand for the ERE above, not a string to match.

**HA-15.3 — MUST NOT false-positive (load-bearing):** `guardia.sh` MUST `defer` (NOT deny) the ubiquitous benign forms that merely look similar:
- `set -e`, `set -u`, `set -x`, `set +e`, `set -euo pipefail`, `set -o pipefail` (shell option setting)
- `declare -i x`, `declare -a arr`, `declare x=1`, `typeset -i x` (variable declaration, not `-p`)
- `export FOO=bar`, `export PATH="$PATH:/x"` (setting an exported variable, not `-p`)
- `env FOO=bar somecommand` (running a command with a variable set — the dominant `env` use)
- `env -u FOO somecommand`, `env -i somecommand`, `env -u A -i somecommand`, `env --unset=FOO somecommand`, `env --ignore-environment somecommand` (sanitized-exec forms: options FOLLOWED by a command word — NOT a dump)
- `readonly FOO=bar`, `readonly X` (declaration, not `readonly -p`)
- a mere FILENAME or path that merely CONTAINS a dump verb as a substring — `bash printenv.sh`, `cat printenv.md`, `./printenv.sh`, `scripts/printenv.sh`, `node printenv.js`, `cat myprintenv.md`, `cat printenv_helper.md` (the verb is part of a filename token, not a command word)
- a print flag appearing INSIDE quoted argument text — `echo "use export -p to list"`, `git commit -m "document declare -p usage"`, `echo "run: typeset -p to inspect"` (the flag is not in command position, so the command performs no env access)

A category that denied bare `set` but broke `set -euo pipefail`, or denied `env VAR=val cmd` / `env -i cmd`, or hard-denied a routine `git commit`/`cat`/`bash` whose argument text merely mentions a dump verb, would make the agent unusable; this distinction is normative, not advisory, and is a primary target of the adversarial review (for both missed denials AND false-positives). The filename and quoted-argument false-positives above were found and closed by the Phase-3 blind adversarial attack on the implemented matchers.

**HA-15.4** The deny reason MUST follow PSC R3.1: `permissionDecisionReason` MUST be a non-empty string of the form `[guardia] denied: env-dump — <brief explanation>`.

**HA-15.5** This category extends PSC R2 and MUST NOT alter the behavior of R2.1–R2.6 (sudo, curl/wget, rm -rf, disk-wipe, secrets-path, platform-path) or R1/R3/R4. All pre-existing guardia scenarios MUST still pass. **Step position is normative:** the env-dump + bash-native-egress checks MUST be inserted as step 7.5 — AFTER the secrets check (R2.5, step 6) and the platform check (R2.6, step 7), immediately BEFORE the default defer (step 8). Because guardia is first-match-wins (each step `emit_deny … exit 0`), this ordering guarantees a command matching BOTH an inherited category and env-dump still denies with the INHERITED reason (e.g. `cat /proc/self/environ > /opt/osgania/platform/x` denies as `platform`, not `env-dump`), preserving R2.x reason attribution and the HA-09 probe's Layer-isolation claim.

**HA-15.5a — bash-native egress deny (TMH-2).** `guardia.sh` MUST also deny any Bash command containing the substring `/dev/tcp` or `/dev/udp` (bash's network pseudo-devices), with reason prefix `[guardia] denied: net-builtin — …`. Rationale: post-pivot the key is in the agent env; `/dev/tcp` is a `curl`/`wget`-free, interpreter-free exfil channel reachable from the Bash tool (`exec 3<>/dev/tcp/host/443`). This is cheap, low-false-positive defense-in-depth (legitimate agent commands rarely name `/dev/tcp`). It is a speed-bump, NOT the exfil wall (HA-15.6 / 2b egress).

**HA-15.7 — Non-functional preservation (PSC R4).** The extended `guardia.sh` MUST continue to satisfy PSC R4.1–R4.5: no network calls, no filesystem reads beyond STDIN, `shellcheck`-clean (no warnings), completes < 2s, and defers gracefully on malformed/empty STDIN. The env-dump / net-builtin steps MUST be pure string/ERE matching on the already-parsed command and MUST NOT read the filesystem or alter the STDIN-parse / defer-on-malformed path (R1.6/R4.5).

**HA-15.6 — Honest scope (speed-bump, not a sandbox):** This category is defense-in-depth against naive/accidental dumps. It does NOT, and MUST NOT attempt to, block the env from being read by:
- an interpreter (`python -c`, `node -e`, `perl`, `ruby`, `awk` `ENVIRON`, a compiled binary), OR
- a bash-native one-liner that simply names the variable — `echo "$ANTHROPIC_API_KEY"`, `printf '%s' "$ANTHROPIC_API_KEY"`, indirect expansion `x=ANTHROPIC_API_KEY; echo "${!x}"`, OR
- variable-indirection of the path — `p=/proc/self/environ; cat "$p"`.

Denying these would break the agent's core tooling (`echo`/`printf`/interpreters) and is still evadable, so they are KNOWINGLY out of scope. The bar is therefore very low (a one-token `echo $VAR` suffices to read the key); the env-dump category only raises it against the literal dump verbs/paths. Containment of key EXFILTRATION is the responsibility of single-tenancy + the 2b egress firewall, not guardia (consistent with PSC's guardia "speed bump… not a complete sandbox" non-goal).

**Isolation boundary (HA-15):** `guardia.sh` runs as a managed PreToolUse hook invoked by the Claude Code runtime (not via an agent tool), is `root:root` and non-writable by `aios` (PSC R9.5/R9.6 + guardia R2.6), and emits only `deny`/`defer` (never `allow`). The env-dump / net-builtin checks add matching only; they cannot widen guardia's authority or alter the hook contract (PSC R1). Like R2.1–R2.6, they match agent Bash tool-call command strings ONLY; they never intercept the runtime's own guardia/camara hook-invocation path (PSC R9.7), so they cannot block the hooks from running.

---

## Behavioral Scenarios

Scenarios are written for `bats-core` (`tests/provision-agent.bats`). IDs continue the HA- family.

### Testability classification (mandatory, per design Testing Strategy)

| Label | Meaning |
|-------|---------|
| HOST-SAFE | Pure string/JSON logic; no root, no systemd, no real install; runs on macOS/Linux CI without privileges |
| LINUX-ROOT | Requires real Ubuntu + `PROVISION_TEST_ALLOW_MUTATION=1` + `EUID==0`; skips off-target with explicit message |
| LIVE-KEY | Also requires a real Anthropic API key at `/etc/osgania/secrets/anthropic-api-key`; UNVERIFIED-skip if absent |

---

### HA-01 — Preconditions gate

#### HA-01-S1 — Missing aios account causes abort (HOST-SAFE)

**Requirement**: HA-01.1, HA-01.2

```
GIVEN provision-agent.sh is invoked on a system where `getent passwd aios` returns no entry
WHEN provision-agent.sh runs
THEN exit code > 0
 AND stderr contains a message identifying the failed precondition (aios account absent)
 AND no filesystem mutation has occurred
```

#### HA-01-S2 — Invalid managed-settings.json causes abort (HOST-SAFE)

**Requirement**: HA-01.1, HA-01.2

```
GIVEN /etc/claude-code/managed-settings.json exists but contains invalid JSON (e.g. `{bad}`)
WHEN provision-agent.sh runs
THEN exit code > 0
 AND stderr contains a message identifying the failed precondition (managed-settings invalid)
 AND no filesystem mutation has occurred
```

#### HA-01-S3 — Dry-run reports plan without mutation (HOST-SAFE)

**Requirement**: HA-01.4

```
GIVEN provision-agent.sh is invoked with --check
WHEN provision-agent.sh runs
THEN exit code is 0
 AND stdout/stderr describe the provisioning plan (what would be applied)
 AND no npm package is installed
 AND no file is written to /etc/ or /opt/ or /etc/systemd/
 AND no `apt` command is executed
 AND the defense-in-depth probe is NOT executed (no `claude` invocation, no network call) — `--check` is a pure plan, including step 7
```

---

### HA-02 — Node.js runtime

#### HA-02-S1 — Node >= 18 present after provisioning (LINUX-ROOT)

**Requirement**: HA-02.1, HA-02.2

```
GIVEN provision-agent.sh has run to completion on a fresh Ubuntu 24.04 or 26.04 box
WHEN `node --version` is run
THEN exit code is 0
 AND the version string parses as >= 18 (e.g. "v18.19.1", "v20.x.x")

WHEN `npm --version` is run
THEN exit code is 0
 AND stdout is non-empty
```

#### HA-02-S2 — nodejs and npm packages are held (LINUX-ROOT)

**Requirement**: HA-02.3

```
GIVEN provision-agent.sh has run to completion
WHEN `apt-mark showhold` is run
THEN the output contains "nodejs"
 AND the output contains "npm"
```

#### HA-02-S3 — Node version branch logic (HOST-SAFE, unit test)

**Requirement**: HA-02.1, HA-02.4

```
GIVEN the version-check function is tested against a mocked `node --version` returning "v20.1.0"
WHEN the branch logic is evaluated
THEN the NodeSource install branch is NOT taken (version >= 18, skip apt)

GIVEN the version-check function is tested against a mocked `node --version` returning "v16.0.0" or absent
WHEN the branch logic is evaluated
THEN the NodeSource 20.x install branch IS taken
```

---

### HA-03 — Claude Code CLI pin

#### HA-03-S1 — CLI version is 2.1.153 after provisioning (LINUX-ROOT)

**Requirement**: HA-03.1, HA-03.2

```
GIVEN provision-agent.sh has run to completion
WHEN `claude --version` is run
THEN exit code is 0
 AND the version string contains "2.1.153"
 AND the version is >= 2.1.153 (semantic version assertion)
```

#### HA-03-S2 — CLI not reinstalled if already at pin (HOST-SAFE, unit test)

**Requirement**: HA-03.3

```
GIVEN a mock `claude --version` returning "2.1.153"
WHEN the CLI install logic is evaluated
THEN `npm install -g @anthropic-ai/claude-code@2.1.153` is NOT invoked
```

#### HA-03-S3 — CLI reinstalled if version differs (HOST-SAFE, unit test)

**Requirement**: HA-03.3

```
GIVEN a mock `claude --version` returning "2.1.100"
WHEN the CLI install logic is evaluated
THEN `npm install -g @anthropic-ai/claude-code@2.1.153` IS invoked
```

#### HA-03-S4 — CLI version recorded in summary (LINUX-ROOT)

**Requirement**: HA-03.4

```
GIVEN provision-agent.sh has run to completion
WHEN the provisioning summary output is examined
THEN it contains the installed CLI version string (e.g. "Claude Code 2.1.153")
```

---

### HA-04 — Client workspace

#### HA-04-S1 — /opt/osgania/client/ exists with correct owner and mode (LINUX-ROOT)

**Requirement**: HA-04.1, HA-04.2

```
GIVEN provision-agent.sh has run to completion
WHEN `stat -c '%U:%G %a' /opt/osgania/client` is run
THEN the output is "aios:aios 700"
```

#### HA-04-S2 — Workspace mode re-asserted on re-run (LINUX-ROOT)

**Requirement**: HA-04.2, HA-10.1

```
GIVEN provision-agent.sh has run once
  AND an operator manually changes /opt/osgania/client to mode 0755
WHEN provision-agent.sh is run a second time
WHEN `stat -c '%a' /opt/osgania/client` is checked
THEN the mode is restored to 700
```

---

### HA-05 — Launch wrapper and managed-settings preservation

#### HA-05-S1 — Wrapper file installed with correct owner and mode (LINUX-ROOT)

**Requirement**: HA-05.1, HA-05.2

```
GIVEN provision-agent.sh has run to completion
WHEN `stat -c '%U:%G %a' /opt/osgania/platform/bin/agent-run.sh` is run
THEN the output is "root:root 755"

WHEN `test -x /opt/osgania/platform/bin/agent-run.sh` is run
THEN exit code is 0

WHEN `test -e /opt/osgania/platform/bin/anthropic-key.sh` is run
THEN exit code is non-zero (the obsolete apiKeyHelper is absent)
```

#### HA-05-S2 — 2a does NOT modify managed-settings.json (HOST-SAFE against fixture)

**Requirement**: HA-05.3, HA-05.5, HA-05.7

```
GIVEN a fixture copy of /etc/claude-code/managed-settings.json (the Slice-1 template)
WHEN provision-agent.sh's managed-settings handling runs against the fixture (read-only verify path)
THEN the fixture file is byte-identical before and after (no write; no apiKeyHelper key added)
 AND `jq .` on the fixture exits 0 (still valid JSON)
 AND `jq -e 'has("apiKeyHelper")'` on the fixture exits non-zero (the key is absent)
```

#### HA-05-S3 — R9–R12 structural invariant: all existing keys present and unchanged (HOST-SAFE against fixture)

**Requirement**: HA-05.6

```
GIVEN a fixture copy of /etc/claude-code/managed-settings.json (Slice-1 template with all R9-R12 keys)
WHEN provision-agent.sh's read-only R9–R12 structural verify runs against the fixture (no write)
THEN `.permissions.deny | length` equals 6
 AND `.permissions.deny` contains "Bash(sudo *)"
 AND `.permissions.deny` contains "Bash(curl *)"
 AND `.permissions.deny` contains "Bash(wget *)"
 AND `.permissions.deny` contains "Read(/etc/osgania/secrets/**)"
 AND `.permissions.deny` contains "Edit(/opt/osgania/platform/**)"
 AND `.permissions.deny` contains "Write(/opt/osgania/platform/**)"
 AND `.permissions.allow == []`
 AND `.permissions.defaultMode == "default"`
 AND `.permissions.disableBypassPermissionsMode == "disable"`
 AND `.allowManagedHooksOnly == true`
 AND the guardia PreToolUse hook entry for Bash with path /opt/osgania/platform/hooks/guardia.sh and timeout 10 is present
 AND the camara PostToolUse hook entry for all tools with path /opt/osgania/platform/hooks/camara.sh and timeout 10 is present
```

#### HA-05-S4 — Wrapper body invariant: exec claude "$@", no --bare, key from CREDENTIALS_DIRECTORY (HOST-SAFE)

**Requirement**: HA-05.1, HA-05.4, HA-06.2

```
GIVEN the repo wrapper template platform/bin/agent-run.sh
THEN it contains `exec /usr/bin/claude "$@"`
 AND it does NOT contain the token `--bare`
 AND it sources the key from "${CREDENTIALS_DIRECTORY}/anthropic-api-key" and from no other path
 AND it exports ANTHROPIC_API_KEY (not ANTHROPIC_AUTH_TOKEN, not a hardcoded value)
 AND it does NOT write the key to any file
```

#### HA-05-S5 — Wrapper script shellcheck (HOST-SAFE)

**Requirement**: HA-14.2

```
GIVEN platform/bin/agent-run.sh
WHEN `shellcheck -s bash platform/bin/agent-run.sh` is run
THEN exit code is 0
 AND no warnings or errors are present
```

---

### HA-06 — systemd service unit

#### HA-06-S1 — Unit contains all required directives (HOST-SAFE, unit-string assertion)

**Requirement**: HA-06.1, HA-06.4, HA-06.7

```
GIVEN the assembled osgania-agent.service unit string (built from the template, not read from disk)
THEN the string contains "Type=oneshot"
 AND "User=aios"
 AND "Group=aios"
 AND "WorkingDirectory=/opt/osgania/client"
 AND "StateDirectory=osgania-agent"
 AND "StateDirectoryMode=0700"
 AND "Environment=DISABLE_AUTOUPDATER=1"
 AND "Environment=HOME=%S/osgania-agent"
 AND "Environment=XDG_CONFIG_HOME=%S/osgania-agent"
 AND "Environment=XDG_CACHE_HOME=%S/osgania-agent"
 AND "Environment=XDG_DATA_HOME=%S/osgania-agent"
 AND "Environment=XDG_STATE_HOME=%S/osgania-agent"
 AND "LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key"
 AND "UnsetEnvironment=ANTHROPIC_AUTH_TOKEN" (and ANTHROPIC_API_KEY does NOT appear on any UnsetEnvironment directive)
 AND "ExecStart=/opt/osgania/platform/bin/agent-run.sh -p"
 AND "ProtectSystem=strict"
 AND "ReadWritePaths=/opt/osgania/client /var/log/osgania"
 AND "NoNewPrivileges=yes"
 AND "PrivateTmp=yes"
 AND "ProtectHome=yes"
 AND "ProtectKernelTunables=yes"
 AND "ProtectKernelModules=yes"
 AND "ProtectControlGroups=yes"
 AND "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"
 AND "CapabilityBoundingSet="
 AND "RestrictNamespaces=yes"
 AND "RestrictSUIDSGID=yes"
 AND "LockPersonality=yes"
 AND "LimitCORE=0"
 AND "SystemCallFilter=~@reboot @swap @mount @clock @debug @module @raw-io @obsolete"
 AND "After=network-online.target"
 AND "Wants=network-online.target"
```

#### HA-06-S2 — --bare guard: assembled unit MUST NOT contain --bare (HOST-SAFE, load-bearing)

**Requirement**: HA-06.2

```
GIVEN the assembled osgania-agent.service unit string AND the wrapper template platform/bin/agent-run.sh
THEN the unit string does NOT contain "--bare"
 AND the ExecStart line matches the pattern ^ExecStart=/opt/osgania/platform/bin/agent-run.sh -p$
      (only "-p", no extra flags, no --bare token anywhere on the line)
 AND the wrapper `exec`s `/usr/bin/claude "$@"` and contains no "--bare" token
```

#### HA-06-S3 — Forbidden token absence: MemoryDenyWriteExecute, AUDIT_LOG=, Environment=ANTHROPIC_API_KEY (HOST-SAFE, load-bearing)

**Requirement**: HA-06.3

```
GIVEN the assembled osgania-agent.service unit string
THEN the string does NOT contain "MemoryDenyWriteExecute"
 AND the string does NOT contain "AUDIT_LOG="
 AND the string does NOT contain "Environment=ANTHROPIC_API_KEY"
```

#### HA-06-S4 — Unit file on disk after provisioning (LINUX-ROOT)

**Requirement**: HA-06.1, HA-06.5

```
GIVEN provision-agent.sh has run to completion
WHEN `systemctl show osgania-agent.service` is run
THEN exit code is 0 (unit is recognized by systemd)

WHEN `cat /etc/systemd/system/osgania-agent.service` is run
THEN output contains "Type=oneshot"
 AND output contains "User=aios"
 AND output contains "ExecStart=/opt/osgania/platform/bin/agent-run.sh -p"
 AND output does NOT contain "--bare"
 AND output does NOT contain "MemoryDenyWriteExecute"
 AND output does NOT contain "AUDIT_LOG="
 AND output does NOT contain "Environment=ANTHROPIC_API_KEY"
```

#### HA-06-S5 — provision-agent.sh shellcheck (HOST-SAFE)

**Requirement**: HA-14.2

```
GIVEN scripts/provision-agent.sh
WHEN `shellcheck -s bash scripts/provision-agent.sh` is run
THEN exit code is 0
 AND no warnings or errors are present
```

#### HA-06-S6 — Agent run produces no XDG / EROFS permission errors (LINUX-ROOT)

**Requirement**: HA-06.7

```
GIVEN provision-agent.sh has run to completion
  AND osgania-agent.service has been started at least once (via timer trigger or direct start)
WHEN `journalctl -u osgania-agent.service --no-pager` is examined
THEN the output does NOT contain "Permission denied"
 AND the output does NOT contain "Read-only file system"
 AND the output does NOT contain "EROFS"
 AND the output does NOT contain "XDG"
 AND the output does NOT contain "EAFNOSUPPORT" / "Address family not supported" / a "getaddrinfo" failure (SC-3: confirms RestrictAddressFamilies does not break DNS; if it does, add AF_NETLINK)
```

*(This scenario verifies that the explicit `XDG_CACHE_HOME` and `XDG_DATA_HOME` directives in the unit prevent any write attempt from landing on the read-only filesystem under `ProtectSystem=strict`.)*

---

### HA-07 — systemd timer unit

#### HA-07-S1 — Timer unit contains placeholder cadence (HOST-SAFE, unit-string assertion)

**Requirement**: HA-07.1, HA-07.2

```
GIVEN the assembled osgania-agent.timer unit string
THEN the string contains "OnCalendar=daily"
 AND "RandomizedDelaySec=3600"
 AND "Persistent=true"
 AND "WantedBy=timers.target"
```

#### HA-07-S2 — Timer enabled after provisioning (LINUX-ROOT)

**Requirement**: HA-06.6, HA-07.3

```
GIVEN provision-agent.sh has run to completion
WHEN `systemctl is-enabled osgania-agent.timer` is run
THEN exit code is 0
 AND stdout contains "enabled"
```

---

### HA-08 — API-key delivery and env scrub

#### HA-08-S1 — UnsetEnvironment scrubs ANTHROPIC_AUTH_TOKEN only (HOST-SAFE, unit-string assertion)

**Requirement**: HA-06.4, HA-08.3

```
GIVEN the assembled osgania-agent.service unit string
THEN the string contains "UnsetEnvironment=ANTHROPIC_AUTH_TOKEN"
 AND ANTHROPIC_API_KEY does NOT appear on any UnsetEnvironment directive
     (post-pivot the wrapper sets ANTHROPIC_API_KEY; unsetting it would break key delivery)
```

#### HA-08-S2 — AUDIT_LOG is not set at end of provision-agent.sh run (HOST-SAFE / LINUX-ROOT)

**Requirement**: HA-08.6, HA-11.1

```
GIVEN provision-agent.sh has run to completion
WHEN the executing shell environment is inspected (`env | grep AUDIT_LOG`)
THEN AUDIT_LOG is NOT present
 AND the grep exit code is non-zero (variable not set)
```

#### HA-08-S3 — Key value never appears in provision-agent.sh stdout or the unit file (HOST-SAFE / LINUX-ROOT)

**Requirement**: HA-08.1, HA-08.5

```
GIVEN provision-agent.sh has run to completion with a test key "sk-test-DUMMY" at the secrets path
WHEN all output from provision-agent.sh and the content of osgania-agent.service AND the wrapper agent-run.sh are inspected
THEN neither the value "sk-test-DUMMY" nor any substring that looks like an API key appears in any output, the unit file, or the wrapper source
 AND LoadCredential references the path /etc/osgania/secrets/anthropic-api-key (not the key value)
 AND (scope note: this tests FILES + stdout only; the wrapper deliberately places the key in the LIVE process env at runtime — the accepted ADR-6 exposure, not a file leak)
```

#### HA-08-S4 — Wrapper loads ANTHROPIC_API_KEY from CREDENTIALS_DIRECTORY and forwards "$@" (HOST-SAFE)

**Requirement**: HA-08.4, HA-05.1

> Replaces the obsolete apiKeyHelper read scenario (the helper is abandoned — ADR-1 superseded by ADR-6). The original `runuser -u aios -- env CREDENTIALS_DIRECTORY=/etc/osgania/secrets …` form was UNFAITHFUL: `/etc/osgania/secrets` is `root:root 0700`, so `aios` cannot read it directly — only systemd's `LoadCredential` makes an aios-readable tmpfs copy. The faithful end-to-end key hand-off is verified via the REAL systemd unit (HA-13-S1 + Phase-4 auth check). This scenario verifies the wrapper's read+export logic in isolation.

```
GIVEN a temp directory <creds> containing a file `anthropic-api-key` with dummy content "sk-test-DUMMY-VALUE"
  AND a test harness that runs the wrapper with its final `exec /usr/bin/claude "$@"` replaced by a probe that prints ANTHROPIC_API_KEY and the forwarded args (e.g. via `sed` substitution — no real CLI, no network)
WHEN the wrapper logic is run as `env CREDENTIALS_DIRECTORY=<creds> <wrapper> -p`
THEN exit code is 0
 AND the probe observed ANTHROPIC_API_KEY == "sk-test-DUMMY-VALUE"
 AND the forwarded args are exactly "-p" ("$@" preserved)

GIVEN the key file content is "  sk-test-DUMMY-VALUE\r\n" (leading spaces + CRLF — a Windows/web-console paste)
WHEN the wrapper logic is run
THEN exit code is 0
 AND the probe observed ANTHROPIC_API_KEY == "sk-test-DUMMY-VALUE" (whitespace + CR stripped, HA-05.1a)

GIVEN the key file is empty or whitespace-only
WHEN the wrapper logic is run
THEN it aborts non-zero (fail closed — does NOT export an empty key)

GIVEN CREDENTIALS_DIRECTORY is NOT set
WHEN the wrapper is run
THEN it aborts non-zero with a message naming CREDENTIALS_DIRECTORY (the `:?` guard)
```

*(Verifies the wrapper sources the key from `$CREDENTIALS_DIRECTORY`, exports it as `ANTHROPIC_API_KEY`, forwards `"$@"`, and fails closed when the credential dir is missing. The real auth hand-off — systemd LoadCredential → tmpfs readable by aios → CLI authenticates — is exercised by HA-13-S1 via the real unit, not by an ad-hoc harness.)*

---

### HA-09 — Live defense-in-depth probe (guardia denies under bypass)

#### HA-09-S1 — Defense-in-depth status is one of VERIFIED/UNVERIFIED/FAILED and always recorded (LINUX-ROOT)

**Requirement**: HA-09.2, HA-09.3

```
GIVEN provision-agent.sh has run to completion
WHEN the provisioning summary output is examined
THEN it contains one of:
  "Defense-in-depth: VERIFIED"   (permissionMode=default under --dangerously-skip-permissions — the managed disableBypassPermissionsMode neutralized the bypass flag)
  "Defense-in-depth: UNVERIFIED" (no stream-json init event — key/CLI/wrapper absent or an auth error)
  "Defense-in-depth: FAILED"     (permissionMode=bypassPermissions — the CLI honored the bypass flag; managed disable not in effect)
AND in no case does the output claim VERIFIED with an absent/empty permissionMode (a missing init event MUST map to UNVERIFIED, not VERIFIED)
AND the probe prints no secret (the oracle is the CLI-reported permissionMode, captured to a shell variable, never the journal)
```

#### HA-09-S2 — FAILED result causes non-zero exit (LINUX-ROOT / LIVE-KEY)

**Requirement**: HA-09.4

```
GIVEN the installed CLI honored --dangerously-skip-permissions (permissionMode=bypassPermissions — managed disableBypassPermissionsMode NOT in effect)
WHEN provision-agent.sh runs the defense-in-depth probe
THEN the probe is classified FAILED
 AND provision-agent.sh exits with a non-zero exit code
 AND stderr surfaces the FAILED finding prominently (recording the observed permissionMode, never a secret)
 (note: an absent/empty permissionMode is UNVERIFIED, not FAILED — only an explicit bypassPermissions is FAILED)
```

#### HA-09-S3 — UNVERIFIED when key absent (LINUX-ROOT, no LIVE-KEY)

**Requirement**: HA-09.2, HA-09.3

```
GIVEN /etc/osgania/secrets/anthropic-api-key does NOT exist (the agent cannot authenticate, so .probe-alive is never written)
WHEN provision-agent.sh runs the defense-in-depth probe step
THEN the result is classified UNVERIFIED (not FAILED, not VERIFIED) — .probe-alive absent
 AND provision-agent.sh exits 0 (key absence is a residual risk, not a provisioning error)
 AND the summary records "Defense-in-depth: UNVERIFIED" with a note that the key was absent
```

---

### HA-10 — Idempotency

#### HA-10-S1 — Re-run on 2a box exits 0 with no duplicate units (LINUX-ROOT)

**Requirement**: HA-10.1, HA-10.2

```
GIVEN provision-agent.sh has been run once to completion
WHEN provision-agent.sh is run a second time
THEN exit code is 0
 AND `systemctl list-unit-files | grep osgania-agent` shows exactly one .service and one .timer entry
 AND `claude --version` still returns "2.1.153" (CLI not reinstalled)
 AND `stat -c '%a' /opt/osgania/client` returns 700 (mode unchanged)
 AND `stat -c '%U:%G %a' /opt/osgania/platform/bin/agent-run.sh` returns "root:root 755" (wrapper mode re-asserted)
 AND `/etc/claude-code/managed-settings.json` is byte-identical to its pre-run content (2a never writes it; `jq -e 'has("apiKeyHelper")'` exits non-zero)
```

#### HA-10-S2 — Re-run does not corrupt audit log or +a flag (LINUX-ROOT)

**Requirement**: HA-10.3, HA-11.2

```
GIVEN provision-agent.sh has run once
  AND /var/log/osgania/audit.jsonl has inode N with content C and chattr +a
WHEN provision-agent.sh is run a second time
THEN `stat -c %i /var/log/osgania/audit.jsonl` returns N (same inode)
 AND the file content is unchanged
 AND `lsattr /var/log/osgania/audit.jsonl` still shows the "a" flag
```

---

### HA-11 — Slice-1 invariants preserved

#### HA-11-S1 — aios account intact after 2a (LINUX-ROOT)

**Requirement**: HA-11.1

```
GIVEN provision-agent.sh has run to completion
WHEN `getent passwd aios` is queried
THEN UID is 9001
 AND GID is 9001
 AND shell is /usr/sbin/nologin
 AND home is /nonexistent

WHEN `id -nG aios` is run
THEN output does NOT contain "sudo"
 AND output does NOT contain "admin"
```

#### HA-11-S2 — Secrets dir mode intact after 2a (LINUX-ROOT)

**Requirement**: HA-11.1, HA-11.3

```
GIVEN provision-agent.sh has run to completion
WHEN `stat -c '%U:%G %a' /etc/osgania/secrets` is run
THEN the output is "root:root 700"
```

#### HA-11-S3 — audit +a flag intact after 2a (LINUX-ROOT)

**Requirement**: HA-11.1, HA-11.2

```
GIVEN provision-agent.sh has run to completion
WHEN `lsattr /var/log/osgania/audit.jsonl` is run
THEN the output contains the "a" flag
```

---

### HA-12 — Rollback (scenarios)

#### HA-12-S1 — Rollback returns box to Slice-1 end-state (OPERATOR-MANUAL)

**Requirement**: HA-12.1, HA-12.2, HA-12.3

```
GIVEN provision-agent.sh has run to completion (box is in 2a end-state)
WHEN an operator performs rollback steps HA-12.1–HA-12.3 in order:
  1. systemctl disable --now osgania-agent.timer osgania-agent.service
  2. rm /etc/systemd/system/osgania-agent.service /etc/systemd/system/osgania-agent.timer && systemctl daemon-reload
  3. rm -f /opt/osgania/platform/bin/agent-run.sh   (managed-settings.json needs NO change — 2a never modified it)
  4. npm uninstall -g @anthropic-ai/claude-code
  5. (optional) apt-mark unhold nodejs npm
  6. rm -rf /opt/osgania/client/
THEN `systemctl list-unit-files | grep osgania-agent` returns no entries
 AND `jq -e 'has("apiKeyHelper")' /etc/claude-code/managed-settings.json` exits non-zero (the key was never present — 2a never modified the file)
 AND `jq .` /etc/claude-code/managed-settings.json exits 0 AND all R9-R12 keys are still present (deny[], allow, defaultMode, disableBypassPermissionsMode, allowManagedHooksOnly, hooks)
 AND `getent passwd aios` returns UID 9001, GID 9001, shell /usr/sbin/nologin, home /nonexistent
 AND `lsattr /var/log/osgania/audit.jsonl` still shows the "a" flag
 AND /etc/osgania/secrets/ mode is root:root 0700
 AND no chattr -a was run on the audit log
 AND no R9-R12 key was modified
```

*(This scenario requires operator execution on the target box and cannot be automated in bats CI.
Assertions MUST be verified manually by the operator running the steps above and checking the stated conditions.)*

---

### HA-13 — Agent run integration

#### HA-13-S1 — Provisioned audit log exists and is append-only (+a) (LINUX-ROOT)

**Requirement**: HA-06.1, HA-06.7, platform-security-core R5.5

> **Re-tiered (Phase-4):** the audit-RECORD append is exercised host-safe by `camara.bats` CA-01/CA-02 (feeding `camara.sh` a PostToolUse event). It CANNOT be driven end-to-end through a live agent, because managed-settings `disableBypassPermissionsMode: "disable"` keeps the headless agent in `permissionMode=default`, where every Bash tool call DEFERS (no approver in `-p`) and `camara` (PostToolUse) never fires — so no live tool call can append a record. This scenario therefore verifies the STRUCTURAL guarantee (no live key required).

```
GIVEN provision-agent.sh has run to completion on a Slice-1 box
THEN exit code is 0
 AND /var/log/osgania/audit.jsonl exists
 AND `lsattr /var/log/osgania/audit.jsonl` shows the "a" (append-only) flag
     (set by Slice-1, asserted by provision-agent.sh preconditions)
```

---

### HA-15 — guardia env-dump denial

_All HOST-SAFE: pure `guardia.sh` STDIN→STDOUT, same harness as the existing guardia scenarios. Encoded in `tests/guardia.bats`._

#### HA-15-S1 — Deny the env-dump verbs (HOST-SAFE)

**Requirement**: HA-15.1, HA-15.4

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "env"
  "printenv"
  "printenv ANTHROPIC_API_KEY"
  "set"
  "declare"
  "typeset"
  "declare -p"
  "typeset -p"
  "local -p"
  "export -p"
  "compgen -v"
  "compgen -e"
  "compgen -A variable"
  "compgen -A export"
  "env | grep ANTHROPIC"
THEN for EACH, guardia emits permissionDecision "deny"
 AND permissionDecisionReason matches "^\[guardia\] denied: env-dump"
```

#### HA-15-S2 — Deny reads of /proc/<pid>/environ (HOST-SAFE)

**Requirement**: HA-15.2, HA-15.4

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "cat /proc/self/environ"
  "cat /proc/$$/environ"
  "cat /proc/$BASHPID/environ"
  "cat /proc/${$}/environ"
  "xxd /proc/1234/environ"
  "tr '\\0' '\\n' < /proc/self/environ"
THEN for EACH, guardia emits permissionDecision "deny"
 AND permissionDecisionReason matches "^\[guardia\] denied: env-dump"
```

#### HA-15-S3 — MUST NOT false-positive the benign forms (HOST-SAFE, load-bearing)

**Requirement**: HA-15.3

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "set -e"
  "set -euo pipefail"
  "set -o pipefail"
  "set +e"
  "declare -i count=0"
  "declare -a items"
  "declare x=1"
  "export FOO=bar"
  "export PATH=\"$PATH:/usr/local/bin\""
  "env FOO=bar make build"
  "env NODE_ENV=production node app.js"
  "env -u FOO make build"
  "env -i /bin/sh -c true"
THEN for EACH, guardia emits permissionDecision "defer" (NOT deny)
```

#### HA-15-S4 — env-dump category does not alter R2.1–R2.6 (HOST-SAFE regression)

**Requirement**: HA-15.5

```
GIVEN the full pre-existing guardia scenario set (sudo, curl/wget, rm -rf, disk-wipe, secrets-path, platform-path deny cases + the existing defer cases)
WHEN guardia.sh (with the env-dump category added) is run against each
THEN every pre-existing scenario produces the SAME decision (deny/defer) and category it did before
 AND no env-dump rule shadows or suppresses an R2.1–R2.6 deny
```

#### HA-15-S5 — Interpreters and bare variable reads are NOT denied (HOST-SAFE, HA-15.6 negative scope)

**Requirement**: HA-15.6

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "python3 -c 'import os; print(os.environ[\"ANTHROPIC_API_KEY\"])'"
  "node -e 'console.log(process.env.ANTHROPIC_API_KEY)'"
  "awk 'BEGIN{print ENVIRON[\"PATH\"]}'"
  "echo \"$ANTHROPIC_API_KEY\""
  "printf '%s' \"$ANTHROPIC_API_KEY\""
THEN for EACH, guardia emits permissionDecision "defer" (NOT deny)
 (these are the knowingly-uncovered bypasses — denying them would break the agent's core tooling; HA-15.6)
```

#### HA-15-S6 — bash-native /dev/tcp and /dev/udp are denied (HOST-SAFE)

**Requirement**: HA-15.5a

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "exec 3<>/dev/tcp/example.com/443"
  "cat </dev/tcp/1.2.3.4/80"
  "echo x >/dev/udp/8.8.8.8/53"
THEN for EACH, guardia emits permissionDecision "deny"
 AND permissionDecisionReason matches "^\[guardia\] denied: net-builtin"
```

#### HA-15-S7 — env-dump step does not shadow inherited deny reasons (HOST-SAFE, ICP-01 ordering)

**Requirement**: HA-15.5

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "cat /proc/self/environ > /opt/osgania/platform/x"   (matches BOTH platform R2.6 AND env-dump path)
  "printenv && cat /etc/osgania/secrets/x"             (matches BOTH env-dump AND secrets R2.5)
THEN for EACH, guardia emits permissionDecision "deny"
 AND the reason is the INHERITED category ("platform" / "secrets"), NOT "env-dump"
     (proves the env-dump step is placed AFTER R2.5/R2.6 — first-match-wins preserves R2.x reason attribution)
```

#### HA-15-S8 — MUST NOT false-positive filenames or quoted-arg text (HOST-SAFE, load-bearing, Phase-3)

**Requirement**: HA-15.3

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "bash printenv.sh"
  "cat printenv.md"
  "./printenv.sh"
  "vim scripts/printenv.sh"
  "node printenv.js"
  "echo \"use export -p to list\""
  "git commit -m \"add export -p support\""
  "echo \"run: typeset -p to inspect\""
  "git commit -m \"document declare -p usage\""
  "cat myprintenv.md"
  "cat printenv_helper.md"
  "env --unset=FOO bash"
  "env --ignore-environment make"
THEN for EACH, guardia emits permissionDecision "defer" (NOT deny)
 (a dump verb appearing in a FILENAME token or inside QUOTED argument text is not a dump; the
  Phase-3 blind attack found the printenv and -p matchers firing on these — denying them breaks the agent)
```

#### HA-15-S9 — Deny env-dump verb cheap-variants: redirect / cluster / readonly / --null (HOST-SAFE, Phase-3)

**Requirement**: HA-15.1, HA-15.4

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "set > /tmp/x"
  "set >> /tmp/x"
  "declare > /tmp/x"
  "typeset > /tmp/x"
  "declare -px"
  "export -px"
  "declare -pf"
  "declare -ip"
  "readonly -p"
  "compgen -ve"
  "compgen -ev"
  "env --null"
THEN for EACH, guardia emits permissionDecision "deny"
 AND permissionDecisionReason matches "^\[guardia\] denied: env-dump"
 (redirect-to-file dumps, fused -p flag clusters, readonly -p, compgen -ve/-ev clusters, and the
  env --null synonym of -0 are all cheap variants of already-covered verbs — closed in Phase-3)
```

#### HA-15-S10 — Deny /proc environ indirection: $VAR / thread-self / task (HOST-SAFE, Phase-3)

**Requirement**: HA-15.2, HA-15.4

```
GIVEN guardia.sh receives a Bash tool call whose tool_input.command is each of, separately:
  "cat /proc/$PPID/environ"
  "cat /proc/$PID/environ"
  "cat /proc/$mypid/environ"
  "cat /proc/self/task/123/environ"
  "cat /proc/1/task/1/environ"
  "cat /proc/thread-self/environ"
THEN for EACH, guardia emits permissionDecision "deny"
 AND permissionDecisionReason matches "^\[guardia\] denied: env-dump"
 (bare-variable pid forms, the thread-self magic symlink, and the per-thread /task/<tid>/ alias name
  the same /proc/<pid>/environ file the hook already covers — closed in Phase-3)
```

---

## Scenario-to-requirement map

| Scenario | Requirement | Testability |
|----------|-------------|-------------|
| HA-01-S1 | HA-01.1, HA-01.2 | HOST-SAFE |
| HA-01-S2 | HA-01.1, HA-01.2 | HOST-SAFE |
| HA-01-S3 | HA-01.4 | HOST-SAFE |
| HA-02-S1 | HA-02.1, HA-02.2 | LINUX-ROOT |
| HA-02-S2 | HA-02.3 | LINUX-ROOT |
| HA-02-S3 | HA-02.1, HA-02.4 | HOST-SAFE |
| HA-03-S1 | HA-03.1, HA-03.2 | LINUX-ROOT |
| HA-03-S2 | HA-03.3 | HOST-SAFE |
| HA-03-S3 | HA-03.3 | HOST-SAFE |
| HA-03-S4 | HA-03.4 | LINUX-ROOT |
| HA-04-S1 | HA-04.1, HA-04.2 | LINUX-ROOT |
| HA-04-S2 | HA-04.2, HA-10.1 | LINUX-ROOT |
| HA-05-S1 | HA-05.1, HA-05.2 | LINUX-ROOT |
| HA-05-S2 | HA-05.3, HA-05.5, HA-05.7 | HOST-SAFE |
| HA-05-S3 | HA-05.6 | HOST-SAFE |
| HA-05-S4 | HA-05.1, HA-05.4, HA-06.2 | HOST-SAFE |
| HA-05-S5 | HA-14.2 | HOST-SAFE |
| HA-06-S1 | HA-06.1, HA-06.4, HA-06.7 | HOST-SAFE |
| HA-06-S2 | HA-06.2 | HOST-SAFE |
| HA-06-S3 | HA-06.3 | HOST-SAFE |
| HA-06-S4 | HA-06.1, HA-06.5 | LINUX-ROOT |
| HA-06-S5 | HA-14.2 | HOST-SAFE |
| HA-06-S6 | HA-06.7 | LINUX-ROOT |
| HA-07-S1 | HA-07.1, HA-07.2 | HOST-SAFE |
| HA-07-S2 | HA-06.6, HA-07.3 | LINUX-ROOT |
| HA-08-S1 | HA-06.4, HA-08.3 | HOST-SAFE |
| HA-08-S2 | HA-08.6, HA-11.1 | HOST-SAFE/LINUX-ROOT |
| HA-08-S3 | HA-08.1, HA-08.5 | HOST-SAFE/LINUX-ROOT |
| HA-08-S4 | HA-08.4, HA-05.1 | HOST-SAFE |
| HA-09-S1 | HA-09.2, HA-09.3 | LINUX-ROOT |
| HA-09-S2 | HA-09.4 | LINUX-ROOT/LIVE-KEY |
| HA-09-S3 | HA-09.2, HA-09.3 | LINUX-ROOT |
| HA-10-S1 | HA-10.1, HA-10.2 | LINUX-ROOT |
| HA-10-S2 | HA-10.3, HA-11.2 | LINUX-ROOT |
| HA-11-S1 | HA-11.1 | LINUX-ROOT |
| HA-11-S2 | HA-11.1, HA-11.3 | LINUX-ROOT |
| HA-11-S3 | HA-11.1, HA-11.2 | LINUX-ROOT |
| HA-12-S1 | HA-12.1, HA-12.2, HA-12.3 | OPERATOR-MANUAL |
| HA-13-S1 | HA-06.1, HA-06.7, PSC R5.5 | LINUX-ROOT |
| HA-15-S1 | HA-15.1, HA-15.4 | HOST-SAFE |
| HA-15-S2 | HA-15.2, HA-15.4 | HOST-SAFE |
| HA-15-S3 | HA-15.3 | HOST-SAFE |
| HA-15-S4 | HA-15.5 | HOST-SAFE |
| HA-15-S5 | HA-15.6 | HOST-SAFE |
| HA-15-S6 | HA-15.5a | HOST-SAFE |
| HA-15-S7 | HA-15.5 | HOST-SAFE |
| HA-15-S8 | HA-15.3 | HOST-SAFE |
| HA-15-S9 | HA-15.1, HA-15.4 | HOST-SAFE |
| HA-15-S10 | HA-15.2, HA-15.4 | HOST-SAFE |

**Total scenarios: 49** (was 39; +10 HA-15 env-dump/net-builtin/ordering/negative-scope/Phase-3-hardening; HA-08-S4 retiered LIVE-KEY→HOST-SAFE; HA-13-S1 re-tiered LIVE-KEY→LINUX-ROOT in Phase-4; no scenario removed). Tallied from the map above:
- **HOST-SAFE (pure): 27** — HA-01-S1/S2/S3, HA-02-S3, HA-03-S2/S3, HA-05-S2/S3/S4/S5, HA-06-S1/S2/S3/S5, HA-07-S1, HA-08-S1/S4, HA-15-S1..S10
- **HOST-SAFE ∪ LINUX-ROOT (dual): 2** — HA-08-S2, HA-08-S3 (run host-safe; also have a LINUX-ROOT mutation path)
- **LINUX-ROOT (pure): 18** — HA-02-S1/S2, HA-03-S1/S4, HA-04-S1/S2, HA-05-S1, HA-06-S4/S6, HA-07-S2, HA-09-S1/S3, HA-10-S1/S2, HA-11-S1/S2/S3, HA-13-S1
- **LINUX-ROOT + LIVE-KEY: 1** — HA-09-S2 (+ contingent paths in HA-08-S2/S3/HA-09-S1 when a key is present)
- **OPERATOR-MANUAL: 1** — HA-12-S1

(27 + 2 + 18 + 1 + 1 = 49.)

---

## Assumptions (none open — all resolved by design)

| # | Was open question | Design resolution | Risk |
|---|-------------------|-------------------|------|
| A1 | API-key delivery to non-root `aios` | **PIVOT:** apiKeyHelper unusable (CLI 2.1.153 cannot spawn it as `aios`); deliver `ANTHROPIC_API_KEY` via an `ExecStart` wrapper (ADR-6, supersedes ADR-1) | Resolved; **residual: key in process env** — bounded by tenancy + 2b egress (K-2 / ADR-6) |
| A2 | Exact CLI version pin | `@anthropic-ai/claude-code@2.1.153` (ADR-2) | Resolved |
| A3 | systemd unit shape | `Type=oneshot` + `.timer`, placeholder cadence; `ExecStart`=wrapper (ADR-3 amended) | Resolved |
| A4 | StateDirectory / HOME | `StateDirectory=osgania-agent`, `HOME=%S/osgania-agent`, `XDG_CONFIG_HOME=%S/osgania-agent` (ADR-4) | Resolved |
| A5 | Live probe semantics | **REWORKED:** mode-lock may be a no-op; the probe verifies **guardia denies a forbidden command under `--dangerously-skip-permissions`** (ADR-5) | Resolved; degraded Layer-3 is an accepted residual (PSC R10.3) |
| A6 | env-key exposure mitigation | guardia env-dump denial (ADR-7 / HA-15) — a speed-bump | Resolved; **NOT a hard boundary** — interpreters bypass it; the real exfil wall is the 2b egress firewall |

---

## Non-goals (out of scope — reiterated for contract clarity)

- UFW egress firewall — 2b
- SSH sealing of `aios` — 2b
- unattended-upgrades — 2b
- logrotate under `chattr +a` — 2b
- Docker/Coolify coexistence — 2b
- Tightening to B3 systemd hardening — future change (gated on profiling)
- TPM-encrypted key at rest (`LoadCredentialEncrypted`) — D5 v2 future milestone
- Timer cadence final value — autonomy-ladder change
- Modifying `platform-security-core` archived spec TEXT — intentionally not done (live-artifact pattern: HA-15 extends the live `guardia.sh` and `managed-settings.json` is left untouched, but the archived PSC spec is never rewritten — ADR-6/ADR-7 rationale)
- Blocking interpreters (`python`/`node`/etc.) from reading their own environment — explicitly out of scope (HA-15.6); containment of key exfil is single-tenancy + the 2b egress firewall
- MCP least-privilege wiring — not exercised by 2a
- Any change to `vps-provisioning-base` or `platform-security-core` deny rules, hooks, `disableBypassPermissionsMode`, `chattr +a` arming, or `CAP_LINUX_IMMUTABLE`
