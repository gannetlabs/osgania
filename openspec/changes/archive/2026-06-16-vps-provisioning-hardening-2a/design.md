# Design: vps-provisioning-hardening-2a ("Run the agent")

**Change**: `vps-provisioning-hardening-2a` (Slice 2, sub-slice 2a)
**Project**: osgania
**Artifact store**: openspec
**Date**: 2026-06-15
**Status**: design
**Depends on**: proposal.md (APPROVED, 5 open questions), explore.md, `vps-provisioning-base` (ARCHIVED spec + design), `platform-security-core` (R5.5, R9–R12 deny/hook contract). The decided literals below are AUTHORITATIVE — the spec MUST copy them verbatim (drift gate); if a value looks wrong, fix it HERE first.

> 2a extends the running box with a Node/CLI runtime + a hardened systemd launch unit + API-key delivery (via a systemd `LoadCredential` wrapper) + a live defense-in-depth probe. It does NOT alter any Slice-1 / `platform-security-core` deny rule, hook, `disableBypassPermissionsMode`, `chattr +a` arming, or `CAP_LINUX_IMMUTABLE`.

---

## PIVOT (2026-06-16) — apiKeyHelper abandoned, key now delivered via `ANTHROPIC_API_KEY`

VPS verification of the `apiKeyHelper` design (ADR-1) exposed a hard blocker: **Claude Code CLI 2.1.153 cannot spawn the `apiKeyHelper` when the agent runs as the unprivileged `aios` user** ("apiKeyHelper failed: exited undefined" → 401 → "Not logged in"). It works as root. The failure was diagnosed exhaustively (shell, config dir, PATH, perms, key validity, network all ruled out) and confirmed against official docs/issues — there is **no fix**; Anthropic's recommended headless/non-root auth is the `ANTHROPIC_API_KEY` env var, which is confirmed working as `aios` on the VPS. Full diagnosis: engram `architecture/apikeyhelper-aios-auth-blocker`.

**Decision (user-approved):** deliver the key as `ANTHROPIC_API_KEY`, exported by a tiny root-owned `ExecStart` wrapper that reads it from the systemd `LoadCredential` tmpfs at runtime. This reverses the apiKeyHelper + `UnsetEnvironment=ANTHROPIC_API_KEY` approach and accepts a bounded, mitigated security trade-off (the key now lands in the agent process environment).

| Old (superseded) | New (authoritative) |
|------------------|---------------------|
| **ADR-1** apiKeyHelper live-artifact extension | **SUPERSEDED → ADR-6**: `ANTHROPIC_API_KEY` via wrapper; managed-settings.json is now **not modified by 2a at all** |
| **ADR-3** `ExecStart=/usr/bin/claude -p`; `UnsetEnvironment=ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN` | **AMENDED**: `ExecStart=/opt/osgania/platform/bin/agent-run.sh -p`; `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` only |
| **ADR-5** Layer-3 probe = CLI refuses `--dangerously-skip-permissions` | **REWORKED**: probe = guardia (Layer 2) still **denies** a forbidden command under `--dangerously-skip-permissions` (defense-in-depth; mode-lock may be a no-op per PSC R10.3) |
| *(none)* | **ADR-7 (NEW)**: guardia env-dump denial — a speed-bump mitigation for the env-key exposure |

The ADR bodies below are authoritative. Where ADR-1/3/5 text conflicts with the pivot, ADR-6/ADR-7 and the amended ADR-3/ADR-5 win.

---

## Quick path (the resolved decisions, one literal each — post-pivot)

| # | Open question | Decision (concrete literal) |
|---|---------------|------------------------------|
| ~~ADR-1~~ | ~~apiKeyHelper boundary (D3)~~ | **SUPERSEDED by ADR-6.** apiKeyHelper cannot spawn as non-root `aios` on CLI 2.1.153 (no fix). 2a now adds NOTHING to managed-settings.json; it must verify R9–R12 are untouched. |
| ADR-2 | Pinned CLI version literal | **`@anthropic-ai/claude-code@2.1.153`** (exact pin == the Slice-1 floor; single source of truth). Verified live via `claude --version` parsed `>= 2.1.153`. |
| ADR-3 (amended) | systemd unit shape | **`Type=oneshot` `osgania-agent.service` + `osgania-agent.timer`.** Placeholder cadence `OnCalendar=daily` + `RandomizedDelaySec=3600` + `Persistent=true` — DEFERRED to the autonomy-ladder change (marked in-file). **POST-PIVOT:** `ExecStart=/opt/osgania/platform/bin/agent-run.sh -p` (the wrapper, not `claude` directly); `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` only (`ANTHROPIC_API_KEY` is now set by the wrapper, so it MUST NOT be unset). Full directive set below. |
| ADR-4 | StateDirectory / HOME | **`StateDirectory=osgania-agent`** → `/var/lib/osgania-agent` (`aios:aios 0700`, systemd-created). Set `Environment=HOME=%S/osgania-agent`, `Environment=XDG_CONFIG_HOME=%S/osgania-agent`, `Environment=XDG_CACHE_HOME=%S/osgania-agent`, and `Environment=XDG_DATA_HOME=%S/osgania-agent` so the homeless `aios` gets a writable config/cache/data tree under `ProtectSystem=strict`. |
| ADR-5 (reworked) | Live defense-in-depth probe | The mode-lock (`disableBypassPermissionsMode`) may be a no-op on 2.1.153 (PSC R10.3 / #44642); the real guarantee is that **guardia (Layer 2) still denies under bypass**. Probe: run a **known-denied** command (e.g. `curl`) under `--dangerously-skip-permissions` and observe guardia's veto. **VERIFIED** = the denied command is BLOCKED; **UNVERIFIED** = key/CLI absent (probe could not run); **FAILED** = the denied command EXECUTES (Layer 2 broken). *(Navigational index only — the ADR-5 body below is authoritative.)* |
| ADR-6 (new) | API-key delivery (post-pivot) | **`ANTHROPIC_API_KEY` via a root-owned `ExecStart` wrapper** `/opt/osgania/platform/bin/agent-run.sh` (`root:root 0755`): reads + whitespace-strips the key from `$CREDENTIALS_DIRECTORY`, exports `ANTHROPIC_API_KEY`, then `exec /usr/bin/claude "$@"` *(condensed — see ADR-6 body for the authoritative `set -euo pipefail` + `:?`-guarded + `tr`-normalized form)*. Key injected via `LoadCredential` (tmpfs, never in the unit file). |
| ADR-7 (new) | guardia env-dump denial | Add a denylist category to `guardia.sh` denying `env`/`printenv`/`set`/`declare -p`/`export -p`/`compgen -v` and reads of `/proc/<pid>/environ`. A **speed-bump** mitigation for the env-key exposure (PSC already frames guardia as a speed-bump, not a sandbox) — NOT a hard boundary. |

The single agent-run flow (config rule: sequence diagram for agent-to-app) is in **Sequence diagram**.

---

## Technical Approach

2a adds a second provisioning module (`scripts/provision-agent.sh`, paired `tests/provision-agent.bats`, the launch wrapper `platform/bin/agent-run.sh`, and the two unit templates) that runs AFTER Slice-1 `provision.sh` on a Slice-1-provisioned box. It is the sanctioned mutator of the launch layer, exactly as Slice-1 is the sanctioned mutator of the OS baseline. Key delivery is per-box file-based (D5=v1, engram `architecture/onboarding-secrets`): one revocable static key per box at `/etc/osgania/secrets/anthropic-api-key`, injected into the unit's private `LoadCredential` tmpfs (never in the unit file or any versioned file), then surfaced to the CLI as `ANTHROPIC_API_KEY` by a root-owned `ExecStart` wrapper (ADR-6, post-pivot). **Post-pivot the key DOES land in the agent process environment** — a bounded, mitigated trade-off (see ADR-6 residual-risk analysis and ADR-7 env-dump speed-bump); the original "never through the process environment" goal (apiKeyHelper) was abandoned because the CLI cannot spawn the helper as non-root `aios`.

---

## Architecture Decisions

### ADR-1 — apiKeyHelper as a live-artifact extension (Option A), not an archived-spec edit  — ⚠️ SUPERSEDED BY ADR-6 (2026-06-16)

> **SUPERSEDED.** This ADR is retained for decision history only. Claude Code CLI 2.1.153 **cannot spawn `apiKeyHelper` when the agent runs as the unprivileged `aios` user** (works as root; "exited undefined" → 401). Diagnosed exhaustively and confirmed against official docs — no fix (engram `architecture/apikeyhelper-aios-auth-blocker`). Key delivery now uses `ANTHROPIC_API_KEY` via a wrapper — see **ADR-6**. **2a no longer modifies `/etc/claude-code/managed-settings.json` at all**; it only verifies R9–R12 are intact (the structural invariant below is repurposed from "after the upsert" to "2a made no change"). `apiKeyHelper` may return as a future hardening if Anthropic fixes non-root spawn.

**Choice.** Append exactly ONE top-level sibling key to the LIVE `/etc/claude-code/managed-settings.json`:
`"apiKeyHelper": "/opt/osgania/platform/bin/anthropic-key.sh"`. The helper:

```sh
#!/usr/bin/env bash
# /opt/osgania/platform/bin/anthropic-key.sh — root:root 0755
set -euo pipefail
cat "${CREDENTIALS_DIRECTORY}/anthropic-api-key"
```

Installed `install -o root -g root -m 0755` (root-owned, NOT writable by aios; aios needs only r-x). The edit is a presence-guarded `jq` upsert against the live file, then `jq .` re-validation:
`jq --arg h /opt/osgania/platform/bin/anthropic-key.sh '.apiKeyHelper = $h' file` (idempotent — re-running sets the same value, never duplicates).

**Alternatives considered.** Option B — open a separate `platform-security-core` amendment first, then depend on it. Rejected: serializes 2a behind a second change for a single key on a single-purpose box.

**Rationale.** `platform-security-core` is archived as a *spec/design contract*, but `managed-settings.json` is a *live operator artifact* the box owns and provisioning is the sanctioned mutator of — the exact line Slice-1 ADR-2 drew. The helper + the unit's `LoadCredential` are one inseparable delivery mechanism, so coupling them in 2a is coherent. **Normative guard (spec MUST encode):** the edit MUST be a pure addition; a structural test MUST assert that after the edit ALL of `permissions.deny[]` (6 entries), `permissions.allow == []`, `permissions.defaultMode == "default"`, `permissions.disableBypassPermissionsMode == "disable"`, `allowManagedHooksOnly == true`, and both hook registrations (guardia PreToolUse/Bash/timeout 10, camara PostToolUse/*/timeout 10) are present and byte-for-byte unchanged. **Archived `platform-security-core` spec text is NOT rewritten;** 2a's spec carries the cross-reference note ("extends managed-settings.json with apiKeyHelper; MUST NOT alter any R9–R12 key").

### ADR-2 — Pin `@anthropic-ai/claude-code@2.1.153`

**Choice.** `npm install -g @anthropic-ai/claude-code@2.1.153` (exact, not floating). The pinned literal `2.1.153` is the single source of truth, recorded in provisioning output. Provision verifies by parsing `claude --version` and asserting `>= 2.1.153`.

**Alternatives considered.** "Latest stable at provision time" — rejected: non-reproducible across the fleet, breaks the drift gate. A version below 2.1.153 — rejected: it is the Slice-1 floor, 61 versions past the v2.1.92 mode-lock no-op bug (#44642).

**Rationale.** Equals the Slice-1 verified floor → fleet-consistent and reproducible. Runtime drift is blocked by `Environment=DISABLE_AUTOUPDATER=1` (unit) + `apt-mark hold nodejs npm` (the npm-global CLI is not an apt package, so the hold protects the runtime under it). Re-install only when running version ≠ pin.

### ADR-3 — `Type=oneshot` service + `.timer`, full B2+ directive set

**Choice.** Two unit files written declaratively to `/etc/systemd/system/`, then `systemctl daemon-reload` + `systemctl enable --now osgania-agent.timer`:

```ini
# osgania-agent.service
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
# --- B2+ hardening ---
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
# MemoryDenyWriteExecute deliberately EXCLUDED — incompatible with Node V8 JIT
# LimitCORE=0 — no core dumps (a core would contain ANTHROPIC_API_KEY post-pivot; TMH-5)
```

```ini
# osgania-agent.timer  (cadence is a PLACEHOLDER — owned by the autonomy-ladder change)
[Unit]
Description=OSGANIA agent cadence (PLACEHOLDER — autonomy-ladder owns the real schedule)

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

**Alternatives considered.** Long-running `Type=simple` service — rejected: the product model is a headless cadence (L3), not a daemon; oneshot+timer matches and is cheaper to reason about. `SystemCallFilter=@system-service` allowlist — rejected: the agent legitimately spawns subprocesses via the Bash tool; an allowlist would break them, so deny-form (`~…`) only. `MemoryDenyWriteExecute=yes` — rejected: crashes V8 JIT (the agent would not start).

**Rationale (non-obvious choices).** `CapabilityBoundingSet=` (empty) drops ALL capabilities — the agent needs none (no bind <1024, no chown, no `CAP_LINUX_IMMUTABLE`); this satisfies the proposal's "MUST NOT need/clear CAP_LINUX_IMMUTABLE" because the host already armed `+a` (R7.5) and append works for an unprivileged user with zero caps. `RestrictAddressFamilies` keeps INET/INET6 (HTTPS to the API) + UNIX (local IPC) and drops exotic families. **AF_NETLINK caveat (SC-3, Phase-4 gate):** glibc `getaddrinfo()`/NSS sometimes opens an `AF_NETLINK` (NETLINK_ROUTE) socket for source-address selection; blocking it usually degrades gracefully but on some Node/resolver stacks surfaces as an intermittent `EAFNOSUPPORT`/DNS failure at startup that LOOKS like a network problem. We deliberately do NOT widen the set pre-emptively (NETLINK is broad); instead the real-unit VPS verification MUST confirm the service reaches the API with no `getaddrinfo`/`EAFNOSUPPORT` errors (HA-06-S6), and `AF_NETLINK` is added ONLY if that test shows it is needed. `ProtectSystem=strict` makes the entire FS read-only except `ReadWritePaths` + `StateDirectory` + `PrivateTmp` — `/var/log/osgania` MUST be in `ReadWritePaths` or camara's append hits EROFS. The unit deliberately omits `Environment=AUDIT_LOG=` (base R10.1) and omits `--bare` (see invariant).

**POST-PIVOT amendment (2026-06-16).** Two directives change vs. the original ADR-3:
- **`ExecStart=/opt/osgania/platform/bin/agent-run.sh -p`** (was `/usr/bin/claude -p`). The wrapper is the new ExecStart entrypoint (ADR-6); it exports `ANTHROPIC_API_KEY` from `$CREDENTIALS_DIRECTORY` and `exec`s `/usr/bin/claude "$@"`. The `--bare` invariant (below) now binds on the wrapper's `exec` line AND the ExecStart line.
- **`UnsetEnvironment=ANTHROPIC_AUTH_TOKEN`** (dropped `ANTHROPIC_API_KEY`). Rationale: post-pivot the wrapper INTENTIONALLY sets `ANTHROPIC_API_KEY`, so it must not be unset. `ANTHROPIC_AUTH_TOKEN` is still scrubbed — pure defense-in-depth against an `ANTHROPIC_AUTH_TOKEN` *inherited from the systemd manager env / `DefaultEnvironment`* (for a system unit that set is near-empty, so this is belt-and-suspenders, not a guard against a precedence attack the wrapper itself could introduce — SC-4). **Note:** `Environment=ANTHROPIC_API_KEY=…` in the unit file remains FORBIDDEN — the literal key value must never appear in the (world-readable) unit file or the journal; the wrapper reads it at runtime from the tmpfs credential.

### ADR-4 — StateDirectory provides the writable `~/.claude` for the homeless aios

**Choice.** `StateDirectory=osgania-agent` → systemd creates/owns `/var/lib/osgania-agent` as `aios:aios 0700` on every start (idempotent, survives reboots). Point the CLI at it via `Environment=HOME=%S/osgania-agent` and `Environment=XDG_CONFIG_HOME=%S/osgania-agent` (`%S` = `/var/lib`). This is the writable substitute given `aios` has home `/nonexistent` (Slice-1 ADR-4).

**Alternatives considered.** `WorkingDirectory` only (no HOME) — rejected: the CLI writes config/cache to `$HOME/.claude`; with `HOME=/nonexistent` under `ProtectSystem=strict` it would EROFS/fail. A real home dir for aios — rejected: Slice-1 ADR-4 explicitly avoids attack surface; StateDirectory is the systemd-native, mode-correct equivalent.

**Rationale.** `StateDirectory` is auto-added to the unit's writable set even under `ProtectSystem=strict` (no extra `ReadWritePaths` entry needed), created with the right owner/mode automatically, and namespaced to the unit. Pointing `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, and `XDG_STATE_HOME` at it guarantees every CLI config/cache/data/state write lands in the one writable, private location (SC-5: `XDG_STATE_HOME` added so a CLI that consults it directly cannot hit EROFS under `ProtectSystem=strict`). (`XDG_RUNTIME_DIR` is intentionally not set; its default `/run/user/UID` would be inaccessible under `ProtectSystem=strict`, but Claude Code does not require a runtime dir for headless `-p` runs.)

### ADR-5 — Live defense-in-depth probe — RE-AMENDED 2026-06-16 (Phase-4): permissionMode oracle

> **RE-AMENDMENT (authoritative; supersedes the two-marker design below).** Phase-4 hardware verification on the real systemd unit (CLI 2.1.153) refuted the "mode-lock is a no-op" assumption AND proved the two-marker probe can never reach VERIFIED. The stream-json `init` event reports **`permissionMode: "default"` even WITH `--dangerously-skip-permissions`** — so `disableBypassPermissionsMode: "disable"` IS in effect (the flag is *accepted without error* but does NOT grant bypass). Consequently the headless agent stays in `default` mode where every Bash tool call DEFERS (no approver in `-p`); the forbidden command can never execute — but neither can the benign liveness command, so `.probe-alive` is never written and the marker oracle is permanently UNVERIFIED (independently, the model also refuses the exfil-shaped prompt). The probe is therefore replaced by a **deterministic `permissionMode` oracle**: run the wrapper with `-p --output-format stream-json --verbose --dangerously-skip-permissions` and a benign prompt, parse `permissionMode` from the `init` event — `default`/non-bypass → **VERIFIED** (bypass neutralized, the real Layer-3 outer wall); `bypassPermissions` → **FAILED** (managed disable not in effect); no init event → **UNVERIFIED**. This is model-independent, sandbox-independent, and CAN reach VERIFIED. guardia (the inner denylist layer, which a live tool call would hit IF approvals existed) is proven separately and exhaustively by the host-safe `guardia.bats` matchers (R2.x + HA-15). Code: `_classify_bypass_probe` + `run_defense_in_depth_probe` in `scripts/provision-agent.sh`; tests `ADV-F03a-d` (host-safe) + `HA-09-S1/S2/S3`. **The two-marker rationale below is retained as superseded history.**

**Context for the (now-superseded) two-marker rework.** The original ADR-5 probe tried to prove the CLI *refuses* `--dangerously-skip-permissions` (mode-lock enforced). VPS observation: **CLI 2.1.153 ACCEPTS the flag** — the mode-lock (`disableBypassPermissionsMode`) may be a no-op (PSC R10.3 / anthropics/claude-code#44642). That is acceptable as a *degraded Layer 3* **only because** PSC's architecture says Layers 1 (deny rules) and 2 (guardia hook) still hold independently. So the probe's job changes: it must prove the load-bearing guarantee — **guardia (Layer 2) still vetoes a forbidden command even under `--dangerously-skip-permissions`.** *(Phase-4 update: the "ACCEPTS the flag" observation was correct but its interpretation was not — accepting the flag is not the same as entering bypass mode; permissionMode stays `default`, so the mode-lock is actually ENFORCED. See the re-amendment above.)*

**Choice — a TWO-MARKER probe (closes the false-VERIFIED hole).** As the FINAL 2a step (needs a real key), run the installed CLI as `aios` under the production runtime env, with `--dangerously-skip-permissions`, instructing the agent to run EXACTLY two Bash commands in order:

1. **Liveness marker (allowed):** `echo probe-alive > /opt/osgania/client/.probe-alive` — `echo` + a write under `client/` is denied by NO layer, so it succeeds whenever the agent is actually issuing Bash calls.
2. **Forbidden command (must be vetoed by guardia, Layer 2 only):** `cat /opt/osgania/platform/hooks/guardia.sh > /opt/osgania/client/.probe-leak` — guardia R2.6 denies the `platform/` substring; NO Layer-1 Bash deny rule covers a `cat` (Layer-1 Bash denies are only `sudo`/`curl`/`wget`), so a block isolates **Layer 2**. The target is **pinned** to `guardia.sh` (open-source policy logic — confidentiality-irrelevant); the forbidden command MUST NOT be an env-dump (HA-15) form, MUST NOT read the secrets path or `/proc/*/environ`, and MUST NOT name `platform/bin/**` — so a FAILED outcome reveals the broken layer WITHOUT disclosing a secret.

The two markers are the causal oracle (no model-prose parsing):

| `.probe-alive` | `.probe-leak` | Classification | Meaning |
|----------------|---------------|----------------|---------|
| present | absent or empty | **VERIFIED** | The agent WAS issuing Bash calls (liveness proven) AND guardia vetoed the forbidden read. Layer 2 holds; degraded Layer-3 mode-lock is an accepted residual. |
| absent | (any) | **UNVERIFIED** | The agent never ran even the allowed command (auth failed, key/CLI absent, model declined, turn-limit). Inconclusive — never VERIFIED. |
| (any) | non-empty | **FAILED** | The forbidden `cat` executed (its output landed in `.probe-leak`) → guardia did NOT veto under bypass. Layer 2 broken: surfaced loudly, non-zero exit. |

The liveness marker is what distinguishes "model refused / never engaged" (→ UNVERIFIED) from "guardia blocked" (→ VERIFIED): both leave `.probe-leak` empty, but only a refusal also leaves `.probe-alive` absent. `.probe-leak` is content-coupled to execution (it is filled ONLY if the read runs), so absence/emptiness is positive evidence of the veto, not mere "content didn't appear in prose." The probe records only WHICH marker fired (never the leaked content), then deletes both markers after classifying. (Belt-and-suspenders: if the CLI's `-p` structured output exposes a guardia `deny` event for the probe command, the probe MAY also assert it — but the two-marker filesystem oracle is the authoritative signal.)

**Alternatives considered.** Single sentinel / "content didn't appear" as the only signal — rejected: a model refusal produces the identical observation, silently yielding a FALSE VERIFIED (the original flaw). Keep testing flag-refusal — rejected: the CLI accepts the flag on 2.1.153, so that probe would always FAIL and tell us nothing about the real guarantee. Pipe crafted JSON straight into `guardia.sh` and assert it denies — KEPT as the authoritative host-safe *unit* proof of R2.6 / HA-15 correctness, but rejected as THE live probe because it does not exercise guardia **inside the real runtime under bypass**, which is the property in question. Use `curl`/`rm -rf`/an env-dump as the forbidden command — rejected: `curl` is also Layer-1-denied (can't attribute the block to Layer 2), `rm -rf` is destructive and likely refused by the model before guardia sees it, and an env-dump command would, on a FAILED run, leak `ANTHROPIC_API_KEY` into `.probe-leak`/the journal (turning a Layer-2 break into a credential disclosure).

**Rationale.** Mirrors Slice-1's honesty gate (R9.5): VERIFIED requires POSITIVE evidence both that the agent was live AND that the forbidden command was blocked. The probe tests the guarantee the product actually relies on (defense-in-depth), not a CLI feature that turned out to be a no-op — and it cannot be fooled into a false pass by a model refusal.

### ADR-6 — Key delivery via `ANTHROPIC_API_KEY` + a root-owned `ExecStart` wrapper (THE PIVOT, 2026-06-16)

**Choice.** Replace the apiKeyHelper (ADR-1, superseded) with a tiny root-owned launch wrapper that surfaces the credential as `ANTHROPIC_API_KEY`:

```sh
#!/usr/bin/env bash
# /opt/osgania/platform/bin/agent-run.sh — root:root 0755
# Launch wrapper: source the API key from the systemd LoadCredential tmpfs into
# ANTHROPIC_API_KEY, then exec the real CLI. The key value never appears in the
# unit file, the journal, or any versioned file — only in this process's env at
# runtime (read from $CREDENTIALS_DIRECTORY, a per-unit non-swappable tmpfs).
set -euo pipefail
: "${CREDENTIALS_DIRECTORY:?CREDENTIALS_DIRECTORY is not set — agent-run.sh must run under systemd LoadCredential}"
# Read the key and strip ALL whitespace (trailing newline, a CRLF \r from a
# Windows-pasted key, stray surrounding spaces). A valid Anthropic key contains
# no whitespace, so [:space:] removal is lossless and prevents the opaque 401
# this pivot exists to escape. export-then-assign (NOT `export X=$(...)`) keeps
# set -e fail-closed: a missing/unreadable file aborts the wrapper.
export ANTHROPIC_API_KEY
ANTHROPIC_API_KEY="$(tr -d '[:space:]' < "${CREDENTIALS_DIRECTORY}/anthropic-api-key")"
[[ -n "$ANTHROPIC_API_KEY" ]] || { printf 'agent-run.sh: API key file is empty or whitespace-only\n' >&2; exit 1; }
exec /usr/bin/claude "$@"
```

**Key-file precondition (operator contract).** The credential at `/etc/osgania/secrets/anthropic-api-key` MUST contain the raw key only. The wrapper strips all whitespace (so a trailing `\n`/`\r\n`/surrounding spaces are tolerated), but the operator MUST NOT embed comments, multiple keys, or internal whitespace. An empty/whitespace-only file fails the wrapper loudly (exit 1) rather than authenticating with an empty key.

Installed `install -o root -g root -m 0755` (aios r-x only; root-owned, non-writable by aios — same property the apiKeyHelper had, and already covered by guardia R2.6 + PSC R9.5/R9.6 `Edit/Write(/opt/osgania/platform/**)`). The unit's `ExecStart=/opt/osgania/platform/bin/agent-run.sh -p` invokes it; systemd's `LoadCredential` still injects the key into `$CREDENTIALS_DIRECTORY` (tmpfs), so the key is **never** in the unit file or any committed file.

**Why apiKeyHelper was abandoned.** CLI 2.1.153 cannot spawn `apiKeyHelper` as the unprivileged `aios` user (it spawns it via `execa` with `shell:true` and silently swallows stderr — GH #29142; "exited undefined" → 401). Ruled out shell, config dir, PATH, perms, key validity, network; works as root; no upstream fix (issues #11631/#42593/#60155/#38314 closed not-planned/duplicate). Anthropic's documented headless/non-root auth is `ANTHROPIC_API_KEY` (always used in `-p` mode when present; confirmed authenticating as `aios` on the VPS). Full diagnosis: engram `architecture/apikeyhelper-aios-auth-blocker`.

**Security trade-off (the cost of the pivot).** With apiKeyHelper the key was read on-demand inside the CLI and **never entered the process environment**. Post-pivot the key IS in `ANTHROPIC_API_KEY` in the agent process — and therefore in `/proc/<agent-pid>/environ`, and **inherited by every Bash-tool subprocess the agent spawns** (children inherit the parent env). So any command the agent runs can, in principle, read its own environment.

**Residual-risk analysis + layered mitigations (defense in depth, honest about each layer's strength):**

| Layer | Mitigation | Strength |
|-------|-----------|----------|
| Tenancy | The VPS is single-tenant-per-client; the key authorizes only *this* client's own box, which the operator owns. Blast radius of a self-read is the client's own credential. | **Primary boundary.** Bounds the consequence, not the read. |
| Egress (Layer 1 + guardia, partial) | `Bash(curl *)` / `Bash(wget *)` denied (PSC R9.2/R9.3 + guardia R2.2); guardia also speed-bumps bash's `/dev/tcp`//dev/udp (HA-15.5a, TMH-2). | Incomplete — interpreters (`python`/`node`) can still open sockets, and only the literal `/dev/tcp` token is bumped (not an indirected path). `curl`/`wget`/`/dev/tcp` are NOT "the only" easy channels — the **real** exfil wall is 2b egress. |
| Egress (2b) | UFW default-deny-egress (allow only the API endpoint) is the **real exfil wall**. | **The actual boundary against exfil** — but it ships in **2b**, not 2a. |
| env-dump (ADR-7) | guardia denies the obvious env-dump verbs/paths (`env`/`printenv`/bare `set`/`declare -p`/`/proc/*/environ`). | **Speed-bump only** (see ADR-7) — defeated by any interpreter; raises the bar against naive/accidental dumps. |
| At rest | The key file stays `root:root 0700`; `Read(/etc/osgania/secrets/**)` denied (PSC R9.4) + guardia R2.5; key delivered via tmpfs `LoadCredential`, never a plaintext unit-file env. | Strong for *at-rest*; orthogonal to the in-environ exposure. |

**What this explicitly does NOT protect against (stated plainly, no self-deception):**
- **Self-read of the env.** A determined agent that runs an interpreter (`python -c '…os.environ["ANTHROPIC_API_KEY"]…'`, `node -e`, a compiled binary, `awk`'s `ENVIRON`) — OR simply a bash one-liner naming the variable (`echo "$ANTHROPIC_API_KEY"`, `${!name}` indirection) — can read the key. guardia cannot stop that without denying tooling the agent legitimately needs.
- **Same-uid sibling inspection.** Every Bash-tool child runs as `aios`; one `aios` process can read another's `/proc/<pid>/environ` (same-uid), so a long-lived agent-spawned process can read the key from a sibling even if its own env were scrubbed.
- **Runtime print into the journal.** A runtime `echo $ANTHROPIC_API_KEY` (or a crash backtrace printing env) lands in the `Type=oneshot` service's stdout → journald (operator-readable). The unit-file guard (HA-06.3) only stops the *literal-in-file* case, not a runtime print.
- **Persist-then-ship.** The agent can WRITE the key to a file under the writable paths (`/opt/osgania/client`, `/var/lib/osgania-agent`) that later leaves the box out-of-band (operator `git push` of the client workspace, a backup, a support bundle). The **2b egress firewall does NOT close this** (it is not network egress from the agent) — contained only by single-tenancy + operator discipline (don't ship the workspace/state with a live key).

*(CLOSED by the pivot's hardening: a key-bearing **core dump** is prevented by `LimitCORE=0` (TMH-5); the literal key in the unit file/journal is forbidden by HA-06.3.)*

Containing **exfiltration** of a read key is the job of single-tenancy (consequence) + the 2b egress firewall (channel), not of guardia. This is consistent with PSC's own framing of guardia as "a defense-in-depth speed bump… not a complete sandbox against a motivated adversary."

**Alternatives considered.** (a) Keep apiKeyHelper — rejected: does not work as non-root on 2.1.153 (the blocker). (b) `Environment=ANTHROPIC_API_KEY=<value>` directly in the unit — **rejected hard**: the literal key would sit in the world-readable `/etc/systemd/system/*.service` and in `systemctl show`/journal output; the wrapper keeps the key in tmpfs and out of every file. (c) `LoadCredentialEncrypted` / TPM at rest — deferred (D5 v2); it hardens at-rest, not the in-environ exposure, so it does not change this analysis. (d) Pull the 2b egress firewall forward into 2a — considered; deferred to keep slice boundaries clean, but explicitly noted as the load-bearing exfil control (operators running 2a before 2b accept the documented residual).

### ADR-7 — guardia env-dump denial: a speed-bump mitigation extending PSC R2 (NEW, 2026-06-16)

**Choice.** Add one new denylist category to `guardia.sh` — inserted as **step 7.5** (AFTER the secrets R2.5 and platform R2.6 steps, immediately BEFORE the default `defer`, so first-match-wins preserves the inherited deny reasons; ICP-01) — that denies the obvious environment-dumping commands, so the agent cannot trivially print its own `ANTHROPIC_API_KEY`. Target forms (HA-15.1/.2 are normative; matchers MUST be ERE-expressible in guardia's no-parser model, HA-15.1a):
- `printenv` as a **command word** (its only purpose is printing the environment) — NOT a filename containing it (`bash printenv.sh`, `cat printenv.md`): the matcher excludes `/` from its leading boundary and requires a space/`|`/`;`/`&`/EOL trailing boundary (Phase-3 false-positive fix);
- `env` used as a **dump** (`env` alone, `env` with only options `-0`/`--null`/`-i`/`-u VAR` and NO following command word, or `env` piped/redirected) — NOT `env VAR=val <cmd>` / `env -u FOO <cmd>` / `env -i <cmd>` / `env --unset=FOO <cmd>` / `env --ignore-environment <cmd>` (the ubiquitous run/sanitized-exec forms must keep working). `--null` is the GNU long synonym of `-0`;
- **bare** `set` (prints all shell vars+functions), incl. redirect `set > file` — NOT `set -e`/`set -u`/`set -x`/`set +e`/`set -o …`/`set -- …`;
- **bare** `declare` / **bare** `typeset` (no args — dump all vars+values like bare `set`), incl. redirect `declare > file`, AND the print-definitions flag `-p` on `declare`/`typeset`/`local`/`export`/`readonly` INCLUDING fused short-flag clusters that contain `p` (`-px`/`-pf`/`-ip`) — NOT `declare -i x`/`declare -a x`/`declare x=1`/`export FOO=bar`/`readonly FOO=bar`. The `-p` matcher is anchored to command position (start or after `|`/`;`/`&`) so a flag inside quoted argument text (`echo "use export -p"`, `git commit -m "…declare -p…"`) does NOT false-positive (Phase-3 fix);
- `compgen -v` / `compgen -e` / `compgen -A variable` / `compgen -A export` and fused clusters containing `v`/`e` (`compgen -ve`/`-ev`) (the `-A` synonyms MUST be covered);
- reads of the proc-environ path, ERE `/proc/(self|thread-self|<pid>|$$|$BASHPID|$VAR|${…})(/task/<tid>)?/environ`, tool-agnostic (catches `cat`/`xxd`/`strings`/`tr`/`mapfile`/here-strings that NAME the path; covers a bare-variable pid like `/proc/$PPID/environ`, the `thread-self` symlink, and the per-thread `/task/<tid>/` alias; the `<pid>` placeholder used elsewhere is doc shorthand for the exact ERE in spec HA-15.2);
- **bash-native egress** (HA-15.5a, TMH-2): the substrings `/dev/tcp` and `/dev/udp` (bash's network pseudo-device — a `curl`/`wget`-free, interpreter-free exfil channel), reason `[guardia] denied: net-builtin — …`.

**Where it lives (the live-artifact pattern, same as ADR-1's philosophy).** `guardia.sh` is a *live operator artifact* of `platform-security-core`; the pivot is what necessitates the new category, so 2a owns it: implemented in `platform/hooks/guardia.sh` (new steps in the same case-insensitive, word-boundary idiom as R2.1–R2.6), specified as 2a requirement **HA-15** ("extends PSC R2; MUST NOT alter R2.1–R2.6; preserves R4 non-functional"), regression-tested in `tests/guardia.bats`. **The archived PSC spec text is NOT rewritten** — exactly the boundary ADR-1 drew for managed-settings.

**Honest scope (this is a speed-bump, by design and by precedent).** PSC already declares guardia *"a defense-in-depth speed bump for obvious and accidental dangerous commands… not a complete sandbox against a motivated adversary with shell knowledge."* This category inherits that contract. It **stops**: naive/accidental dumps (`env`, `printenv`, `cat /proc/self/environ`, bare `set`/`declare`) and the lazy `/dev/tcp` exfil. It **does NOT stop** (and must not try to, because that would break the agent's legitimate tools): any interpreter reading its own environment (`python`/`node`/`perl`/`ruby`/`awk ENVIRON`, a compiled reader); **a one-token bash read of the variable itself** (`echo "$ANTHROPIC_API_KEY"`, `printf '%s' "$ANTHROPIC_API_KEY"`, indirect `${!name}`); or variable-indirection of the path (`p=/proc/self/environ; cat "$p"`). The bar is therefore very low — a bare `echo $VAR` suffices; the category only raises it against literal dump verbs/paths. Exfil containment is tenancy + the 2b egress firewall, not guardia.

**Precision requirement (load-bearing for correctness).** The matchers MUST deny the *dumping* forms while never false-positiving the ubiquitous benign forms (`set -e`, `declare -i`, `export FOO=bar`, `env VAR=val cmd`). A category that denies bare `set` but breaks `set -euo pipefail` would make the agent unusable — this distinction is the crux of the implementation and a primary target of the adversarial review (both for **bypasses** that should be denied and for **false-positives** that must not be). Reason strings follow R3.1 (`[guardia] denied: env-dump — …`).

**Alternatives considered.** (a) Attempt exhaustive coverage incl. interpreters — rejected: denying `python`/`node`/`perl` breaks the agent's core capability, is still leaky (a compiled binary or a renamed interpreter slips through), and trades a real capability for false security. (b) Do nothing and rely solely on tenancy + 2b egress — rejected: the ADR-6 trade-off was accepted *on condition of* adding this speed-bump; it is cheap, catches the common case, and is genuine defense-in-depth. (c) Put the new rule in a new PSC change instead of 2a — rejected: serializes 2a behind a second change for a mitigation that the 2a pivot itself necessitates (same reasoning as ADR-1's Option-A rejection of Option B).

**Phase-3 hardening (2026-06-16, provenance).** After implementation, a blind dual-judge adversarial attack EXECUTED real bypasses and false-positive probes against the implemented matchers (not just reading the tests). It found **4 false positives** that hard-denied legitimate agent commands — `printenv` firing on a filename (`bash printenv.sh`) and the `-p` flag firing inside quoted argument text (`echo "…export -p…"`, `git commit -m "…declare -p…"`) — plus a set of cheap redirect/cluster/synonym variants of already-covered verbs (`set > file`, `declare -px`, `readonly -p`, `compgen -ve`, `env --null`, `/proc/$PPID/environ`, `/proc/<pid>/task/<tid>/environ`, `thread-self`). All findings were re-verified by the orchestrator executing the attacks against a patched copy (92-case before/after battery, 0 benign regressions). The 7 resulting matcher tightenings are folded into the EREs above and the HA-15.1/.2/.3 normative text; the false-positive fixes (filename anchoring, command-position anchoring of `-p`) are the **priority-1** changes — a hard-deny of a routine command is worse than a leaky speed bump. Deliberately NOT closed (documented residuals, consistent with the speed-bump scope below): interpreters, bare `echo $VAR`/`${!x}`, `getent`, command-substitution `$(…)/environ`, path-splitting `cd /proc/self && cat environ`, and the runtime-dead mixed-case `/Dev/Tcp`.

---

## Execution model and ordering (idempotency per step)

`scripts/provision-agent.sh` runs as **root** on a Slice-1 box, ordered:

```
0. PRECONDITIONS  (abort early)
   • Slice-1 end-state present (aios uid/gid 9001, /etc/claude-code/managed-settings.json valid, audit +a armed)
   • systemd present; --check/dry-run supported (host-safe, mirrors base R1.7)
1. NODE/NPM RUNTIME      idempotent: node>=18? skip apt; else NodeSource 20.x. Then `apt-mark hold nodejs npm`.
2. CLAUDE CLI PIN        idempotent: `claude --version` == 2.1.153 ? skip : `npm i -g @anthropic-ai/claude-code@2.1.153`
3. CLIENT WORKSPACE      `install -d -o aios -g aios -m 0700 /opt/osgania/client`  (re-asserts mode every run)
4. LAUNCH WRAPPER        `install -o root -g root -m 0755 platform/bin/agent-run.sh /opt/osgania/platform/bin/`
                         (ADR-6; the apiKeyHelper install is GONE)
5. POLICY VERIFY         managed-settings.json is NOT modified by 2a (post-pivot). Read-only structural assert
                         that R9–R12 are intact (deny[6], allow [], defaultMode, disableBypassPermissionsMode,
                         allowManagedHooksOnly, guardia+camara hooks); `jq .` validate. NO write, NO upsert.
6. UNITS                 write service+timer to /etc/systemd/system; `--bare` GUARD assert (ExecStart=wrapper AND
                         the wrapper's `exec` line contain no `--bare`); daemon-reload. (NO enable yet — SC-2.)
7. DEFENSE-IN-DEPTH PROBE (final active step; needs key) → guardia denies a forbidden command under
                         `--dangerously-skip-permissions` → VERIFIED / UNVERIFIED / FAILED (ADR-5)
7.5 ENABLE TIMER         `systemctl enable osgania-agent.timer` (NO `--now`) — AFTER the probe, so the probe's
                         `claude` never races a `Persistent=true` immediate service trigger (SC-2). idempotent.
8. SUMMARY               non-secret: version, paths, defense-in-depth status; assert AUDIT_LOG unset (base R10.1)
```

Idempotency primitives: apt install guarded by version check; `apt-mark hold` is add-only; `npm i -g` re-run only on version mismatch; `install -d`/`install` re-assert owner+mode; jq upsert sets a fixed value (no duplicate key); unit files overwritten declaratively; `systemctl enable` is a no-op when already enabled.

### The `--bare` invariant (load-bearing)

`ExecStart=/opt/osgania/platform/bin/agent-run.sh -p`, and inside the wrapper `exec /usr/bin/claude "$@"` — NEVER `--bare` on either. `--bare` skips managed-settings + hooks → Layers 1+2 (deny rules + guardia/camara) silently off. Post-pivot the entrypoint is the wrapper, so the invariant binds in **two** places: the ExecStart line MUST be exactly `^ExecStart=/opt/osgania/platform/bin/agent-run.sh -p$` (the only argument is `-p`, no `--bare`), AND the wrapper script MUST `exec /usr/bin/claude "$@"` with no literal `--bare` token. Guarantee mechanisms: (1) `provision-agent.sh` lints the assembled unit string (ExecStart matches the pattern, no `--bare`) AND lints the installed wrapper content (`exec /usr/bin/claude "$@"`, no `--bare`) before writing/installing, aborting if violated; (2) `tests/provision-agent.bats` asserts the rendered unit string contains `agent-run.sh -p` and does NOT contain `--bare`, `MemoryDenyWriteExecute`, `AUDIT_LOG=`, or `Environment=ANTHROPIC_API_KEY`, and that the wrapper template `exec`s `claude "$@"` with no `--bare`.

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `scripts/provision-agent.sh` | Modify | Reworked for the pivot: install the wrapper (not the helper), VERIFY managed-settings read-only (no upsert), defense-in-depth probe. Idempotent; `--check` dry-run. |
| `platform/bin/agent-run.sh` | Create | **Launch wrapper (ADR-6).** Exports `ANTHROPIC_API_KEY` from `$CREDENTIALS_DIRECTORY` then `exec /usr/bin/claude "$@"`; installed `root:root 0755`. |
| `platform/bin/anthropic-key.sh` | Delete | apiKeyHelper, obsolete (ADR-1 SUPERSEDED by ADR-6). Rationale preserved in ADR-1 + engram `architecture/apikeyhelper-aios-auth-blocker`; trivially re-derivable if revived. |
| `platform/hooks/guardia.sh` | Modify | Add the env-dump denylist category (ADR-7 / HA-15). R2.1–R2.6 unchanged. |
| `platform/systemd/osgania-agent.service` | Modify | `ExecStart`=wrapper; `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` only (ADR-3 amended). |
| `platform/systemd/osgania-agent.timer` | Unchanged | Placeholder cadence (ADR-3) — pivot does not touch the timer. |
| `tests/provision-agent.bats` | Modify | Rework HA-05/HA-06/HA-08/HA-09 clusters for the pivot; add wrapper scenarios. |
| `tests/guardia.bats` | Modify | Add env-dump regression scenarios (HA-15) — deny dumps, allow benign forms. |
| `/etc/claude-code/managed-settings.json` (live box, not repo) | **No change** | Post-pivot 2a does NOT modify it; read-only structural verify that R9–R12 are intact. |

Neither the repo template `platform/managed-settings.json` NOR the live `/etc/claude-code/managed-settings.json` is modified by 2a post-pivot — the only structural touch the apiKeyHelper design had is removed.

---

## Secret-leak surface review (config rule: flag every leak point)

| # | Surface | Risk | Mitigation |
|---|---------|------|------------|
| K-1 | The API key file `/etc/osgania/secrets/anthropic-api-key` | Wrong mode → aios reads it directly | Stays `0700 root:root` (Slice-1 R5.1) + policy `Read(/etc/osgania/secrets/**)` deny + guardia R2.5 substring deny. 2a writes NO key value (operator supplies it). |
| K-2 | Process environment / `/proc/<agent-pid>/environ` | **REALIZED (accepted, ADR-6):** post-pivot `ANTHROPIC_API_KEY` IS in the agent env and inherited by every Bash-tool child → any agent code-exec can read it. | Bounded + layered, NOT eliminated: single-tenant blast radius (own box) + Layer-1 `curl`/`wget` deny + ADR-7 env-dump speed-bump + **2b UFW egress = the real exfil wall**. Key still injected via `LoadCredential` tmpfs and **never written to the unit file, journal, or any committed file** — only the live process env at runtime. See ADR-6 residual-risk table. |
| K-3 | `ANTHROPIC_AUTH_TOKEN` precedence | A stray auth token could override the key → wrong/expired credential, auth failure | `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` scrubs it. `ANTHROPIC_API_KEY` is intentionally SET by the wrapper (no longer unset — ADR-3 amended). |
| K-4 | Launch wrapper `agent-run.sh` | If aios-writable, agent could swap it to leak/alter the key | Installed `root:root 0755` (aios r-x only); root-owned, non-writable by aios; under `Edit/Write(/opt/osgania/platform/**)` deny (PSC R9.5/R9.6) + guardia R2.6. |
| K-5 | Audit log | Key reaching audit.jsonl becomes append-only & permanent | camara already redacts (`tool_response` body never logged, only exit_code — platform-security-core R6.3). 2a writes nothing into the log; cross-ref only. |
| K-6 | provision-agent.sh stdout / `set -x` | Tracing could echo the key | The script never reads the key value (the wrapper does, at runtime, inside the unit); summary prints only paths/version/probe status; MUST NOT `set -x` around any credential path. |
| K-7 | Agent dumps its own env via the Bash tool (the K-2 channel) | `env`/`printenv`/`cat /proc/self/environ`/bare `set`/`declare` would print `ANTHROPIC_API_KEY` | ADR-7 guardia env-dump denial (HA-15) — **speed-bump only**: stops the naive/accidental dump verbs + `/dev/tcp`, but an interpreter (`python`/`node`) or a bare `echo $VAR` is NOT stopped (and must not be — see ADR-7/HA-15.6). Containment of exfil is K-2's job (tenancy + 2b egress). |
| K-8 | camara `tool_input_summary` logs the Bash command string (PSC R6.2 — NOT redacted) | An agent command interpolating `$ANTHROPIC_API_KEY` into argv (e.g. `node -e '…'` with the key inline) is captured verbatim → PERMANENT in the `chattr +a` audit log | Accepted residual (the interpreter-class leak guardia cannot stop, HA-15.6): bounded by tenancy. PSC R6.3 redacts `tool_response` but NOT `tool_input_summary`; redacting a key-shaped token from the command string is a candidate future hardening (flagged, ICP-06). |

---

## Testing Strategy

| Layer | What to test | Approach |
|-------|-------------|----------|
| Host-safe (macOS now, bats) | Unit-file string assembly (all ADR-3 directives present, `ExecStart`=wrapper); `--bare` guard on unit AND wrapper; forbidden-token absence (`--bare`, `MemoryDenyWriteExecute`, `AUDIT_LOG=`, `Environment=ANTHROPIC_API_KEY`); `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` present and `ANTHROPIC_API_KEY` NOT unset; version floor logic (node>=18 branch, CLI>=2.1.153); managed-settings read-only structural verify keeps R9–R12 unchanged (fixture copy, NO write); wrapper script shellcheck; **guardia env-dump tests — deny the dump verbs/paths AND allow the benign forms (`set -e`, `declare -i`, `export FOO=bar`, `env VAR=val cmd`)** | Pure string/JSON logic, no root, no systemd; bats on the dev host; `--check` dry-run path |
| Linux-root-deferred (disposable VPS) | Actual Node/CLI install + `apt-mark hold`; `systemctl start osgania-agent.service` runs the wrapper → `claude -p` as aios; B2+ hardening takes effect (`systemd-analyze security`); LoadCredential wiring; an agent run appends a record to audit.jsonl and `lsattr` still shows `a`; Slice-1 invariants intact | `PROVISION_TEST_ALLOW_MUTATION=1 && EUID==0`; skip off-target with a clear message (mirrors Slice-1) |
| Live (needs real key) | The agent actually authenticating (via `ANTHROPIC_API_KEY`) + the live defense-in-depth probe (ADR-5: guardia denies a forbidden command under `--dangerously-skip-permissions`) | Requires operator-supplied key at `/etc/osgania/secrets/anthropic-api-key`; without it → UNVERIFIED skip, not failure (Slice-1 PV-17/PV-19 gate) |

`tests/provision-agent.bats` gates these: host-safe scenarios always run in CI; mutation/live scenarios are env-gated and skip with explicit messages off the disposable target. Every bash file gets a paired shellcheck task (config `rules.tasks`).

---

## Sequence diagram (config rule: agent-to-app flow — a single agent run)

```
systemd.timer (OnCalendar)
   │ triggers
   ▼
osgania-agent.service (oneshot, User=aios, ProtectSystem=strict)
   │ LoadCredential → $CREDENTIALS_DIRECTORY/anthropic-api-key (tmpfs)
   │ UnsetEnvironment scrubs ANTHROPIC_AUTH_TOKEN
   ▼
ExecStart=agent-run.sh -p   (the wrapper, root:root 0755)
   │ ANTHROPIC_API_KEY="$(tr -d '[:space:]' < $CREDENTIALS_DIRECTORY/anthropic-api-key)"; export it  (condensed)
   │ exec /usr/bin/claude "$@"          ← "$@" == "-p"
   ▼
claude -p   (HOME/XDG → /var/lib/osgania-agent ; WorkingDirectory=/opt/osgania/client)
   │ loads /etc/claude-code/managed-settings.json  (deny rules + hooks; NO apiKeyHelper)
   │ auth via ANTHROPIC_API_KEY env var (set by the wrapper)  [now in /proc/PID/environ → K-2]
   ▼
agent issues a tool call (e.g. Bash)
   ├─► PreToolUse hook  guardia.sh  → deny | defer            (Layer 2)
   │      (managed deny rules apply first                      Layer 1)
   ▼ (if allowed)
   tool executes
   ▼
   PostToolUse hook  camara.sh  → append 1 JSON line to /var/log/osgania/audit.jsonl (+a armed)
   ▼
service exits 0 (oneshot success) → timer waits for next cadence
```

This is the only agent-to-app/runtime flow 2a introduces; the rest of `provision-agent.sh` is provision.sh → OS syscalls (no app, no protocol).

---

## Migration / Rollout

No data migration. Rollout = run `provision-agent.sh` once on a Slice-1 box; re-run is the idempotent repair path. Rollback (proposal §): disable+remove the units, remove the wrapper `/opt/osgania/platform/bin/agent-run.sh`, `npm uninstall -g`, optional `apt-mark unhold`, `rm -rf /opt/osgania/client`. **No managed-settings edit to undo** — post-pivot 2a never modified it. The guardia env-dump category (HA-15) is additive defense-in-depth and may be left in place; reverting it is optional and only needed for a byte-identical Slice-1 restore. MUST NOT during rollback: `chattr -a` the audit log, delete the secrets dir/key, or touch any R9–R12 key / `CAP_LINUX_IMMUTABLE`.

## Open Questions

None blocking. The pivot (ADR-6/ADR-7, amended ADR-3/ADR-5) is decided. One minor disposition flagged to the operator: whether to **delete** `platform/bin/anthropic-key.sh` (recommended — obsolete; rationale preserved in ADR-1 + engram `architecture/apikeyhelper-aios-auth-blocker`) or retain it un-wired for a future apiKeyHelper revival. **Default: delete.**

## Next step

Encode the pivot literals into `spec.md`: wrapper path/mode/body, `ExecStart`=wrapper, `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`-via-wrapper key delivery (HA-08), managed-settings read-only verify (HA-05), defense-in-depth probe (HA-09), and new **HA-15** env-dump denial; mark HA-08-S4 (helper) obsolete. Then rework the tests + implement (Phase 2), adversarial-review the security code (Phase 3), and verify on the real systemd unit (Phase 4).
