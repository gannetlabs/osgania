# Proposal: vps-provisioning-hardening-2a

**Change id**: `vps-provisioning-hardening-2a`
**Capability**: vps-provisioning-hardening (Slice 2, **sub-slice 2a — "Run the agent"**)
**Project**: osgania
**Artifact store**: openspec
**Date**: 2026-06-15
**Status**: proposal (awaiting review → spec + design)
**Builds on**: `vps-provisioning-base` (Slice 1, ARCHIVED + verified on real Ubuntu 24.04) and `platform-security-core` (the three-locks L0 baseline). Reads the shared exploration `openspec/changes/vps-provisioning-hardening-2a/explore.md`.
**Split from**: Slice 2 was split (user decision) into **2a (run the agent)** and **2b (harden network + maintenance)**. This proposal covers ONLY 2a. 2b is `vps-provisioning-hardening-2b`.

---

## Why (the problem)

Slice 1 turned the three-locks artifacts into load-bearing OS state: the `aios` no-sudo nologin account, the platform tree at `/opt/osgania/platform/`, the operator policy at `/etc/claude-code/managed-settings.json`, the root-only secrets dir, and the append-only audit log armed with `chattr +a` in the host namespace. Everything is in place **except the one thing the product exists to do**: the box does not yet run the client's agent.

Today there is:

- **No Node/npm runtime and no Claude Code CLI** on the box (Slice 1 deliberately deferred the runtime — spec R9.1 records CLI install as a Slice 2 forward dependency).
- **No launch mechanism** — `aios` has no home, no `~/.claude`, no shell, and nothing invokes `claude`. Without a launch unit, `DISABLE_AUTOUPDATER=1` has no durable runtime home (Slice 1 forward dependency R9.2a), and the live Layer-3 mode-lock test could not run (Slice 1's PV-19 records Layer-3 as UNVERIFIED until the agent actually runs against the policy).
- **No API-key delivery** — the secrets dir exists but holds no key, and nothing wires a key into the CLI without leaking it into the process environment.
- **No process-level hardening** — even once the agent runs, its Linux process rights are wide open.

OSGANIA is "one VPS per client, each running a dedicated Claude Code CLI agent for repetitive business work." Until 2a lands, that agent does not exist on the box. 2a makes the box run the agent — hardened at the process layer (B2+), reading its key without exposing it, and with Layer-3 (the bypass-permissions mode-lock) finally validated **live** against the running CLI. Network containment and maintenance posture are a separate concern and are deferred to 2b.

**Why now**: 2a is the smallest slice that produces a working, hardened, production-capable box. It is unblocked — the heaviest user decisions (egress firewall model, Docker/Coolify coexistence) live in 2b, so 2a can ship first while 2b adds the network/maintenance layer afterward.

---

## What changes (capability description)

After 2a is applied to a Slice-1-provisioned box, `systemctl start osgania-agent.service` runs `claude -p` as `aios`, the managed-settings deny rules and hooks fire (Layers 1 + 2), and `camara.sh` appends records to the `+a`-armed audit log. Concretely, 2a establishes the following capabilities:

1. **Node.js + npm runtime, version-held.** Install the distro apt Node when its version is >= 18 (Ubuntu 24.04 ships 18.19.1), otherwise install NodeSource 20.x LTS. Hold both packages (`apt-mark hold nodejs npm`) so an OS package upgrade cannot silently move the runtime out from under the pinned CLI.

2. **Claude Code CLI installed and pinned.** `npm install -g @anthropic-ai/claude-code@<pinned>` at a version **>= v2.1.153** (the Slice-1 floor; the exact pinned literal is an open question for design). Auto-update is disabled **durably** for the `aios` runtime via the systemd unit's `Environment=DISABLE_AUTOUPDATER=1` — this discharges Slice 1's forward dependency R9.2a, which Slice 1 could not satisfy (no launch mechanism, no `aios` home).

3. **Per-client writable workspace.** Create `/opt/osgania/client/` with `install -d -o aios -g aios -m 0700`. This is the agent's `WorkingDirectory` and the only place under `/opt` it may write. (Slice 1 deliberately did NOT create this — base spec R3.8 / design ADR-3 deferred it to onboarding + Slice 2 to avoid dead, unmanaged state.)

4. **systemd launch unit.** A `osgania-agent.service` (`Type=oneshot`, `User=aios`, `WorkingDirectory=/opt/osgania/client`, `StateDirectory=osgania-agent` to provide a writable `~/.claude` substitute since `aios` has no home) paired with a `osgania-agent.timer`. **The timer cadence is a PLACEHOLDER** — the real autonomy/workload schedule is deferred to the future autonomy-ladder/onboarding change; 2a ships a conservative placeholder cadence and says so explicitly.

5. **Guarded agent invocation.** The unit invokes `claude -p` (headless print mode) **WITHOUT `--bare`**. This is a load-bearing invariant, not a style choice — see Risks. `--bare` skips managed-settings and hooks, which would bypass Layers 1 + 2 of the entire security model. The invocation MUST be guarded so `--bare` can never be introduced.

6. **B2+ systemd process hardening.** Apply `ProtectSystem=strict` with `ReadWritePaths=/opt/osgania/client /var/log/osgania`, plus `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, and the kernel/namespace protection set. **Exclude `MemoryDenyWriteExecute=yes`** (confirmed incompatible with Node.js V8 JIT — it would crash the agent). `SystemCallFilter` uses the **deny-form only** (not the `@system-service` allowlist) because the agent legitimately spawns subprocesses through the Bash tool. Tightening toward B3 is explicitly out of scope (later, gated on `systemd-analyze security` + live profiling).

7. **API-key delivery without env exposure (file-based, D5=v1).** The unit uses `LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key`, and `managed-settings.json` gains an `apiKeyHelper` entry that reads `$CREDENTIALS_DIRECTORY/anthropic-api-key`. The key stays out of `/proc/PID/environ` and out of the agent's context (the secrets path is already deny-read at both the OS layer — `0700 root:root` — and the policy layer — `Read(/etc/osgania/secrets/**)`). **Mandatory**: `UnsetEnvironment=ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN` in the unit — the env var has **precedence over `apiKeyHelper`** (verified), so without scrubbing it the helper would never be called. This is consistent with the v1 onboarding/secrets decision (static per-client key via root-owned helper + deny-read; engram `architecture/onboarding-secrets`) and the workspace-per-client billing model (one revocable key per client; engram `architecture/billing-model`).

8. **Live Layer-3 mode-lock validation.** As the **final** 2a step (it needs a real API key present so the agent can actually run), validate that `disableBypassPermissionsMode: "disable"` is honored by the installed CLI against the installed policy. Classify the result honestly as **VERIFIED / UNVERIFIED / FAILED** — never claim VERIFIED without a successful live probe (same honesty gate as Slice 1's R9.5 / PV-19).

9. **Idempotency.** Every 2a provisioning step is safe to re-run: package install/hold is guarded, the CLI version is checked before re-install, `install -d` re-asserts the workspace ownership/mode, the systemd units are written declaratively and re-`daemon-reload`ed, and the `apiKeyHelper` edit is applied as a presence-guarded upsert (not a blind append). Re-running is the day-to-day repair path, mirroring Slice 1.

---

## Out of scope (deferred to 2b = `vps-provisioning-hardening-2b`)

- **UFW egress firewall** — default-deny-egress + allow {443, 53, 123, 80}, allow-in 22 BEFORE `ufw enable`; includes the egress-model fork (OD-EGRESS: baseline UFW vs Squid domain-ACL proxy) and the Docker/Coolify coexistence question (OD-DOCKER: `ufw-docker` if Docker is present).
- **SSH sealing of `aios`** — `DenyUsers aios` drop-in (`passwd -l` from Slice 1 does NOT block key login; base spec R2.5 flagged this as Slice 2's job).
- **unattended-upgrades drop-in** — security-pocket-only auto-patching with `nodejs npm libnode*` blacklisted (belt-and-suspenders with 2a's `apt-mark hold`).
- **logrotate under `chattr +a`** — rotating the audit log while preserving the append-only arming.

Also out of scope (later, separate changes): tightening systemd hardening to **B3**; **TPM-encrypted key at rest** (`LoadCredentialEncrypted` — the D5 v2 future milestone, superseding 2a's plaintext-file delivery).

---

## Non-negotiable principles referenced (config.yaml)

| Principle | How 2a honors it |
|-----------|------------------|
| Client-facing agent has NO root and is read-only by default | Unit runs `User=aios` (no root, from Slice 1); `ProtectSystem=strict` + `NoNewPrivileges=yes`; the only writable paths are `/opt/osgania/client` and `/var/log/osgania` (append-only). |
| Operator policy (managed-settings.json) cannot be overridden by the client/agent | The agent is invoked **without `--bare`**, so managed-settings + hooks always load; live Layer-3 test confirms the mode-lock is real, not a no-op. |
| Audit log of every action | The unit must NOT clear `chattr +a` (base R7.6) and MUST keep `CAP_LINUX_IMMUTABLE` intact for the host arming; `camara.sh` appends to the armed file when the agent runs. The unit MUST NOT set `AUDIT_LOG` (base R10.1). |
| Secrets never in versioned files, repo, or conversation | The API key is delivered via `LoadCredential` (not in the unit file, not in env, not in `/proc/PID/environ`); `apiKeyHelper` reads it from the runtime credentials dir; the secrets path stays deny-read at OS + policy layers. The pinned key value is never committed. |
| Per-client isolation (one VPS, one API key, one workspace per client) | One key at `/etc/osgania/secrets/anthropic-api-key`, one writable workspace `/opt/osgania/client`, one agent unit — per box. Revoking the key is the per-client kill switch. |
| Verify product facts against official docs; never guess | The env-precedence-over-`apiKeyHelper` fact and the `MemoryDenyWriteExecute` vs V8 JIT incompatibility are verified (explore sources); the live Layer-3 probe validates the mode-lock instead of trusting the version number. |

Brain-vs-apps separation / MCP least-privilege is not exercised by 2a (no MCP wiring in this slice) and is not regressed.

---

## Change-boundary handling (the `apiKeyHelper` extension) — DESIGN QUESTION

Adding an `apiKeyHelper` entry to `managed-settings.json` touches an artifact governed by the **archived** `platform-security-core` contract. The exploration's user decision **D3=A** is to add it directly in Slice 2, documented as a v1 extension. This proposal does NOT silently mutate an archived contract — it flags the cleanest handling for design to ratify.

**The distinction that matters**: `platform-security-core` is archived as a *spec/design contract*, but `managed-settings.json` is a **live operator artifact** that the running box owns and that provisioning is the sanctioned mutator of. Slice 1 already drew this exact line (base design ADR-2): it refused to add `requiredMinimumVersion` to the archived template because that would either edit an archived artifact or create repo↔box drift — and it left a true policy change to "a separate, explicit `platform-security-core` change."

The `apiKeyHelper` addition is the same class of decision. Two clean options:

- **Option A (recommended) — treat `apiKeyHelper` as a documented v1 extension applied at the live-artifact layer, with a thin spec note.** 2a adds the `apiKeyHelper` key to the `managed-settings.json` the box runs, and records the extension in 2a's own spec/design with an explicit cross-reference back to `platform-security-core` R9–R12 (the deny/hook contract it must not disturb). The archived `platform-security-core` spec text is NOT rewritten; instead 2a's spec carries a normative "extends managed-settings.json with `apiKeyHelper`; MUST NOT alter any existing R9–R12 key" requirement plus a structural test. This keeps the boundary honest and visible without reopening an archived change. **This matches how Slice 1 handled its only near-boundary decision.**
- **Option B — open a separate explicit `platform-security-core` amendment for `apiKeyHelper` first, then have 2a depend on it.** Cleanest contractually, but slower and heavier for a single key on a single-purpose box; it serializes 2a behind a second change.

**Recommendation**: Option A. The `apiKeyHelper` key is operationally inseparable from the launch unit (the unit's `LoadCredential` + the helper are one delivery mechanism), so coupling them in 2a is coherent; the spec-note + structural test keep the archived contract uncrossed. **Design MUST confirm** which option it adopts and, if A, MUST add the "extends, does not alter R9–R12" guard and a structural test that the existing deny rules, `disableBypassPermissionsMode`, `allowManagedHooksOnly`, `defaultMode`, `allow: []`, and both hook registrations are all still present and unchanged after the `apiKeyHelper` edit.

---

## Rollback plan (REQUIRED — touches managed-settings.json + reads the secrets path)

2a installs Node/CLI, creates systemd units, edits `managed-settings.json`, creates `/opt/osgania/client/`, and reads the API key. Because it mutates live VPS state, rollback is real. To fully undo a 2a run:

1. **Stop and disable the unit**: `systemctl disable --now osgania-agent.timer osgania-agent.service`.
2. **Remove the unit files** and reload: delete `osgania-agent.service` + `osgania-agent.timer` from their systemd path, then `systemctl daemon-reload`.
3. **Revert the policy edit**: remove the `apiKeyHelper` line from `managed-settings.json` (the file is a live artifact; restore it to the verbatim `platform-security-core` template — this leaves all R9–R12 keys exactly as Slice 1 installed them). Re-validate with `jq .`.
4. **Uninstall the CLI**: `npm uninstall -g @anthropic-ai/claude-code`.
5. **Release the runtime hold** (only if reverting the runtime too): `apt-mark unhold nodejs npm`. Node itself may be left installed; the hold-release just restores normal upgrade behavior.
6. **Remove the workspace**: `rm -rf /opt/osgania/client/` (per-client working state only — confirm it contains no data worth keeping first).

**MUST NOT during rollback**: do NOT `chattr -a` the audit log, do NOT delete `/etc/osgania/secrets/` or the key (that is the operator's revocable credential), and do NOT touch any Slice-1 / `platform-security-core` deny rule, hook registration, `disableBypassPermissionsMode`, or `CAP_LINUX_IMMUTABLE` arming. Rolling back 2a returns the box to the verified Slice-1 end-state, not below it.

**Forward-fix path (preferred)**: because every 2a step is idempotent, **re-running the 2a provisioning** is the normal repair for a partial or drifted install — it re-installs/re-pins the CLI, re-asserts the workspace mode, re-writes the units, and re-upserts the `apiKeyHelper` key. Full rollback is the escape hatch; idempotent re-run is the day-to-day repair (same posture as Slice 1).

---

## Risks and mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| **`--bare` invocation** skips managed-settings + hooks → Layers 1 + 2 (deny rules + guardia/camara) silently bypassed → the entire security model is off while the agent runs | **Critical** | The unit invokes `claude -p` **without `--bare`**, treated as a guarded invariant. Spec MUST encode it as a normative requirement; the unit-file content assembly is host-testable on macOS to assert `--bare` is absent (a real TDD guard, not just a comment). |
| **`ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` in env override `apiKeyHelper`** → the helper is never called; key delivery silently breaks or falls back to an unintended key | High | Mandatory `UnsetEnvironment=ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN` in the unit; env-scrub logic is host-testable. |
| **`MemoryDenyWriteExecute=yes`** crashes Node V8 JIT → agent will not start | High | Explicitly EXCLUDE it from the unit; document why. The B2+ set is chosen precisely to avoid Node-incompatible directives. |
| **`ProtectSystem=strict` without correct `ReadWritePaths`** → EROFS when the agent writes the workspace or `camara.sh` appends the audit log | High | `ReadWritePaths=/opt/osgania/client /var/log/osgania` in the unit; both paths verified on the live VPS. |
| **Unit drops `CAP_LINUX_IMMUTABLE` or the hardening interferes with the host `+a` arming** → audit append-only guarantee weakened | Medium | The unit MUST NOT clear `chattr +a` and MUST NOT strip capabilities in a way that touches the host-armed inode flag (base R7.1 / R7.5 host-namespace arming + HA-11.2 in this 2a spec). Verified on the VPS by re-checking `lsattr` after a run. |
| **Editing `managed-settings.json` corrupts or drifts an existing R9–R12 key** | Medium | Apply `apiKeyHelper` as a presence-guarded upsert + `jq .` re-validation + a structural test asserting all existing keys are unchanged (see Change-boundary handling). |
| **CLI auto-update drifts the pin** at runtime | Medium | `Environment=DISABLE_AUTOUPDATER=1` in the unit (discharges base R9.2a) + `apt-mark hold` on the runtime packages. |
| **Live Layer-3 probe cannot run / is inconclusive** | Medium | Classify honestly as UNVERIFIED; never claim VERIFIED without a successful probe (base R9.5). |
| **Verification needs a real API key** that may be absent on the test VPS | Medium | See "Verification dependency" below — affected scenarios skip as UNVERIFIED rather than failing, same as Slice 1's PV-17. |
| **Node security patches blocked by `apt-mark hold`** | Low | Operator-controlled update cadence; 2b's unattended-upgrades drop-in will reconcile the hold with security patching. |

**Note on lockout**: 2a does **NOT** touch the firewall or SSH. The Slice-1 critical risk "`ufw enable` before SSH allow → operator lockout" does **not** apply to this sub-slice — UFW and SSH sealing are entirely in 2b. 2a carries no lockout risk.

---

## Verification dependency (flag clearly)

**End-to-end verification of 2a on the disposable test VPS REQUIRES a real Anthropic API key placed at `/etc/osgania/secrets/anthropic-api-key`.** Two scenarios cannot run without it:

1. **The agent actually running** — `systemctl start osgania-agent.service` invoking `claude -p` and producing audit records requires a working key (the CLI needs to authenticate).
2. **The live Layer-3 mode-lock test** — it runs the CLI against the installed policy, which needs the key present.

Without a key, those scenarios **skip and are classified UNVERIFIED** — the same honesty gate as Slice 1's PV-17 (CLI version) and PV-19 (Layer-3). **The operator must supply a real test key** (a per-client or a disposable test workspace key, per the workspace-per-client billing model) on the disposable VPS for full verification. Host-safe logic (below) is fully testable without a key.

---

## Testing strategy

Same macOS-now / Linux-deferred split as Slice 1:

- **Host-safe logic — real TDD on macOS, now.** Pure/string logic with no root or systemd dependency: argument parsing, the systemd **unit-file content assembly** (assert the exact directives are present and that forbidden ones — `--bare`, `MemoryDenyWriteExecute=yes`, `AUDIT_LOG=`, `Environment=ANTHROPIC_API_KEY` — are absent), the version/precondition logic (Node >= 18 branch, CLI floor >= v2.1.153), the **`--bare` guard**, and the **env-scrub logic** (`UnsetEnvironment` includes both tokens). These are bats-testable on the dev host with no mutation.
- **Linux-root-deferred — verified on the disposable VPS.** The actual Node/CLI/service install, the running unit, `LoadCredential` wiring, the B2+ hardening taking effect, and the **live Layer-3 probe** require real Ubuntu + root + systemd (and, for the run + Layer-3, the API key). These are gated behind the same disposable-target strategy as Slice 1 (`PROVISION_TEST_ALLOW_MUTATION=1` + `EUID==0`), skipping with a clear message off-target.

A `--check`/dry-run for the 2a steps (report planned changes without mutating) is the host-safe everyday check, mirroring base R1.7.

---

## Success criteria (testable)

1. On a Slice-1-provisioned Ubuntu 24.04/26.04 box, `systemctl start osgania-agent.service` runs `claude -p` as `aios` and exits cleanly (`Type=oneshot` success).
2. `node --version` >= 18 and `npm` present; `nodejs`/`npm` are held (`apt-mark showhold` lists them).
3. `claude --version` parses and is **>= v2.1.153**; the pinned literal is recorded.
4. `/opt/osgania/client/` exists as `aios:aios 0700`.
5. The unit file contains `Type=oneshot`, `User=aios`, `WorkingDirectory=/opt/osgania/client`, `StateDirectory=osgania-agent`, `Environment=DISABLE_AUTOUPDATER=1`, `LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key`, `UnsetEnvironment=ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN`, the B2+ directive set, and `ReadWritePaths=/opt/osgania/client /var/log/osgania`; and it **does NOT** contain `--bare`, `MemoryDenyWriteExecute=yes`, or `AUDIT_LOG=`.
6. `managed-settings.json` contains an `apiKeyHelper` reading `$CREDENTIALS_DIRECTORY/anthropic-api-key`, is valid JSON, and **all** existing `platform-security-core` R9–R12 keys are present and unchanged.
7. With a real key present, an agent run produces at least one new record in `/var/log/osgania/audit.jsonl` and the file's `+a` flag is still set after the run (`lsattr`).
8. The live Layer-3 probe reports an explicit VERIFIED / UNVERIFIED / FAILED status (never VERIFIED without a successful probe).
9. Re-running the 2a provisioning is a no-op on an already-2a box (no duplicate units, CLI not re-installed if version matches, `apiKeyHelper` not duplicated, workspace mode unchanged) and exits 0.
10. The Slice-1 invariants are intact after 2a: `aios` still no-home/no-sudo, secrets dir still `0700`, audit `+a` still armed, `AUDIT_LOG` still unset, `CAP_LINUX_IMMUTABLE` not cleared.

---

## Open questions for design

1. **`apiKeyHelper` change-boundary handling** — confirm Option A (documented live-artifact extension + "extends, does not alter R9–R12" guard + structural test) vs Option B (separate `platform-security-core` amendment first). Proposal recommends A.
2. **Exact pinned CLI version** — floor is >= v2.1.153; design must choose the concrete pinned literal (latest stable >= floor at provision time, or a fixed tested version) and define how it is recorded as the single source of truth.
3. **`oneshot`+`timer` vs `service` final shape** — confirm `Type=oneshot` + `.timer` (with a placeholder cadence) is the right v1 shape, and define the placeholder cadence value + how the autonomy-ladder change will later own it.
4. **`StateDirectory` specifics** — confirm `StateDirectory=osgania-agent` (under `/var/lib/`) is the right `~/.claude` substitute for the homeless `aios`, and define whether the CLI needs `HOME`/`XDG_*` env pointed at it (e.g. `Environment=HOME=%S/osgania-agent` or `XDG_CONFIG_HOME`/`XDG_CACHE_HOME`) for config/cache to land in the writable state dir under `ProtectSystem=strict`.
5. **Live Layer-3 probe invocation** — define exactly how the probe is invoked (attempt `--dangerously-skip-permissions` against the installed policy and assert refusal, vs effective-policy introspection) and how it is classified VERIFIED / UNVERIFIED / FAILED, given it needs the API key and a real run.

---

## Next step

Run `sdd-spec` (encode the 2a end-state as Given/When/Then with RFC-2119 keywords and explicit isolation boundaries) and `sdd-design` (resolve the 5 open questions above with ADRs, sequence/flow diagrams, and the secret-leak surface review) — these two can run in parallel from this proposal.
