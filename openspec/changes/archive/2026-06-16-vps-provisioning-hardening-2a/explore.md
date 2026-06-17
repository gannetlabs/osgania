# Exploration: vps-provisioning-hardening (Slice 2)

**Change**: vps-provisioning-hardening
**Date**: 2026-06-15
**Artifact store**: openspec
**Status**: exploration (investigate & recommend only — no proposal, no final decisions)
**Builds on**: the shared exploration archived at `openspec/changes/archive/2026-06-15-vps-provisioning-base/explore.md` (covers both slices and the forks OD-EGRESS, OD-SYSTEMD, OD-KEY) — facts there are reused, not re-verified.

---

## Why This Slice / Why Now

Slice 1 (`vps-provisioning-base`, archived + verified on real Ubuntu 24.04) created the deterministic OS baseline: the `aios` user, the platform tree, the operator policy, the secrets dir, and the load-bearing append-only audit log. But the box does **not yet run the agent**, has **no network containment**, and is **not hardened at the process or SSH layer**. Slice 2 makes the box actually run the client agent — hardened, network-contained, and maintainable.

---

## Recommended Architecture (per concern)

### 1. Agent run model + systemd unit (OD-SYSTEMD)
- **`Type=oneshot` systemd service + a `.timer`** (cadence/workload deferred to the future autonomy-ladder/onboarding change). Matches the "L3 headless cadence" product model.
- Invocation: `claude -p` (headless print mode) **WITHOUT `--bare`** — bare mode skips managed-settings + hooks, which would bypass Layers 1+2 (CRITICAL: must be documented and linted against).
- `WorkingDirectory=/opt/osgania/client`. `StateDirectory=osgania-agent` provides a writable substitute for `~/.claude` (aios has no home).

### 2. Systemd hardening level (B2+)
- Apply: `ProtectSystem=strict` + `ReadWritePaths=/opt/osgania/client /var/log/osgania`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, kernel/namespace protections.
- **EXCLUDE `MemoryDenyWriteExecute=yes`** — confirmed incompatible with Node.js V8 JIT (would crash the agent).
- `SystemCallFilter` in deny-form only (NOT the `@system-service` allowlist — the agent legitimately spawns subprocesses via the Bash tool).
- `UnsetEnvironment=ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN` is mandatory (see concern 3).
- Tighten toward B3 incrementally later, gated on `systemd-analyze security` + live profiling.

### 3. API key delivery (OD-KEY)
- **`LoadCredential=anthropic-api-key:/etc/osgania/secrets/anthropic-api-key`** in the unit (key never in `/proc/PID/environ`, kept in non-swappable memory) + an `apiKeyHelper` in managed-settings.json that reads `$CREDENTIALS_DIRECTORY/anthropic-api-key`.
- **VERIFIED**: `ANTHROPIC_API_KEY` env (precedence #3) overrides `apiKeyHelper` (#4) → the env MUST be scrubbed via `UnsetEnvironment=`, or apiKeyHelper is never called.
- Consistent with the v1 onboarding decision (static key via root-owned helper + deny-read).

### 4. Node/npm + Claude CLI install
- Use distro apt Node if ≥ 18 (Ubuntu 24.04 ships 18.19.1), else NodeSource 20.x LTS. `npm install -g @anthropic-ai/claude-code@2.1.153`. `apt-mark hold nodejs npm`.
- `DISABLE_AUTOUPDATER=1` durable via systemd `Environment=` (this is the Slice-1 forward dependency W-1/F-03).
- Live Layer-3 (`disableBypassPermissionsMode`) mode-lock test runs as the final 2a step (needs the API key); classify VERIFIED / UNVERIFIED / FAILED honestly.

### 5. Egress firewall (OD-EGRESS) — genuine fork
- Baseline: UFW default-deny-egress + allow out `{443/tcp, 53/udp+tcp, 123/udp, 80/tcp}`; allow-in `22/tcp` **BEFORE `ufw enable`** (lockout guard).
- Domain-level enforcement for the CDN-backed `api.anthropic.com` requires a **Squid forward-proxy with domain ACL** (real FQDN containment, real ops cost). Reserve for threat models that demand destination-level HTTPS containment.

### 6. SSH sealing of aios
- Drop-in `/etc/ssh/sshd_config.d/99-osgania-deny-aios.conf` with `DenyUsers aios`; `sshd -t` before reload. (`passwd -l` does NOT block key login — this does.)

### 7. unattended-upgrades
- Drop-in `/etc/apt/apt.conf.d/51-osgania-unattended` — security pocket only; blacklist `nodejs npm libnode*`. Belt-and-suspenders with `apt-mark hold`. The npm-global CLI is not an apt package, so unattended-upgrades cannot bump it.

### 8. /opt/osgania/client/ (writable workspace)
- `install -d -o aios -g aios -m 0700 /opt/osgania/client`. Onboarding will populate subdirs. Attaches to the unit via `WorkingDirectory=` + `ReadWritePaths=`.

---

## Split Recommendation: YES — split Slice 2 into 2a + 2b

**Sub-slice 2a — "Run the agent"** (concerns 1+2+3+8, tightly coupled): Node+CLI install/pin/DISABLE_AUTOUPDATER, `/opt/osgania/client/`, the `osgania-agent.service`+`.timer` units, API-key delivery (LoadCredential + apiKeyHelper), live Layer-3 test. Independent outcome: `systemctl start osgania-agent.service` runs `claude -p`, hooks fire, audit.jsonl gets records.

**Sub-slice 2b — "Harden the environment"** (concerns 4-network+5+6+7): UFW egress, SSH sealing of aios, unattended-upgrades drop-in, logrotate-under-chattr. Independent outcome: UFW verified, `ssh aios@localhost` rejected, unattended dry-run correct, logrotate re-arms +a.

**Justification**: a combined Slice 2 is a >400-line change touching ~12 files. Splitting keeps each reviewable, lets 2a reach production first (the agent runs, hardened at B2+) while 2b adds the network/maintenance layer. Egress + Docker decisions (the heaviest user calls) live in 2b, so 2a is unblocked.

---

## Genuine User Decisions (plain terms)

**D1 — How tightly to lock down where the agent can send data online?** (belongs to 2b)
- A (recommended): block everything except HTTPS, DNS, NTP, apt. Stops weird protocols, but the agent can still reach any HTTPS site.
- C (stricter): a local proxy that only allows approved domains (Anthropic and nothing else). Prevents HTTPS exfiltration to unexpected destinations; adds a proxy we maintain.
- Recommendation: A for v1; C only if a client requires proof the agent can't send data outside a whitelist.

**D2 — Do these VPS boxes run Docker/Coolify alongside the agent?** (factual; affects 2b)
- If YES → extra firewall config (ufw-docker) so Docker doesn't bypass egress rules.
- If NO (agent-only boxes) → simpler egress.

**D3 — How to add the apiKeyHelper to the agent's policy?** (affects 2a)
- A (recommended): add `apiKeyHelper` directly to managed-settings.json in Slice 2, documented as a v1 extension of the platform-security-core baseline.
- B: a separate explicit change to platform-security-core (cleaner boundary, slower).

**D4 — How hard to lock down the agent's Linux process rights now?** (affects 2a)
- B2+ (recommended): solid hardening minus the settings that break Node.js; tighten later with monitoring.
- Full lockdown now: high risk the agent won't start.

**D5 — API key storage: file-based now, encrypted-at-rest later?** (affects 2a)
- v1 (recommended): root-only file via `LoadCredential`. Secure, key not in process env.
- v2 (future): TPM-encrypted (`LoadCredentialEncrypted`) — strongest, separate change.

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| `--bare` used accidentally → hooks + managed-settings skipped → Layer 1+2 bypass | Critical | document + lint against it |
| `ufw enable` before SSH allow → operator lockout (console-only recovery) | Critical | hard guard in provision.sh |
| `ANTHROPIC_API_KEY` in env overrides apiKeyHelper | High | `UnsetEnvironment=` in unit |
| `MemoryDenyWriteExecute=yes` crashes Node V8 JIT | High | exclude from unit; document |
| `ProtectSystem=strict` without correct `ReadWritePaths` → EROFS for agent/audit | High | both paths in `ReadWritePaths=` |
| chattr +a logrotate unprotected window | Medium | postrotate `lsattr` assertion; accept for v1 |
| Docker/Coolify UFW egress bypass | Medium | depends on D2 |
| aios SSH key login if operator adds authorized_keys | Medium | `DenyUsers aios` blocks regardless |
| Most Slice 2 tests need real Ubuntu + root; live Layer-3 needs a real API key | Medium | same disposable-VPS strategy as Slice 1 |
| Node security patches blocked by `apt-mark hold` | Low | operator-controlled update cadence |

---

## Sources
Claude Code headless docs; Claude Code authentication + precedence (issues #60155, #9880); systemd LoadCredential / systemd-creds; MemoryDenyWriteExecute vs Node V8 JIT; UFW outbound guide; logrotate + chattr; SSH DenyUsers/AllowUsers; NodeSource on Ubuntu 24.04.
