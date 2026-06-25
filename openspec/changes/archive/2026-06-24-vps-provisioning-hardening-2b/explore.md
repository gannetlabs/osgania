# OSGANIA Slice 2b — Exploration: Autonomy + Egress (Security Infrastructure)

**Change**: vps-provisioning-hardening-2b
**Date**: 2026-06-17
**Artifact store**: openspec + engram
**Status**: exploration (scope NOT yet confirmed — proposal pending user decisions D1–D4)
**Method**: 12-agent read-only exploration (5 grounding readers over specs/disk/live-VPS/Claude-Code-docs, 6 multi-lens approach generators incl. adversarial bypass/abuse lenses, 1 synthesizer), then orchestrator hardware re-verification.

---

## 1. Context

Slice 2a hardened the OSGANIA single-tenant VPS agent to the point of **functional deadlock**, and a Phase-4 hardware finding reframed what Slice 2b must deliver.

Two things are simultaneously true today:

1. **The agent cannot do autonomous work.** With `defaultMode:"default"` + `permissions.allow:[]` + `disableBypassPermissionsMode:"disable"`, the headless `claude -p` agent has NO approver, so every Bash tool call falls through to the default permission prompt and **defers** — zero autonomous work. This is the Phase-4 finding. Re-enabling bypass is forbidden (it would break the hardware-proven Layer-3 wall).
2. **The agent has no exfil wall.** Post-pivot (ADR-6), `ANTHROPIC_API_KEY` lives in the agent's `/proc/<pid>/environ` and is inherited by every Bash-tool child. Layer-1 only denies `curl`/`wget`; guardia's `/dev/tcp` rule is a self-admitted speed-bump that any interpreter (`node -e`, `python -c`) defeats. The live VPS has **zero** egress controls (`ufw inactive`, `nft` empty, `iptables OUTPUT policy ACCEPT`). The egress firewall is therefore **the actual exfil wall**, not defense-in-depth.

Slice 2b's two load-bearing concerns are: **(A) restore autonomy without weakening `disableBypassPermissionsMode`**, and **(B) build the egress wall, honest about residual risk**.

### Critical current-state blocker (verified on disk + live + orchestrator re-verified)

The live VPS service is **DEAD** and has never executed a single real tool call:

- `agent-run.sh` is **MISSING** on the box (`/opt/osgania/platform/bin/` does not exist), yet `osgania-agent.service` calls it. Failures: `status=243/CREDENTIALS` (early), then a repeating `Error: Input must be provided either through stdin or as a prompt argument when using --print` (`status=1/FAILURE`).
- `/opt/osgania/client` (the `WorkingDirectory`) does not exist.
- The audit log holds only test sentinel markers; no real records exist.

The source tree DOES contain `platform/bin/agent-run.sh` (ends in `exec /usr/bin/claude "$@"`). Because ExecStart passes only `-p`, the wrapper — even when correctly deployed — forwards `-p` with **no prompt source**. So the "Input must be provided" failure is **structural**, not merely a deployment miss. **No autonomy or egress mechanism is observable end-to-end until (a) the wrapper is (re)provisioned and (b) a prompt/task source is wired.** This is **STEP 0** for 2b.

> **Orchestrator hardware re-verification (2026-06-17, read-only SSH to root@147.93.187.127):**
> Confirmed all of the above directly. Added nuance: `/opt/osgania/platform/` has mtime **Jun 17 01:42–01:43** and contains only `hooks/` (guardia.sh + camara.sh, mode 0750 root:aios) — **no `bin/`**. This points to a **half-provisioned box** left by a partial provision / bats run (consistent with memory #231: "a later test rebuilt the tree"), NOT a defect in 2a's design. STEP 0 should therefore be a *clean full re-provision*, then reconcile why `bin/agent-run.sh` was absent before trusting any behavioral measurement.
> Live egress confirmed wide open: `ufw inactive`, `nft` ruleset empty, `iptables -P OUTPUT ACCEPT`. Key intact: 108 bytes root:root 600. systemd 255.4, Node v20.20.2, npm 10.8.2, no docker/coolify.

---

## 2. Inheritance — Hard Constraints (2b must NOT regress any)

| # | Inherited constraint | Status / where enforced |
|---|---|---|
| 1 | Slice-1 managed-settings 6-entry `deny[]` (Layer-1 denylist) | Intact in `platform/managed-settings.json`; provisioner asserts presence |
| 2 | `disableBypassPermissionsMode:"disable"` (Layer-3 wall, hardware-proven) | Intact; provisioner aborts if != `"disable"` (provision-agent.sh:473) |
| 3 | guardia.sh PreToolUse denylist incl. 2a env-dump + `/dev/tcp` speed-bump (Layer-2) | Intact in `platform/hooks/guardia.sh` step 7.5 |
| 4 | `/var/log/osgania/audit.jsonl` `chattr +a` + camara appends; CAP_LINUX_IMMUTABLE not broken | Intact; armed by provision.sh:776 |
| 5 | aios identity: UID/GID 9001, `/usr/sbin/nologin`, home `/nonexistent`, not in sudo | Intact; asserted in provision.sh |
| 6 | Single-tenant-per-VPS; ADR-6 accepted trade-off (key in environ) | Architectural; bounds consequence, not the read |
| 7 | `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (no AF_NETLINK; DNS works) | Intact in unit |
| 8 | Key delivery via `ANTHROPIC_API_KEY` exported by ExecStart wrapper from LoadCredential (apiKeyHelper ABANDONED) | Wrapper present in source, missing on box |
| 9 | Phase-4: must fix zero-autonomy WITHOUT re-enabling bypass | The core mandate |

**Load-bearing provisioner assertions 2b will collide with** (verified on disk):
- `permissions.allow` length MUST be `0` (provision-agent.sh:454-459) — **2b must relax this** if it adds allow rules (Slice-1 R9.9 amendment, done as a positive expected-set assertion, never a silent loosening).
- `permissions.defaultMode` MUST be `"default"` (provision-agent.sh:463-468) — keep `"default"` by applying any non-default mode as a **CLI flag** inside the wrapper, not the managed field (preserves the HA-09 probe oracle).
- ExecStart MUST equal exactly `ExecStart=/opt/osgania/platform/bin/agent-run.sh -p` (provision-agent.sh:629) — **2b must keep this byte-identical** (read the prompt INSIDE the wrapper).
- `--bare` is banned in both wrapper and assembled unit (provision-agent.sh:344, 622) — **non-negotiable** (it skips hook + managed-settings discovery → breaks L1/L2/L3).

---

## 3. Concern A — Agent Autonomy

Permission precedence is **deny → ask → allow, first match wins**; allow rules are evaluated AFTER deny, so they can never re-open an inherited deny. (Doc-confirmed; quoted in §Evidence.)

### A. Autonomy mechanism options

| Option | Mechanism | Fixes -p defer? | Touches bypass switch? | Verdict |
|---|---|---|---|---|
| **A1. Populate `permissions.allow[]` (scoped)** | Tight enumerated allow list in managed-settings | YES (doc: allow rules auto-approve in `-p`) | NO (independent of `disableBypassPermissionsMode`) | **Recommended (primary)** |
| **A2. `--permission-mode dontAsk` (CLI flag, defaultMode stays `default`)** | Auto-deny anything not allow-matched or read-only | Partial — converts defer-stall into clean auto-deny; needs A1 for non-read-only work | NO (dontAsk ≠ bypass) | **Recommended companion** |
| **A3. `--permission-mode acceptEdits`** | Auto-approves file edits + mkdir/touch/mv/cp | Partial (file work only) | NO | Viable (complement) |
| **A4. Flip guardia to emit `permissionDecision:"allow"`** | Make the PreToolUse hook the approver | Doc-AMBIGUOUS in `-p`; inverts guardia R1.4 (never emits allow) | NO, but regresses Layer-2 contract | **Rejected** |
| **A5. `--permission-prompt-tool` MCP approver** | External MCP tool answers prompts | Possibly; I/O schema UNDOCUMENTED | Risk: programmable approver near the bypass surface | Defense-in-depth-only |
| **A6. `defaultMode:"auto"` (server classifier)** | Server-side classifier approves/blocks | YES but probabilistic, research-preview, network round-trip per call | NO | Defense-in-depth-only |
| **A7. `--bare`** | Skip discovery for CI speed | — | Skips hooks + managed-settings discovery → breaks L1/L2/L3 | **Rejected (HA-06.2 ban)** |

### A. Task/prompt source options

| Option | Mechanism | Keeps ExecStart byte-identical? | Verdict |
|---|---|---|---|
| **P1. Wrapper reads a prompt file under `/opt/osgania/client`, execs `claude -p "$(cat …)"`** | Positional arg sourced INSIDE wrapper | YES (arg added inside wrapper) | **Recommended** |
| **P2. stdin pipe (`cat prompt \| claude -p`)** | Pipe into CLI / systemd StandardInput | Breaks clean `exec claude "$@"`; needs subshell/extra directives | Viable |
| **P3. `--append-system-prompt` only** | System prompt | Does NOT satisfy `-p` input requirement alone | Defense-in-depth-only (complement) |

### Concern A recommendation

**Primary: a tightly scoped `permissions.allow[]` (A1)** — the only doc-confirmed path that auto-executes in headless `-p` with no approver while leaving the bypass switch untouched. Deny-first precedence keeps the 6 inherited deny rules and guardia's deny/exit-2 veto as the absolute ceiling; nothing is re-opened.

**Companion: `--permission-mode dontAsk` (A2)** so any non-allowed, non-read-only call cleanly auto-**denies** instead of deferring-with-no-approver (the exact Phase-4 hang). Apply it as a CLI flag inside the wrapper so the managed `defaultMode` field stays `"default"`.

**Allowlist-shape rule (grounded in ADR-6):** the starter `allow[]` MUST NOT include any general-purpose interpreter (`node`, `python`, `perl`, `ruby`) or any network-capable tool (`git push`, `ssh`, `scp`, `nc`). Those re-open the in-environ key-read and the non-curl egress channels guardia by its own admission cannot stop. Keep it to read/build/inspect primitives scoped to `/opt/osgania/client`.

**Prompt source: P1** — wrapper reads an operator-controlled prompt file under `/opt/osgania/client` (a `ReadWritePaths` location, and the natural per-client customization point) and execs `claude -p "$(cat …)"`. Keeps ExecStart byte-identical, preserves the `--bare` ban, matches the existing export-then-exec pattern.

**Reject A4** (regresses Layer-2 deny/defer-only contract, doc-ambiguous for `-p`). **Reject A5/A6 as primary** (undocumented/probabilistic).

> **#1 hardware truth to prove before committing:** that a `claude -p` run with populated `permissions.allow` rules **actually executes** a matching Bash command autonomously (no approver) on THIS CLI version, under managed `disableBypassPermissionsMode:disable`. The settings-allow path is doc-confirmed but must be verified on the same rig that produced the Phase-4 finding.

---

## 4. Concern B — Egress Firewall

The honest test for each option: **does it stop an HTTPS POST of the in-environ key to a NON-Anthropic host, and does it survive Cloudflare's rotating CDN IPs?**

### B. Egress options

| Option | Mechanism | Stops HTTPS-to-any-host exfil? | Survives CDN IP rotation? | Ops cost | Verdict |
|---|---|---|---|---|---|
| **B1. UFW/nft default-deny-egress + allow 443 anywhere** | Port allow-list, whole-box | NO (443 to any host open) | N/A | Low | Defense-in-depth-only (v1 floor) |
| **B2. nft per-uid (skuid 9001) / cgroup default-deny, allow 443 + DNS/NTP** | Scope deny to the agent principal | NO (443 dest unconstrained) but blast radius = agent only | N/A | Low-med | **Recommended (v1 floor)** |
| **B3. systemd `IPAddressDeny=any` + `IPAddressAllow=<ranges>`** | Per-unit cgroup-BPF IP allow-list | NO (CIDR-only; CF shared IPs) | NO (stale/rotation) | Med | Viable / rejected as wall |
| **B4. IP-pinned 443 to Anthropic CIDR set** | Destination IP allow-list | Partially, but CF ranges = most of HTTPS internet | NO (brittle, breaks agent) | High | Rejected as primary |
| **B5. Forward proxy (Squid) with SNI/CONNECT allowlist to `api.anthropic.com`, transparent-redirected** | Hostname/SNI filtering, agent forced through proxy | **YES** (name-based, rotation-proof) | **YES** | High (new daemon) | **Recommended (true containment)** |
| **B6. DNS allowlist only** | Restrict resolution | NO (hardcoded-IP bypasses DNS) | N/A | Low | Rejected |

### Concern B recommendation — v1 vs true containment

**v1 pragmatic (the floor): B2** — nftables default-deny OUTPUT scoped to **uid 9001 / the `osgania-agent.service` cgroup**, allowing 443 to the API path + DNS/NTP/apt. Lowest-ops control that genuinely contains the *raw/non-443 channel class* (arbitrary-port `/dev/tcp`, reverse shells) that guardia only speed-bumps, scopes blast radius to exactly the untrusted principal (operator SSH/apt untouched, near-zero lockout risk), and the zero-cap/no-sudo aios cannot flush it. **Must be documented as NOT closing HTTPS-to-any-host.**

**True destination containment: B2 + B5** — layer a forward proxy (Squid) under its OWN non-aios identity with an SNI/CONNECT allowlist for `api.anthropic.com`, made non-bypassable via **transparent firewall redirect** of uid-9001:443 to the proxy (do NOT rely on honor-based `HTTPS_PROXY`). The only combination that makes a non-Anthropic destination genuinely unreachable while surviving CDN IP rotation.

**Reject B4/B3 as the wall** (CF shared IPs = allow-most-of-the-internet, and pinning rotates stale). **Reject B6** (hardcoded-IP TLS POST bypasses DNS).

### Irreducible residual (survives EVERY option, including a perfect SNI allowlist)

1. **Legitimate-channel exfil.** Data can be smuggled inside the very `api.anthropic.com:443` requests the agent is allowed to make. No egress filter that must allow `api.anthropic.com` can stop data leaving through `api.anthropic.com`.
2. **Same-CDN-IP exfil** on any address-only filter (B3/B4).
3. **Low-bandwidth DNS tunneling** while port 53 is open; the key is only ~108 bytes.

Bounded ONLY by single-tenancy + the no-self-exfil property of the channel — exactly as ADR-6 already states. **Egress raises the bar dramatically but cannot reduce the irreducible residual to zero.**

---

## 5. Scope Reconciliation (REQUIRED)

The original Slice-2 exploration (#206) split 2b as "harden the environment" = **egress firewall + SSH-sealing + unattended-upgrades + logrotate-under-chattr**. Phase-4 reframed 2b around **autonomy + egress**. Evidence:

| Item | Done in Slice-1/2a? | Evidence | Belongs in 2b? |
|---|---|---|---|
| **Egress firewall** | NO — zero controls on box | `ufw inactive`, `nft` empty, `iptables OUTPUT ACCEPT`; no firewall logic in `scripts/` | **YES — core 2b deliverable** |
| **SSH-sealing of aios** | NO — only `passwd -l` (does not block key login) | provision.sh:595 `passwd -l aios`; provision.sh:429 prints "SSH sealing … is a Slice 2 responsibility"; vps-spec R2.5 defers it | Decision D3 |
| **unattended-upgrades** | NO — no logic anywhere | repo-wide grep ZERO matches; vps-spec Non-goals: "Slice 2" | Decision D3 |
| **logrotate-under-chattr** | NO — no logic anywhere | repo-wide grep ZERO matches; vps-spec Non-goals: "Slice 2" | Decision D3 |
| **Agent autonomy fix** | NO — Phase-4 deadlock | Live journal: defer / "Input must be provided" loop | **YES — core 2b deliverable (Phase-4 reframe)** |

**Conclusion:** SSH-sealing, unattended-upgrades, and logrotate are **all still pending — none was done in 2a**. They were the *original* 2b scope; the Phase-4 reframe elevated autonomy + egress as the load-bearing pair. They genuinely belong to "Slice 2" hardening but are **orthogonal, lower-risk, mechanical OS chores** that neither block nor are blocked by autonomy/egress. Recommendation: make 2b's core deliverable autonomy + egress (the two interdependent, hardware-must-verify concerns) and decide explicitly (D3) whether the three OS chores ride along or move to a "2c environment-hardening" slice.

---

## 6. Recommended Architecture Summary

1. **STEP 0 (blocking): Restore the run path.** Clean full re-provision of the box: install `agent-run.sh` to `/opt/osgania/platform/bin/`, create `/opt/osgania/client`, and reconcile why the wrapper was absent. Wire a prompt source **inside the wrapper** (P1) so ExecStart stays byte-identical and the `--bare` ban holds. Until this lands, nothing else is testable end-to-end.
2. **Concern A: scoped `permissions.allow[]` (A1) + `--permission-mode dontAsk` (A2)**, interpreter-free / network-tool-free starter allowlist scoped to `/opt/osgania/client`. Relax the two 2a drift gates deliberately: replace `allow==0` with a tight positive expected-set assertion (do NOT just delete it); keep `defaultMode==default` by setting dontAsk via CLI flag.
3. **Concern B: nft per-uid/cgroup default-deny (B2) as the v1 floor**, optionally + Squid SNI proxy (B5) for true containment. Firewall configured by root in the host netns — agent unit `RestrictAddressFamilies` untouched and the agent still cannot edit rules.
4. **Preserve every inherited layer.** No change to the 6 deny rules, guardia, `disableBypassPermissionsMode`, chattr +a, or aios identity.
5. **SSH-sealing / unattended / logrotate:** include in 2b only by explicit decision (D3); otherwise defer to a dedicated environment-hardening slice.

---

## 7. MUST verify on hardware before proposal/spec

1. **(#1) Settings allow-rule auto-approval in `-p`** under managed `disableBypassPermissionsMode:disable` on THIS CLI version. The whole autonomy fix rests on this.
2. **dontAsk read-only command set membership** — which exact Bash commands run WITHOUT an explicit allow entry (sizes the allowlist; if `echo`/`cat`/interpreter-eval count as read-only, key-read blast radius equals allow-everything).
3. **Phase-4 probe survival** — does HA-09 still classify VERIFIED if mode is dontAsk? (Argues for dontAsk as a CLI flag, keeping `defaultMode==default`.)
4. **Anthropic egress topology** — stable dedicated egress range vs purely Cloudflare shared/rotating?
5. **Full hostname set the `claude` CLI contacts in `-p`** — an over-tight SNI/DNS allowlist breaks the agent if any host is missed.
6. **nft cgroup-match timing on Type=oneshot** — stable cgroup path before first connect? else fall back to uid-9001 match.
7. **EAFNOSUPPORT / DNS under combined constraints** — does nft/IPAddress egress coexist with `RestrictAddressFamilies` without breaking DNS (SC-3 gate)?
8. **IPv6 coverage** — ip6tables/nft inet + AAAA in lockstep, or v6 is an open bypass.
9. **Squid SNI airtightness** — can it close domain-fronting / fake-SNI?
10. **Box stays Docker/Coolify-free** — Coolify would insert DOCKER nft chains bypassing egress.
11. **Why `agent-run.sh` is missing on the box** when the source tree has it — reconcile (half-provision artifact vs failed install) before measuring real behavior.

---

## 8. Open User Decisions (to confirm before proposal)

See `engram: sdd/vps-provisioning-hardening-2b/explore` and the session's decision round. Summary:

- **D1 — Egress strength**: v1 pragmatic (nft per-uid 443-anywhere) | true containment (+ Squid SNI proxy) | v1 now + proxy as immediate follow-up. *Rec: v1 now, proxy as immediate follow-up — unless key-exfil-over-TLS is unacceptable, then both in 2b.*
- **D2 — Autonomy allowlist width + prompt source**: minimal read/inspect allowlist scoped to `/opt/osgania/client` + prompt-file-in-wrapper | broader build/test/git allowlist | lean on dontAsk read-only set + tiny allowlist | stdin pipe for prompt. *Rec: minimal, interpreter-free/network-tool-free, prompt from file inside wrapper; tune from a real `-p` run after STEP 0.*
- **D3 — Scope of 2b**: include SSH-sealing + unattended + logrotate | defer all three to a 2c slice | include only SSH-sealing. *Rec: defer all three to 2c, SSH-sealing flagged highest priority.*
- **D4 — Timer cadence**: keep `OnCalendar=daily` placeholder (autonomy-ladder owns cadence) | wire a real cadence in 2b. *Rec: keep placeholder.*

---

## 9. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| #1 Headless `-p` allow-rule auto-approval doc-confirmed but NOT yet hardware-proven on this CLI under managed disable. If it doesn't auto-execute, the whole autonomy fix fails. | **critical** | Hardware-verify on the Phase-4 rig BEFORE proposal/spec commits to A1. Keep A2/A4 as fallbacks. No spec assertions until VERIFIED. |
| Live VPS service is DEAD (wrapper missing, client dir absent, "Input must be provided" loop). Nothing testable end-to-end until run path restored. | **critical** | STEP 0: clean re-provision; reconcile WHY the wrapper is missing before measuring behavior. |
| v1 egress (B2, 443-anywhere) leaves HTTPS-to-any-host hole open — the in-environ key can be POSTed over TLS to an attacker host via node/SDK with no curl/wget. | high | Document v1 as NOT closing HTTPS-to-any-host. Squid SNI (B5) as immediate follow-up or in-slice (D1). Keep allowlist interpreter-free/network-tool-free. |
| Over-broad allow rule (`Bash(*)`, interpreter, `git push`) re-opens the in-environ key read + non-curl egress channels guardia can't stop. | high | Hard rule: starter allowlist excludes node/python/perl/ruby and git push/ssh/scp/nc. Bats case asserting no forbidden glob in allow[]. |
| Address-only filters (B3/B4) can't distinguish api.anthropic.com from other CF tenants on shared/rotating IPs. | high | Reject IP-pinning as the wall; use SNI (B5). Verify-live whether Anthropic publishes a stable egress range. |
| Relaxing 2a drift gates (allow==0, defaultMode=='default') could silently regress security-verify if done by deletion. | medium | Replace allow==0 with a positive expected-set assertion; keep defaultMode=='default' via CLI-flag dontAsk. Requires a Slice-1 R9.8/R9.9 spec amendment, not a silent change. |
| nft cgroup match on Type=oneshot may not key on a stable cgroup before first connect; or DNS (uid 0) bypasses a per-uid aios rule. | medium | Verify-live cgroup timing; fall back to uid-9001 skuid match. Place DNS allowance correctly. Cover IPv6 in lockstep. |
| DNS port 53 open is a low-bandwidth exfil tunnel (~108-byte key fits in crafted subdomain queries). | medium | Accept as documented residual bounded by single-tenancy (ADR-6). Optionally IP-pin api.anthropic.com to drop DNS (trades fragility). |
| Changing defaultMode to dontAsk in MANAGED settings could break the HA-09 Phase-4 probe oracle. | medium | Apply dontAsk as a CLI flag, keep managed defaultMode=='default'. Verify-live probe still reads VERIFIED. |
| Squid SNI-only ACL bypassable via TLS domain-fronting / ECH; HTTPS_PROXY is honor-based. | medium | Make proxy non-bypassable via transparent firewall redirect (not HTTPS_PROXY). Verify Squid closes domain-fronting. Run proxy as non-aios identity. |
| Future Docker/Coolify install inserts DOCKER nft chains ahead of egress rules. | low | Verify-live box stays Docker-free; either install ufw-docker reconciliation or document a hard prerequisite. |
| Append-flood / disk-exhaustion of writable paths by an autonomous agent (chattr +a protects integrity, not volume). | low | Accept as residual; addressed by deferred logrotate (D3) + optional disk quota. |
