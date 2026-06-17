# Proposal: vps-provisioning-hardening-2b

**Change id**: `vps-provisioning-hardening-2b`
**Capability**: vps-provisioning-hardening (Slice 2, **sub-slice 2b — "Autonomy + Egress (security infrastructure)"**)
**Project**: osgania
**Artifact store**: openspec + engram
**Date**: 2026-06-17
**Status**: APPROVED 2026-06-17 (scope locked). **REVISED (R2): linchpin verify-gate #1 on hardware REFUTED the original ADR-1 autonomy mechanism → ADR-1 corrected (guardia benign `defer`→pass-through); see "Linchpin verified on hardware".** **REVISED (R3, 2026-06-17): egress gates #4/#5 + a live nft test REFUTED D1's "Squid SNI" premise — `api.anthropic.com` is a STABLE PUBLISHED Anthropic range, NOT Cloudflare → egress simplified to a hardware-PROVEN nft IP-pin and the Squid layer DROPPED; see "Egress simplified + PROVEN on hardware" (user delegated the egress mechanism choice).** Both 2b concerns (autonomy + egress) are now hardware-verified. User decisions D1–D4 otherwise stand.
**Builds on**: `vps-provisioning-hardening-2a` (Slice 2a — "Run the agent", ARCHIVED) and `platform-security-core` (the three-locks L0 baseline) and `vps-provisioning-base` (Slice 1, ARCHIVED + verified on real Ubuntu 24.04). Reads the shared exploration `openspec/changes/vps-provisioning-hardening-2b/explore.md` (the substantive grounding — its evidence tables and risk analysis are reused here, EXCEPT where this proposal deliberately supersedes the explore's allowlist-shape recommendation; see ADR-1/ADR-3).
**Split from**: Slice 2 was split into **2a (run the agent)** and **2b (harden network + maintenance)**. The Phase-4 hardware finding then reframed 2b around **autonomy + egress** as the load-bearing pair; the three original environment chores move to a future **2c** by user decision D3.

---

## Why (the problem)

Slice 2a turned the box into a hardened single-tenant agent host — `aios` no-sudo nologin, B2+ systemd hardening, the three-locks managed-settings policy, the `+a`-armed audit log, and `disableBypassPermissionsMode:"disable"` proven live (Layer-3). It also produced **two simultaneous, opposite problems** that 2b exists to resolve, plus a current-state blocker that must be cleared before either can be measured.

**Problem 1 — zero autonomy (the Phase-4 deadlock).** With `defaultMode:"default"` + `permissions.allow:[]` + `disableBypassPermissionsMode:"disable"`, the headless `claude -p` agent has **no approver**. Every Bash tool call falls through to the default permission prompt and **defers** — the agent does zero autonomous work. Re-enabling bypass is forbidden: it would break the hardware-proven Layer-3 wall. So the box is locked into a posture where it is secure precisely because it can do nothing.

**Problem 2 — the open exfil wall.** Post-pivot (ADR-6), the static `ANTHROPIC_API_KEY` lives in the agent's `/proc/<pid>/environ` and is inherited by every Bash-tool child. The live VPS has **zero** egress controls — `ufw inactive`, `nft` ruleset empty, `iptables -P OUTPUT ACCEPT` (orchestrator hardware-verified 2026-06-17). Layer-1 only denies `curl`/`wget`; guardia's `/dev/tcp` rule is a self-admitted speed-bump that any interpreter (`node -e`, `python -c`) defeats. There is **nothing** today that stops the in-environ key from being POSTed over TLS to an attacker host. The egress firewall is therefore not defense-in-depth — it is **the actual exfil wall**, and it does not exist.

**Blocker — the box is DEAD and half-provisioned.** `osgania-agent.service` is failing: `agent-run.sh` is **missing** on the box (`/opt/osgania/platform/bin/` does not exist), `/opt/osgania/client` (the `WorkingDirectory`) is absent, and the journal shows a repeating `Error: Input must be provided either through stdin or as a prompt argument when using --print` loop (`status=1/FAILURE`). The platform tree has mtime `Jun 17 01:42–01:43` and contains only `hooks/` (guardia.sh + camara.sh) — no `bin/` — pointing to a **half-provisioned box** from a partial provision/bats run, NOT a 2a design defect. Even when the wrapper IS deployed, ExecStart passes only `-p` with no prompt source, so the "Input must be provided" failure is **structural**. No autonomy or egress mechanism is observable end-to-end until the run path is restored and a prompt source is wired. This is **STEP 0**.

**Why now**: the box is in its worst possible interim state — incapable of useful work AND wide open to exfil. 2b closes both gaps in the only safe order: prove the wall before opening the door.

---

## Linchpin verified on hardware — Gate #1 result (forced the ADR-1 correction)

**Run 2026-06-17 on the disposable VPS (`root@147.93.187.127`, CLI 2.1.153), as `aios` via `systemd-run` transients with `LoadCredential`, managed-settings + hooks active — the faithful agent runtime. STEP 0 (wrapper reinstall + `/opt/osgania/client`) was completed first; auth confirmed (`apiKeySource:"ANTHROPIC_API_KEY"`).** Each run asked `claude -p` to execute `echo …` via the Bash tool; the stream-json `result` event was inspected for execution vs `tool_deferred`.

| Exp | `permissions.allow[]` | mode | guardia PreToolUse | Bash `echo` |
|-----|------------------------|------|--------------------|-------------|
| baseline | `[]` | default | ON (defers benign) | **DEFERS** (`tool_deferred`, `result:""`) |
| gate-1 | `[echo]` | default | ON | **DEFERS** |
| exp3 | `[echo]` | **dontAsk** (engaged; NOT blocked by `disableBypassPermissionsMode`) | ON | **DEFERS** |
| exp4 | `[echo]` | default | **OFF** | **EXECUTES** (`end_turn`/`completed`, `tool_result`, `is_error:false`) |
| exp5 | `[]` | default | **emits `permissionDecision:"allow"`** | **EXECUTES** |
| exp6 | `[echo]` | default | **emits NOTHING (exit 0, pass-through)** | **EXECUTES** |

**Findings (hardware-proven, superseding the doc-based assumption):**
1. Settings `allow` rules **do** auto-execute a matching Bash call in headless `-p` with no approver (exp4) — **but only when guardia is not deferring.**
2. **guardia's `permissionDecision:"defer"` is terminal in `-p` and PRE-EMPTS settings allow rules — even under `dontAsk` (exp1/2/3).** This is the true mechanism of the Phase-4 deadlock: not merely "no approver", but that guardia defers every benign Bash and that defer wins over the allow rule.
3. A PreToolUse hook emitting `permissionDecision:"allow"` executes in `-p` (exp5 — A4 is viable); a hook emitting NOTHING (pass-through) lets the allow rule fire (exp6).

**The correction this forces (ADR-1, below):** the original ADR-1 — "add `allow[]` + keep guardia deny/**defer**-only" — is REFUTED; those two are mutually exclusive. The fix is surgical and PRESERVES MORE than the original: guardia's benign branch changes from `defer` to **pass-through (exit 0, no decision)** — a PSC R2.7 amendment — keeping guardia **deny-only** (R1.4 intact: it still never emits "allow"). Autonomy is then delivered by `allow[]` + `dontAsk` exactly as the rest of the proposal describes. A4 (guardia-emits-allow) is viable but rejected as unnecessary (it would needlessly amend R1.4). Box left pristine (canonical 2a; key+backup 108 B intact).

---

## Egress simplified + PROVEN on hardware (R3 — 2026-06-17, SUPERSEDES the Squid design)

Gate #4/#5 + a live nft test refuted the premise behind D1's "both layers / Squid SNI" design and replaced it with a simpler, stronger, **hardware-proven** wall.

**Finding (gates #4/#5):** `api.anthropic.com` is NOT Cloudflare-fronted with rotating IPs. It is served from Anthropic's OWN dedicated, **published, stable** range — official doc: inbound **`160.79.104.0/23`** (IPv4) + **`2607:6bc0::/48`** (IPv6), "will not change without notice"; resolved identically from 4 independent resolvers. A live `claude -p` run contacts ONLY `api.anthropic.com` + optional Datadog telemetry (`http-intake.logs.us5.datadoghq.com`). For our headless `ANTHROPIC_API_KEY` agent, `api.anthropic.com` is the ONLY required endpoint.

**New egress architecture (replaces ADR-2 Squid / §3(B) Layer (ii) / Unit 2b):** a single **nftables per-uid(9001) default-deny OUTPUT** wall that allows ONLY: 443 → `160.79.104.0/23` + `2607:6bc0::/48` (Anthropic) and loopback (the agent's DNS goes to the local `127.0.0.53` systemd-resolved stub; **upstream DNS, NTP, and apt are performed by OTHER uids — never uid 9001** — so the floor needs no `80`/`123` and no arbitrary-resolver `53`). Everything else from uid 9001 → DROP. Plus disable telemetry at the unit (`DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1`) so the agent doesn't attempt the Datadog egress (and the wall blocks it regardless). **NO Squid, NO transparent redirect, NO second uid.**

**Why stronger AND simpler than Squid SNI:** IP-pinning to a dedicated published range gives true destination containment with **NO ECH/domain-fronting weakness** (an attacker cannot own an IP in Anthropic's range) and no daemon to run/secure. Squid's only justification (CDN IP rotation) was false.

**PROVEN ON HARDWARE (2026-06-17 — the ruleset below applied + tested as uid 9001, trap-protected):**
- ✅ uid 9001 → Anthropic `160.79.104.10:443` (v4) AND `2607:6bc0::10:443` (v6): REACHABLE.
- ✅ uid 9001 → `1.1.1.1:443`, GitHub `:443`, Cloudflare-v6 `:443`, AND Datadog `34.149.66.137:443`: ALL **BLOCKED**.
- ✅ root UNAFFECTED (uid-scoped rule, policy accept for all else — no SSH/ops lockout).
- ✅ real `claude -p "Reply with ok"` end-to-end UNDER the wall: `apiKeySource:ANTHROPIC_API_KEY`, `result:"ok"`, `is_error:false`, `terminal_reason:completed` (auth + DNS + API all work — gate #7 DNS-coexistence ✓, gate #8 IPv6 ✓).
- ✅ box clean after (nft table flushed).

```
table inet osgania_egress {
  chain out { type filter hook output priority 0; policy accept; meta skuid 9001 jump aios_egress }
  chain aios_egress {
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1/128 accept
    ip daddr 160.79.104.0/23 tcp dport 443 accept
    ip6 daddr 2607:6bc0::/48 tcp dport 443 accept
    counter drop
  }
}
```

**Residual after IP-pin (ADR-5 shrinks):** only (1) exfil over the LEGITIMATE `api.anthropic.com` channel (irreducible for any agent that talks to Anthropic) and (2) low-bandwidth DNS tunneling via the local stub (~108-byte key, bounded). The "HTTPS-to-any-host" hole is CLOSED; the apt-`:80` / NTP-`:123` / ECH residuals are GONE. Both remaining residuals are bounded by single-tenancy (ADR-6).

**Egress gate verdicts:** #4 ✅ stable published range; #5 ✅ only `api.anthropic.com` (+ telemetry, disabled); #6 ✅ `meta skuid 9001` (dedicated uid, no cgroup-timing); #7 ✅ DNS coexists; #8 ✅ IPv6 covered; #10 ✅ Docker-free; #12/#13/#14 ✅ N/A (apt/NTP/upstream-DNS are other uids); #9 (ECH) and #15 (Squid-uid) **MOOT** (no Squid).

**Tradeoff/risk:** if Anthropic changes its published range (they commit to notice), the agent breaks until the provisioner refreshes the CIDR constant — mitigated by the published stability commitment + a refreshable provisioner value.

**Delivery impact:** egress collapses from two units (nft floor + Squid) to ONE proven unit. 2b is now **3 units**: STEP 0 → nft IP-pin egress wall (PROVEN) → broad autonomy (after the wall, per the ordering invariant).

> The Squid-based **ADR-2**, **§3(B) Layer (ii)**, **Unit 2b**, **ADR-5** egress enumeration, and the **ECH (#9) / Squid-uid (#15)** gates below are SUPERSEDED by this section.

---

## What changes (capability description)

2b ships **three things, in a security-mandated order**. After 2b is applied to a (re-provisioned) 2a box, the agent does real autonomous work scoped to its workspace, and every byte leaving the box for a non-Anthropic destination is blocked by a name-based egress wall that the zero-cap, no-sudo `aios` cannot edit or bypass.

### (STEP 0, blocking) Restore the run path + wire the prompt source

Clean full re-provision of the box: install `agent-run.sh` to `/opt/osgania/platform/bin/`, create `/opt/osgania/client`, and reconcile *why* the wrapper was absent before trusting any behavioral measurement (verify-gate #11, re-tiered as a Unit-1 trust precondition — see below). Wire the task/prompt source **inside the wrapper** (option P1: the wrapper reads an operator-controlled prompt file and execs `claude -p "$(cat …)"`). The prompt file is **root-owned and read-only to `aios`** (see ADR-6) so the now-capable agent can never author its own next-run prompt. This keeps ExecStart **byte-identical** to `ExecStart=/opt/osgania/platform/bin/agent-run.sh -p`, preserves the `--bare` ban, and matches the existing export-then-exec wrapper pattern. Until STEP 0 lands, nothing else is testable end-to-end.

### (A) Autonomy — guardia `defer`→pass-through (the gate-#1 fix) + scoped-but-BROAD allowlist + dontAsk-as-CLI-flag

0. **guardia's benign branch changes from `permissionDecision:"defer"` to PASS-THROUGH (exit 0, no decision).** This is the load-bearing fix proven by gate #1 (see "Linchpin verified on hardware"): while guardia defers, the allow rule never fires. guardia stays **deny-only** — dangerous commands still get `deny`/exit-2; only the benign tail stops emitting `defer` and instead lets the permission flow (`allow[]` + `dontAsk`) decide. This is a flagged PSC R2.7 amendment (see the amendments list).

1. **Populate `permissions.allow[]` with a reviewed, BROAD allowlist (D2).** The starter allowlist MAY include build/test/git commands (interpreters node/python and git included) so the agent does genuinely useful work out of the box. The **exact entries are NOT guessed in this proposal**: they are derived from observed real `claude -p` runs after STEP 0 and then reviewed. Hardware-verified (gate #1, exp4/exp6): with guardia passing through (point 0), a settings `allow` rule auto-executes a matching Bash call in headless `-p` with no approver, leaving the bypass switch untouched (precedence is deny → ask → allow, first-match-wins; allow rules are evaluated AFTER deny and can never re-open an inherited deny). Without the guardia change, the allow rule never fires — guardia's `defer` is terminal in `-p` and pre-empts it.

   > **D2 deliberately SUPERSEDES the explore's allowlist-shape rule.** The exploration (explore.md line 90, line 152, line 180, risk row line 193) prescribed an **interpreter-free / network-tool-free** starter allowlist and a bats guard "asserting no forbidden glob in `allow[]`". D2 reverses that and INCLUDES interpreters + git. This reversal is sound **ONLY because** D1 (both egress layers) + the ADR-3 demotion + the delivery-ordering invariant now carry the exfil containment that the interpreter-ban was protecting. The explore's "no forbidden glob" bats guard is intentionally retired and replaced by the tight positive expected-set assertion (ADR-4) plus the egress wall. This dependency is explicit: remove either egress layer and the interpreter-free rule would have to return.

2. **Companion: `--permission-mode dontAsk` applied as a CLI flag inside the wrapper (A2).** Any non-allowed, non-read-only call cleanly auto-**denies** instead of deferring-with-no-approver (the exact Phase-4 hang). Critically, it is set as a **CLI flag**, NOT the managed `defaultMode` field — `defaultMode` stays `"default"` so the HA-09 Phase-4 probe oracle survives.

3. **Mechanisms considered but NOT chosen (explicit):** A4 (guardia emits `permissionDecision:"allow"`) — VIABLE on hardware (exp5 executed), but rejected as unnecessary: the pass-through change (point 0) restores autonomy while keeping guardia deny-only, whereas A4 would amend R1.4 ("guardia never emits allow") for no added benefit. A7 (`--bare`) — skips hook + managed-settings discovery, breaking L1/L2/L3 (HA-06.2 ban). Re-enabling bypass / `--dangerously-skip-permissions` — the NULL option, forbidden.

### (B) Egress — BOTH layers ship in 2b (D1)

4. **Layer (i): nftables per-uid(9001)/cgroup default-deny-OUTPUT floor (B2).** A default-deny OUTPUT chain scoped to **uid 9001 / the `osgania-agent.service` cgroup**, allowing only `443` (Anthropic API path, redirect-only — see #5) + DNS `53` + NTP `123` + apt `80`. Configured by root in the host netns, so the agent unit's `RestrictAddressFamilies` is untouched and the zero-cap aios cannot flush it. This genuinely contains the **raw/non-443 channel class** (arbitrary-port `/dev/tcp`, reverse shells) that guardia only speed-bumps, and scopes blast radius to exactly the untrusted principal (operator SSH/apt untouched, near-zero lockout risk). Covered for IPv4 **and** IPv6 in lockstep. **The `80` (apt) and `123` (NTP) allowances are NOT behind the Squid SNI wall (Squid intercepts 443 only); they are constrained at the nft destination level and folded into the accepted residual — see ADR-2 and ADR-5.**

5. **Layer (ii): transparent-redirected Squid forward proxy with an SNI/CONNECT allowlist to `api.anthropic.com` (B5).** Squid runs under its **own non-aios identity**; uid-9001:443 is **transparently firewall-redirected** into the proxy (this does NOT rely on honor-based `HTTPS_PROXY`). This is the only combination that makes a non-Anthropic destination genuinely unreachable while surviving Cloudflare CDN IP rotation — true *destination* containment, not just *port* containment. Together with Layer (i) it backstops the channels the broad allowlist opens: `git push` over SSH:22 is blocked by nft (only 443/53/123/80 out); `git push` / interpreter sockets over 443 are denied by Squid SNI for any host that is not `api.anthropic.com`. **The Squid service uid is itself egress-constrained**: the nft floor permits the upstream-443 leg ONLY for the Squid uid (not uid 9001, whose 443 is redirect-only), so a compromised Squid uid cannot reach arbitrary 443 hosts beyond the proxy's own SNI allowlist (see ADR-2).

6. **Rejected egress mechanisms (explicit):** B3/B4 (systemd `IPAddressDeny`/CIDR pinning) — Cloudflare shared IPs mean allow-most-of-the-internet, and pinned ranges rotate stale and break the agent; B6 (DNS allowlist only) — a hardcoded-IP TLS POST bypasses DNS entirely.

### Slice-1 AND Slice-2a amendments 2b OWNS (flagged, not silent)

7. **R9.9 relaxed to a TIGHT POSITIVE EXPECTED-SET assertion (Slice-1).** The Slice-1 provisioner gate "`permissions.allow` length MUST be `0`" (provision-agent.sh:454-459) is replaced — NOT deleted — with an assertion that `allow[]` equals **exactly** the reviewed expected-set and rejects anything else. The check is strengthened, not loosened. `defaultMode == "default"` stays asserted (provision-agent.sh:463-468) because dontAsk is applied as a CLI flag, not the managed field.

8. **2a HA-05.3 / HA-05.6 / HA-05-S3 amended (Slice-2a, named explicitly).** The archived 2a spec asserts that `provision-agent.sh` MUST NOT write to `managed-settings.json`, that the file is "byte-identical before and after a 2a run" (HA-05.3, spec line 208), that R9–R12 are structurally unchanged (HA-05.6, line 214), and that `.permissions.allow == []` (scenario HA-05-S3, line 730). Populating `allow[]` directly collides with all three. **2b explicitly amends them** following 2a's own "live-artifact pattern" (the same way 2a extended the live `guardia.sh` with HA-15 while never rewriting the archived `platform-security-core` text): managed-settings.json is no longer byte-identical for 2b (it now legitimately carries the reviewed `allow[]`), and the 2a `allow == []` structural assert is **superseded by the same tight positive expected-set assertion** as the Slice-1 gate. This is a reviewed, flagged 2a spec amendment owned by 2b — NOT a silent mutation of an archived contract. (`defaultMode == "default"`, the six deny entries, `disableBypassPermissionsMode`, `allowManagedHooksOnly`, and the hook entries all stay asserted unchanged.)

9. **PSC R2.7 amended (guardia benign branch: `defer` → pass-through) — Slice-1, named.** platform-security-core R2.7 specifies that a benign Bash command (no denylist match) MUST receive `permissionDecision:"defer"`. Gate #1 proved (exp1/2/3) that `defer` is terminal in headless `-p` and pre-empts settings allow rules — it is the real Phase-4 deadlock. 2b amends R2.7 so guardia's benign branch emits NO decision (exit 0, pass-through, exp6-proven), letting the `allow[]`+`dontAsk` flow decide. All of guardia's DENY logic (R2.1–R2.6 + the 2a HA-15 env-dump/`/dev/tcp`) is UNCHANGED and guardia remains deny-only (R1.4 intact). This is a reviewed, flagged Slice-1 amendment owned by 2b (live-artifact pattern), verified on hardware.

---

## Non-goals (explicitly out of scope for 2b)

- **SSH-sealing of `aios` (D3 → 2c).** `passwd -l aios` does NOT block key login; base spec R2.5 defers the `DenyUsers aios` drop-in. This is the **highest-priority item** for the dedicated future **2c environment-hardening** slice, but it is OUT of 2b.
- **unattended-upgrades drop-in (D3 → 2c).** Security-pocket-only auto-patching with `nodejs npm libnode*` blacklisted. Out of 2b.
- **logrotate under `chattr +a` (D3 → 2c).** Rotating the audit log while preserving the append-only arming. Out of 2b.
- **Timer cadence (D4 → autonomy-ladder).** 2b KEEPS the conservative `OnCalendar=daily` placeholder from 2a. The real autonomy/workload schedule is owned by the separate autonomy-ladder change. Out of 2b.
- **TPM-encrypted key at rest** (`LoadCredentialEncrypted` — the D5 v2 future milestone). Out of 2b.
- **B3-level systemd hardening** (tightening past B2+, gated on `systemd-analyze security` + live profiling). Out of 2b.

These four deferred items are orthogonal, lower-risk OS chores that neither block nor are blocked by autonomy/egress.

---

## Delivery plan (chained PRs / work units — egress-first-proven-before-broad-autonomy)

The delivery **order is itself the security property** (see ADR-3). Work is split into chained PRs / reviewable work units (see the `chained-pr` and `work-unit-commits` standards) so each slice has a clear start, finish, hardware verification, and rollback boundary, and review focus is protected. Each unit is verified on the disposable VPS before the next begins.

### Review Workload Forecast

- **Chained PRs recommended: Yes.** The full 2b change (re-provision wiring + nft v4/v6 + transparent-redirect + Squid daemon config + non-aios identity + provisioner steps + Docker-free assertion + positive-expected-set assertion + host-safe AND Linux-root-deferred bats for all of it) is **well over the 400-line review budget** as a single PR.
- **400-line budget risk: High** for a naive 3-PR split, because the original Unit 2 alone (both nft families + transparent redirect + Squid config + identity + provisioner + Docker-free assert + bats) is near-certain to exceed 400 lines on its own.
- **Decision needed before apply: Yes.** Per the cached `delivery_strategy` and `chain_strategy`, confirm the split below and the chain target (stacked-to-main vs feature-branch-chain). The recommended chain strategy is **`feature-branch-chain`** (rollback control: only the tracker merges to main), given the load-bearing ordering invariant — but this is the user's call at apply time.

### Work units (the egress unit is split to respect the 400-line budget)

1. **PR/Unit 1 — STEP 0: restore the run path + prompt source.** Clean full re-provision; install `agent-run.sh`, create `/opt/osgania/client`, wire prompt-file-in-wrapper (P1) with the prompt file **root-owned, read-only to aios**, keep ExecStart byte-identical and `--bare` banned. Reconcile WHY the wrapper was missing (verify-gate #11) as a Unit-1 trust precondition.
   **Exit criterion:** `systemctl start osgania-agent.service` runs `claude -p` against the policy and produces an audit record; the box is alive and instrumentable. **AND** verify-gate #2 has been resolved: it is PROVEN that no general-purpose interpreter / `eval` runs under dontAsk as "read-only" WITHOUT an explicit allow entry. Egress is still wide open at this point and the broad allowlist is NOT enabled (read-only/defer posture).
   **Conditional — ✅ RESOLVED FAVORABLY 2026-06-17 (gate #2):** the contingency does NOT fire. On hardware, under `dontAsk` + guardia pass-through + `allow:[]`, interpreters (`python3 -c`, `node -e`), `cat`/Read, and writes (`touch`) ALL auto-DENY cleanly; only `echo`-class read-only auto-runs (and `echo` cannot open a socket). So an agent during the egress-open STEP-0/Unit-1 window CANNOT read-and-exfil the in-environ key via an auto-run interpreter. Unit 1 with egress open is therefore safe, and the delivery order need NOT collapse to egress-wall-before-any-`-p`-run.

2. **PR/Unit 2a — THE nft EGRESS FLOOR (v4 + v6), PROVEN.** nftables per-uid(9001)/cgroup default-deny OUTPUT, allowing only 443 (redirect-only for uid 9001) + DNS 53 + NTP 123 + apt 80, IPv4 + IPv6 in lockstep (B2). Constrain 80 to the apt mirror host(s) and 123 to a pinned NTP host at the nft destination level (verify-gates #12/#13). DNS 53 allowed to a pinned resolver (verify-gate #14).
   **Exit criterion (hardware):** from uid 9001, only 443/53/123/80 leave; raw `/dev/tcp` / arbitrary-port connects are blocked; non-mirror :80 and non-NTP-host :123 are blocked; DNS resolves only via the pinned resolver; DNS coexists with `RestrictAddressFamilies` (no `EAFNOSUPPORT` / SC-3 regression); IPv6 is not an open bypass. The broad allowlist is NOT enabled.

3. **PR/Unit 2b — TRANSPARENT-REDIRECTED SQUID SNI WALL, PROVEN HERMETIC.** Squid under a non-aios identity; uid-9001:443 transparently firewall-redirected into the proxy; SNI/CONNECT allowlist `api.anthropic.com`; the Squid uid's own upstream-443 leg is the ONLY non-redirected 443 the nft floor permits (B5).
   **Exit criterion (non-negotiable, hardware):** a TLS POST to a non-Anthropic host from uid 9001 is BLOCKED; `api.anthropic.com:443` still works; the agent's full hostname set resolves and is reachable; no principal other than Squid can open a direct (non-redirected) 443; the SNI wall closes domain-fronting/fake-SNI and the ECH contingency (gate #9) is resolved per ADR-2; the box stays Docker/Coolify-free. The broad allowlist is NOT enabled in this unit.

4. **PR/Unit 3 — BROAD AUTONOMY (reviewed allowlist + dontAsk-as-CLI-flag + R9.9/HA-05 amendments).** Only after the wall (Units 2a + 2b) is proven hermetic. Derive the exact `allow[]` from observed `-p` runs, review it, encode the tight positive expected-set assertion, set dontAsk via CLI flag.
   **Machine-checkable activation gate (non-negotiable — ADR-3):** the Unit-3 provisioner step MUST REFUSE to write a non-empty `permissions.allow[]` unless it can assert, ON THE SAME HOST, that (a) the nft default-deny OUTPUT chain for uid 9001 is loaded, (b) the Squid transparent-redirect for uid-9001:443 is active, and (c) a hermetic-self-check (a TLS POST from uid 9001 to a non-Anthropic host) is BLOCKED. "Egress wall present + hermetic-self-check passes" is a **fail-closed precondition of allowlist activation**, not merely a PR-ordering convention.
   **Exit criterion:** the agent autonomously executes allowed commands; the HA-09 probe still reads VERIFIED; the wall still holds with the agent now capable.

> **DELIVERY-ORDERING INVARIANT (non-negotiable).** The egress wall (Units 2a + 2b, D1) MUST be deployed AND proven hermetic on hardware BEFORE the broad allowlist (Unit 3, D2) is enabled or trusted. This is enforced in TWO places: (1) the chained-PR ordering, and (2) a **fail-closed machine check in the Unit-3 provisioner** that refuses to write a non-empty `allow[]` unless the egress wall is present and a live hermetic-self-check passes on the same host (so a re-provision, a Unit-2 rollback, or an out-of-order operator run cannot land a capable allowlist on a box whose nft/Squid rules are absent or flushed). Rationale: a broad allowlist makes the agent a capable, scriptable principal; enabling it while the proxy is unproven is **capable agent + leaky wall = worst case**. The order STEP 0 → egress-wall-proven → broad-autonomy is a delivery invariant that lives in the ARTIFACT, not just human process, and must survive into the spec/tasks phases.

---

## ADRs / key decisions

### ADR-1 — Autonomy mechanism (gate-#1 CORRECTED): guardia `defer`→pass-through + scoped allowlist + dontAsk-as-CLI-flag
**Decision.** Restore autonomy with THREE coordinated changes: (i) guardia's benign branch emits NO decision (exit 0, pass-through) instead of `permissionDecision:"defer"`; (ii) a populated, reviewed `permissions.allow[]`; (iii) `--permission-mode dontAsk` applied as a CLI flag inside the wrapper. guardia stays deny-only. Re-enabling bypass is forbidden; A7 (`--bare`) rejected; A4 (guardia-emits-allow) viable but not chosen (it would needlessly amend R1.4).
**Rationale (hardware-corrected).** The original ADR-1 — "`allow[]` + keep guardia deny/**defer**-only" — was REFUTED by gate #1: guardia's `defer` is terminal in headless `-p` and pre-empts settings allow rules, even under `dontAsk` (exp1/2/3 all deferred). Allow rules DO auto-execute in `-p` once guardia passes through (exp4/exp6). So the load-bearing fix is the `defer`→pass-through change (preserving guardia deny-only / R1.4), after which `allow[]` auto-approves the allowlisted set and `dontAsk` cleanly auto-denies the unmatched tail (no stall). `dontAsk` is a CLI flag — NOT the managed `defaultMode`, which stays `"default"` — so the HA-09 probe oracle survives (dontAsk confirmed engaged AND not blocked by `disableBypassPermissionsMode` on hardware). **Explicit reversal of the explore:** D2's broad (interpreter + git) allowlist SUPERSEDES the explore's interpreter-free / network-tool-free allowlist-shape rule (explore.md lines 90/152/180/193) and retires its "no forbidden glob" bats guard; valid ONLY because D1 (both egress layers) + ADR-3 (guardia demotion) + the ordering invariant replace the containment the interpreter-ban was providing.
**Preserves.** `disableBypassPermissionsMode:"disable"` (all three changes are independent of it; dontAsk ≠ bypass); the 6-entry Layer-1 deny[]; guardia's Layer-2 DENY veto (R1.4 intact — guardia never emits "allow"; only its benign `defer` becomes pass-through, a flagged PSC R2.7 amendment); the `--bare` ban (A7 rejected).
**Remaining hardware gate (#2).** Under the new posture (guardia pass-through + `dontAsk`), confirm that a non-allowlisted command auto-DENIES cleanly (no stall) and characterize exactly which commands the CLI treats as read-only without an allow entry — the allowlist-sizing + Unit-1-safety contingency (see Preconditions #2).

### ADR-2 — Egress wall ~~(D1: nft floor + Squid SNI)~~ → **R3 SUPERSEDED: nft per-uid IP-pin to Anthropic's published range; Squid DROPPED**
> **⚠️ SUPERSEDED 2026-06-17 (R3, hardware-proven).** `api.anthropic.com` is a STABLE PUBLISHED Anthropic range (`160.79.104.0/23` + `2607:6bc0::/48`), NOT Cloudflare — so the Squid SNI proxy below is REPLACED by a single nft per-uid(9001) IP-pin that gives true destination containment with no ECH weakness, no daemon. See "Egress simplified + PROVEN on hardware". The original Squid text is retained below for history only.
**Decision (ORIGINAL — superseded).** Ship BOTH the nft per-uid(9001)/cgroup default-deny-OUTPUT floor (B2, allow only 443/53/123/80) AND the transparent-redirected Squid SNI/CONNECT allowlist to `api.anthropic.com` (B5) in 2b. Not a follow-up slice.
**Rationale.** The nft floor alone leaves HTTPS-to-any-host open (443 destination unconstrained); name-based SNI filtering is the only rotation-proof way to make a non-Anthropic destination genuinely unreachable. Address-only filters (B3/B4) cannot distinguish Anthropic from other Cloudflare tenants on shared/rotating IPs. Since the broad allowlist (D2) makes exfil trivially scriptable, the true-containment layer must be present from day one, not deferred.
**Port 80 / NTP 123 (NOT behind the SNI wall).** Squid intercepts 443 only, so the `80` (apt) and `123` (NTP) allowances are NOT destination-filtered by the proxy. To avoid silently opening a cleartext :80 exfil channel and an NTP covert channel, the nft floor MUST constrain `80` to the specific apt mirror host(s) and `123` to a pinned NTP host at the destination level (verify-gates #12/#13). The residual that survives even that constraint is folded into ADR-5.
**Two 443 principals (Squid uid constrained).** Because egress is scoped to uid 9001 (redirect-only on 443) while Squid runs under its own non-aios uid, the Squid uid is the ONLY principal whose direct upstream-443 leg the nft floor permits. The floor MUST scope the direct (non-redirected) 443 allowance to the Squid uid alone, and a verify-gate (#15) MUST prove no principal other than Squid can open a direct 443. A compromised Squid uid is still bounded by Squid's own SNI allowlist.
**ECH contingency.** Squid SNI filtering provides destination containment ONLY while the ClientHello SNI is visible. IF verify-gate #9 finds Encrypted ClientHello (ECH) cannot be reliably blocked at the proxy (e.g. by blocking the ECH-advertising DNS HTTPS/SVCB records, or by refusing ECH at Squid), then SNI containment is NOT airtight and the design MUST EITHER widen the residual (ADR-5) OR terminate TLS at the proxy (MITM with a pinned CA) to regain destination visibility. The design phase MUST state which fallback it takes; "true destination containment" is not claimed as proven until gate #9 resolves.
**Preserves.** Operator SSH/apt (blast radius scoped to uid 9001); `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (firewall lives in the host netns, unit unchanged; DNS still works); the zero-cap aios cannot edit or flush the rules.

### ADR-3 — Guardia is DEMOTED to anti-accident; containment rests on egress + single-tenancy; delivery order is the security property
**Decision.** Accept that a broad allowlist (esp. interpreters node/python + git) **demotes guardia (Layer-2) from an exfil control to an anti-accident control**, and make the delivery order (egress-wall-proven BEFORE broad-autonomy) a hard, machine-enforced invariant.
**Rationale.** ADR-7 already admits any interpreter reads its own env and opens sockets. With interpreters in the allowlist, guardia's env-dump and `/dev/tcp` speed-bumps stop being meaningful exfil controls — a node/python one-liner sidesteps them. Therefore exfil containment rests **entirely** on the egress wall (D1) plus single-tenancy (ADR-6). guardia remains valuable as a guard against accidental destructive actions, but it is no longer the exfil boundary. **This is exactly why D2 may include interpreters at all** — the explore's interpreter-free rule was the prior containment, and it is only retired because the egress wall replaces it. The unavoidable consequence: enabling the broad allowlist while the egress wall is unproven yields a capable agent behind a leaky wall — the worst case. So the wall MUST be proven hermetic on hardware first, AND the Unit-3 provisioner MUST fail-closed-refuse to write a non-empty `allow[]` unless a live hermetic-self-check passes on the same host (see the delivery invariant).
**Interpreter-eval contingency — ✅ RESOLVED (gate #2, 2026-06-17).** On hardware, interpreters (`python3 -c`, `node -e`) auto-DENY under `dontAsk` without an allow entry (only `echo`-class read-only auto-runs). So STEP-0/Unit-1's "egress-open is fine because no autonomy yet" safety HOLDS — no interpreter can read-and-exfil the in-environ key before the wall exists. (Once Unit 3 adds the broad allowlist that DOES include interpreters, the egress wall must already be proven — the delivery-ordering invariant.)
**Preserves.** guardia.sh stays **deny-only** (R1.4 intact — it is NOT flipped to emit "allow"; only its benign branch changes from `defer` to pass-through per ADR-1/gate-#1, a flagged PSC R2.7 amendment); the 2a env-dump + `/dev/tcp` DENY rules remain in place; the security MODEL is re-stated honestly rather than weakened silently.

### ADR-4 — Slice-1 R9.8/R9.9 AND Slice-2a HA-05.3/HA-05.6/HA-05-S3 amendment: positive expected-set assertion + dontAsk-as-CLI-flag
**Decision.** Relax R9.9 (`permissions.allow == []`) to a TIGHT positive expected-set assertion (assert exactly the reviewed allow entries; reject anything else; never delete the check). Keep R9.8 (`defaultMode == "default"`) by applying dontAsk as a CLI flag, not the managed field. **Equally amend the archived 2a contract:** HA-05.3 ("managed-settings.json byte-identical / 2a never writes it"), HA-05.6 ("R9–R12 structurally unchanged"), and scenario HA-05-S3 (`.permissions.allow == []`) are superseded for 2b — managed-settings.json now legitimately carries the reviewed `allow[]`, and the 2a `allow == []` assert is replaced by the SAME positive expected-set assertion.
**Rationale.** Adding allow rules collides with BOTH the 2a provisioner gates (provision-agent.sh:454-468) AND the archived 2a spec assertions (HA-05.x). Loosening by deletion would silently regress security-verify; a positive expected-set assertion strengthens the check (it now fails CLOSED on any unexpected entry). Keeping `defaultMode == "default"` preserves the HA-09 Phase-4 probe oracle. Naming the 2a HA-05.x collision explicitly is required: the draft's claim to "mirror how 2a handled apiKeyHelper" is only honest if the 2a requirement being amended is named — otherwise it is the very "silent mutation of an archived contract" this proposal claims to avoid.
**Live-artifact pattern.** This follows 2a's own precedent: 2a extended the LIVE `guardia.sh` (HA-15) while NEVER rewriting the archived `platform-security-core` text. 2b likewise amends the LIVE `managed-settings.json` and flags the amendment in this proposal + the inherited-constraints table, rather than silently rewriting the archived 2a spec.
**Preserves.** The drift-detection contract (never weakened, only made tighter and positive); the HA-09 probe oracle; the six deny entries, `disableBypassPermissionsMode`, `allowManagedHooksOnly`, and the hook entries (all still asserted unchanged); this is a reviewed, flagged spec amendment owned by 2b — not a silent mutation of an archived contract.

### ADR-5 — Accepted irreducible residual (incl. the 80/123/DNS surface the floor opens)
**Decision.** Knowingly accept the residual that survives even a perfect SNI allowlist: (1) exfil smuggled inside the legitimate `api.anthropic.com:443` channel the agent must be allowed to use; (2) low-bandwidth DNS tunneling over the pinned resolver while port 53 is open (the key is only ~108 bytes); (3) **cleartext exfil over the apt `:80` channel and covert-channel exfil over NTP `:123`**, bounded — but not eliminated — by constraining 80 to the apt mirror host(s) and 123 to a pinned NTP host (ADR-2); and (4) **if gate #9 finds ECH cannot be blocked, address-only (IP) containment of 443** until the design adopts a TLS-terminating proxy (ADR-2).
**DNS framing (honest about the declined mitigation).** DNS(53) tunneling is irreducible only GIVEN the deliberate choice to keep a resolver path. The explore (line 197) named the alternative — IP-pinning `api.anthropic.com` to drop DNS entirely — and DECLINED it for fragility. So DNS(53) is allowed to a PINNED resolver, and the residual is framed as "bounded-but-nonzero given a deliberate resolver choice," NOT "unconditionally irreducible." Tunneling over the legitimate pinned resolver still survives; the framing does not erase the declined mitigation.
**Rationale.** No egress filter that MUST allow `api.anthropic.com` can stop data leaving through `api.anthropic.com`. The broad allowlist makes residuals (1)–(3) trivially scriptable but opens **no new class** of exfil beyond what the open ports already permit. This residual is bounded only by single-tenancy + the no-self-exfil property of the channel — exactly as ADR-6 already states.
**Preserves.** Honesty about what the wall can and cannot do; the residual enumeration is now COMPLETE (it no longer silently omits the 80/123/ECH surface); ADR-6's single-tenancy bound is the documented backstop, not a claim of zero residual.

### ADR-6 — Prompt source inside the wrapper (P1), ExecStart byte-identical, prompt file root-owned
**Decision.** Wire the task/prompt source as a file read INSIDE `agent-run.sh`, execing `claude -p "$(cat …)"`. The prompt file MUST be **root-owned and read-only to `aios`** — placed on a `root:root` path (or a non-agent-writable subpath) so it is OUTSIDE the agent-writable area of `/opt/osgania/client`. Reject stdin-pipe (P2) and append-system-prompt-only (P3) as the primary.
**Rationale.** P1 keeps ExecStart byte-identical (`agent-run.sh -p`), preserves the `--bare` ban, and matches the existing export-then-exec pattern. **Prompt-file integrity:** because the now-capable agent (interpreters + write access) runs with `/opt/osgania/client` as a `ReadWritePaths` WorkingDirectory, an agent-writable prompt file would let it rewrite its own next-run prompt — a privilege-escalation-of-intent path. Making the prompt file root-owned and read-only to aios closes that path. P2 breaks the clean `exec claude "$@"`; P3 does not satisfy the `-p` input requirement alone.
**Preserves.** ExecStart byte-identity (provision-agent.sh:629); the `--bare` ban; the LoadCredential→`ANTHROPIC_API_KEY` export wrapper pattern (apiKeyHelper stays abandoned); prompt-file integrity (agent cannot author its own future prompts).

---

## Inherited constraints preserved

| # | Inherited constraint | How 2b preserves it |
|---|---|---|
| 1 | Slice-1 6-entry managed `deny[]` (Layer-1) | Untouched. Deny-first precedence means the broad allow[] (ADR-1) can never re-open a deny. Provisioner still asserts the 6 entries present. |
| 2 | `disableBypassPermissionsMode:"disable"` (Layer-3, hardware-proven) | Untouched. Autonomy comes from allow[]+dontAsk-CLI-flag (ADR-1), both independent of the bypass switch. Bypass / `--dangerously-skip-permissions` is NEVER re-enabled. |
| 3 | guardia PreToolUse denylist incl. 2a env-dump + `/dev/tcp` (Layer-2) | Stays **deny-only** — guardia is NOT flipped to emit "allow" (R1.4 intact). Its DENY rules are unchanged; only the benign branch changes from `defer` to pass-through (PSC R2.7 amendment, gate #1) so `allow[]`+`dontAsk` can drive autonomy. Role honestly re-stated as anti-accident; exfil containment moved to egress (ADR-2/ADR-3). |
| 4 | audit.jsonl `chattr +a` + camara appends + CAP_LINUX_IMMUTABLE | Untouched. 2b adds no directive that clears `+a` or strips the immutable capability; camara still appends. |
| 5 | aios identity (UID/GID 9001, nologin, home `/nonexistent`, not in sudo) | Untouched. The egress firewall is configured by root in the host netns; the zero-cap, no-sudo aios cannot edit or flush it. |
| 6 | Single-tenant-per-VPS (ADR-6 accepted trade-off, key in environ) | Reinforced — it is the documented bound on the irreducible residual (ADR-5). 2b adds nothing multi-tenant. |
| 7 | `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (no AF_NETLINK; DNS works) | Untouched. Egress filtering lives in the host netns / nft, not in the unit's address-family set. DNS+RestrictAddressFamilies coexistence is a hardware verify-gate (#7). |
| 8 | Key delivery via `ANTHROPIC_API_KEY` exported by ExecStart wrapper from LoadCredential (apiKeyHelper ABANDONED) | Preserved. STEP 0 re-provisions exactly this wrapper pattern (ADR-6); apiKeyHelper is NOT reintroduced. |
| 9 | ExecStart byte-identical `agent-run.sh -p` (prompt read INSIDE wrapper) | Preserved. P1 adds the positional prompt arg inside the wrapper (ADR-6), leaving ExecStart string identical. |
| 10 | `--bare` BANNED | Preserved. A7 rejected (ADR-1); the ban guard stays; assembled unit + wrapper still assert `--bare` absent. |
| 11 | 2a HA-05.3/HA-05.6/HA-05-S3: managed-settings.json byte-identical / `allow == []` (post-pivot, 2a never writes it) | **DELIBERATELY AMENDED by 2b (ADR-4), named explicitly — NOT silent.** 2b legitimately writes the reviewed `allow[]` into the LIVE managed-settings.json (live-artifact pattern, mirroring 2a's HA-15 guardia extension); the `allow == []` assert is superseded by the tight positive expected-set assertion. Every OTHER R9–R12 key (deny[], defaultMode, disableBypassPermissionsMode, allowManagedHooksOnly, hooks) stays asserted unchanged. |
| 12 | Prompt-file integrity (capable agent must not author its own next prompt) | Preserved/added. ADR-6: the P1 prompt file is root-owned, read-only to aios, outside the agent-writable WorkingDirectory subtree. |

---

## Preconditions to the SPEC phase (verify-on-hardware gates)

Gates #1–#10 and #12–#15 MUST pass on the disposable VPS BEFORE a single spec line is written — they are the hardware truths the spec assertions will depend on; writing spec text before they are VERIFIED would encode guesses. Gate #11 is RE-TIERED (see note) as a Unit-1 trust precondition, NOT a hard block on the spec phase.

1. **(#1, the linchpin) — ✅ VERIFIED 2026-06-17 (with a correction).** A `claude -p` run with populated `permissions.allow` rules auto-EXECUTES a matching Bash call (no approver) on CLI 2.1.153 under managed `disableBypassPermissionsMode:disable` — **but ONLY once guardia stops deferring** (benign `defer`→pass-through; see the "Linchpin verified on hardware" section + ADR-1). With guardia deferring, the allow rule is pre-empted (the Phase-4 deadlock). Proven via exp4/exp6; the gate PASSES with the guardia change incorporated.
2. **The exact dontAsk read-only command set — ✅ VERIFIED 2026-06-17 (favorable).** Hardware result (guardia pass-through, `allow:[]`, dontAsk): `echo` auto-runs (read-only); but `cat` (Bash AND Read tool), `python3 -c`, `node -e`, and `touch` ALL **auto-DENY cleanly** (`terminal_reason:"completed"`, `permission_denials` populated — NO stall). **Interpreters do NOT auto-run without an allow entry**, so the feared read-key-then-exfil-during-Unit-1 contingency DOES NOT fire; Unit-1 with egress open is safe. The read-only autorun set is narrow (echo-class), so the BROAD allowlist (D2) must explicitly enumerate build/test/git — they will not auto-run. (`echo $VAR` can still print env to the journal — a pre-existing ADR-6 local-only residual, not exfil.)
3. **HA-09 probe survival** — the Phase-4 probe still classifies VERIFIED when dontAsk is applied as a CLI flag with managed `defaultMode == "default"`.
4. **Anthropic egress topology** — stable dedicated egress range vs purely Cloudflare shared/rotating IPs.
5. **Full hostname set the `claude` CLI contacts in `-p`** — an over-tight SNI/DNS allowlist breaks the agent if any host is missed.
6. **nft cgroup-match timing on `Type=oneshot`** — is the cgroup path stable before first connect? Else fall back to the uid-9001 skuid match.
7. **DNS + `RestrictAddressFamilies` coexistence** — nft/egress filtering does not break DNS (no `EAFNOSUPPORT` / SC-3 regression).
8. **IPv6 coverage in lockstep** — ip6tables/nft inet + AAAA, or v6 is an open bypass.
9. **Squid SNI airtightness + ECH contingency** — closes TLS domain-fronting / fake-SNI; resolves whether ECH (Encrypted ClientHello) can be blocked at the proxy. If ECH cannot be blocked, the design adopts the ADR-2 fallback (block ECH DNS HTTPS/SVCB records, refuse ECH at Squid, OR TLS-terminating proxy) BEFORE claiming destination containment. The proxy is non-bypassable via transparent redirect, NOT honor-based `HTTPS_PROXY`.
10. **Box stays Docker/Coolify-free** — Coolify/Docker would insert DOCKER nft chains ahead of the egress rules and bypass them.
11. **(RE-TIERED) Reconcile WHY `agent-run.sh` was missing** — half-provisioned box (mtime 01:42, hooks-only tree) vs failed install. This is a forensic reconciliation that the spec assertions do NOT depend on; per the explore (line 171) its real role is to make STEP 0 behavioral measurements TRUSTWORTHY. It is therefore a **Unit-1 exit-criterion / trust precondition**, NOT a hard block on writing spec text for gates #1–#10/#12–#15.
12. **apt `:80` mirror constrainability** — the apt mirror host(s) can be pinned at the nft destination level so non-mirror `:80` is blocked (ADR-2/ADR-5).
13. **NTP `:123` host constrainability** — `123` can be pinned to a fixed NTP host so arbitrary `:123` is blocked (ADR-2/ADR-5).
14. **DNS `:53` resolver pinning** — `53` can be constrained to a single pinned resolver without breaking the CLI hostname set (ADR-5; the explore's declined-IP-pinning alternative is documented, not silently dropped).
15. **Squid-uid egress containment** — the direct (non-redirected) `443` allowance is scoped to the Squid uid ALONE; no principal other than Squid (and specifically not uid 9001 directly) can open a direct 443 (ADR-2).

---

## Impact

**Affected files / artifacts:**
- `platform/managed-settings.json` — gains the reviewed broad `permissions.allow[]` (live operator artifact; `defaultMode` stays `"default"`, deny[] and `disableBypassPermissionsMode` unchanged). **This is the 2a HA-05.3/HA-05.6 "byte-identical" amendment 2b owns (ADR-4), not a silent change.**
- `platform/bin/agent-run.sh` (the wrapper) — re-provisioned (STEP 0); reads the **root-owned, aios-read-only** prompt file (P1); applies `--permission-mode dontAsk` as a CLI flag; keeps the LoadCredential→`ANTHROPIC_API_KEY` export; `--bare` still banned.
- `platform/hooks/guardia.sh` — **benign branch changes from `permissionDecision:"defer"` to pass-through (exit 0, no decision)** (gate #1 / ADR-1 / PSC R2.7 amendment). All DENY logic (sudo/curl/wget/rm-rf/disk-wipe/secrets/platform/env-dump/`/dev/tcp`) is UNCHANGED; guardia stays deny-only (R1.4). bats updated: benign Bash now yields NO PreToolUse decision (was `defer`); denies unchanged.
- `osgania-agent.service` (the unit) — ExecStart kept byte-identical (`agent-run.sh -p`); `OnCalendar=daily` timer placeholder kept (D4); no egress directives added to the unit (firewall is host-netns).
- `scripts/provision-agent.sh` — STEP 0 clean re-provision (install `bin/agent-run.sh`, create `/opt/osgania/client`, install the root-owned prompt file); R9.9 gate (lines 454-459) replaced with the positive expected-set assertion; R9.8 gate (463-468) retained; the **fail-closed Unit-3 allowlist-activation gate** (refuse non-empty allow[] unless egress wall present + live hermetic-self-check passes); new steps to install the firewall + Squid config and assert the box is Docker/Coolify-free.
- **NEW: nftables egress config + transparent-redirect ruleset** (per-uid 9001 / cgroup default-deny OUTPUT; allow 443/53/123/80 with 80→apt-mirror, 123→pinned-NTP, 53→pinned-resolver, direct-443→Squid-uid-only, uid-9001:443→redirect-only; v4+v6).
- **NEW: Squid config** (SNI/CONNECT allowlist `api.anthropic.com`; non-aios identity; transparent intercept; ECH handling per gate #9).
- **NEW: bats tests** — host-safe assertions for the firewall/Squid config assembly, the allowlist positive-expected-set assertion, the `--bare`/dontAsk-CLI-flag invariants, the prompt-in-wrapper wiring AND the root-owned/aios-read-only prompt-file ownership; Linux-root-deferred assertions for the hermetic-wall behavior, the 80/123/53 destination constraints, and the Squid-uid egress scoping on the disposable VPS.
- **Slice-1 + Slice-2a spec amendment** — R9.8/R9.9 AND 2a HA-05.3/HA-05.6/HA-05-S3 documented as 2b-owned, reviewed amendments (ADR-4), not silent changes.

**Affected target:** the disposable single-tenant VPS (`root@147.93.187.127`, currently DEAD/half-provisioned). STEP 0 returns it to a live 2a end-state before 2b layers autonomy + egress on top.

---

## Risks and mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Headless `-p` allow-rule auto-approval — ✅ RESOLVED 2026-06-17. Gate #1 proved allow rules DO auto-execute in `-p`, BUT guardia's `defer` pre-empts them (the real Phase-4 deadlock). | Resolved | Fix incorporated into ADR-1: guardia benign `defer`→pass-through (PSC R2.7 amendment, exp6-proven); autonomy via `allow[]`+`dontAsk`, guardia deny-only. |
| Live VPS is DEAD (wrapper missing, client dir absent, "Input must be provided" loop). Nothing testable end-to-end until the run path is restored. | **Critical** | STEP 0 (PR/Unit 1): clean re-provision + root-owned prompt-in-wrapper; reconcile WHY the wrapper was missing (gate #11, Unit-1 trust precondition) before measuring behavior. |
| **Broad allowlist + unproven egress wall = capable agent behind a leaky wall (worst case).** The broad allowlist (interpreters + git) makes exfil trivially scriptable; guardia no longer contains it (ADR-3). | **Critical** | The delivery-ordering invariant enforced in TWO places: chained-PR ordering AND a fail-closed Unit-3 provisioner gate that refuses to write a non-empty allow[] unless the egress wall is present and a live hermetic-self-check passes on the same host. Non-negotiable. |
| Interpreter-eval auto-run read-only with NO allow entry — ✅ RESOLVED 2026-06-17 (gate #2). | Resolved | Hardware: `python3 -c`/`node -e`/`cat`/`touch` ALL auto-DENY under dontAsk+guardia-pass-through; only `echo`-class read-only auto-runs (cannot open a socket). Unit-1-with-egress-open is safe; no forced reorder. Interpreters execute only once Unit 3 allowlists them — by then the egress wall is proven (delivery invariant). |
| nft per-uid 443-anywhere floor alone leaves HTTPS-to-any-host open — the in-environ key can be POSTed over TLS via node/SDK with no curl/wget. | High | Both layers ship in 2b (ADR-2): Squid SNI (B5) constrains the 443 destination to `api.anthropic.com`; uid-9001:443 is redirect-only. Floor is documented as NOT closing HTTPS-to-any-host on its own. |
| Address-only filters (B3/B4) cannot distinguish `api.anthropic.com` from other Cloudflare tenants on shared/rotating IPs. | High | Reject IP-pinning as the wall (ADR-2); use SNI (B5). Verify Anthropic egress topology (gate #4). |
| **ECH (Encrypted ClientHello) would make SNI invisible, collapsing Squid destination containment to IP-only** — exactly what ADR-2 rejects for Cloudflare. | High | Gate #9 resolves ECH first. ADR-2 contingency: block ECH DNS HTTPS/SVCB records, refuse ECH at Squid, OR adopt a TLS-terminating proxy (pinned CA) BEFORE claiming true destination containment. |
| **apt `:80` (cleartext) and NTP `:123` (covert channel) are open OUTSIDE the SNI wall** — the floor silently widens the egress surface. | Medium | ADR-2: constrain `80` to the apt mirror host(s) and `123` to a pinned NTP host at the nft destination level (gates #12/#13); fold the bounded residual into ADR-5's enumeration (no silent widening). |
| Relaxing the 2a drift gates (allow==0, defaultMode==default) AND the archived 2a HA-05.3/HA-05.6/HA-05-S3 contract could silently regress security-verify if done by deletion or left unnamed. | Medium | ADR-4: replace allow==0 with a positive expected-set assertion (fails closed on any unexpected entry); keep defaultMode==default via dontAsk-CLI-flag. BOTH the Slice-1 gate AND the named 2a HA-05.x contract are flagged as 2b-owned amendments (live-artifact pattern), not silent changes. |
| A capable agent could rewrite its own next-run prompt if the P1 prompt file lives in the agent-writable WorkingDirectory (privilege-escalation-of-intent). | Medium | ADR-6: the prompt file is root-owned, read-only to aios, outside the agent-writable subtree; bats asserts ownership/mode. |
| nft cgroup match on `Type=oneshot` may not key on a stable cgroup before first connect; DNS (uid 0) could bypass a per-uid aios rule. | Medium | Verify cgroup timing (gate #6); fall back to uid-9001 skuid match; place the DNS allowance correctly; cover IPv6 in lockstep (gate #8). |
| Squid's OWN non-aios uid making the upstream 443 leg means TWO principals can reach 443; a compromised Squid uid could reach arbitrary 443 hosts. | Medium | ADR-2: scope the direct (non-redirected) 443 allowance to the Squid uid alone; uid-9001:443 is redirect-only; verify-gate #15 proves no other principal can open a direct 443. |
| Changing defaultMode to dontAsk in MANAGED settings would break the HA-09 Phase-4 probe oracle. | Medium | dontAsk applied as a CLI flag; managed defaultMode stays `"default"` (ADR-4); verify probe still reads VERIFIED (gate #3). |
| Squid SNI-only ACL bypassable via TLS domain-fronting / fake-SNI; `HTTPS_PROXY` is honor-based. | Medium | Make the proxy non-bypassable via transparent firewall redirect (not HTTPS_PROXY); run Squid under a non-aios identity; verify it closes domain-fronting (gate #9). |
| Unit 2 (full egress wall) as a single PR exceeds the 400-line review budget. | Medium | Split into Unit 2a (nft floor v4+v6, proven) and Unit 2b (transparent-redirect + Squid SNI, proven hermetic), each with its own hardware exit criterion; chain strategy stated at apply time (Review Workload Forecast). |
| Future Docker/Coolify install inserts DOCKER nft chains ahead of the egress rules. | Low | Verify box stays Docker/Coolify-free (gate #10); document a hard prerequisite or add ufw-docker-style reconciliation. |
| **Irreducible residual (accepted, ADR-5):** exfil over the legitimate `api.anthropic.com:443` channel + low-bandwidth DNS tunneling over the pinned resolver (~108-byte key) + bounded apt-`:80`/NTP-`:123` channels. The broad allowlist makes it trivially scriptable. | Accepted | No new class is opened beyond the open ports. DNS is bounded by resolver pinning (the explore's IP-pin alternative was considered and declined for fragility). Bounded only by single-tenancy (ADR-6). Documented honestly; not claimed closed. |
| Append-flood / disk-exhaustion of writable paths by a now-capable autonomous agent (chattr +a protects integrity, not volume). | Low | Accept as residual; addressed by the deferred logrotate (D3 → 2c) + optional disk quota. |

---

## Next step

**Progress (2026-06-17): STEP 0 restore DONE + gate #1 VERIFIED on hardware (with the ADR-1 correction above).** Continue the remaining verify-on-hardware gates on the disposable VPS — next is gate #2 (does a non-allowlisted command auto-DENY cleanly under guardia-pass-through + `dontAsk`, and which commands count as read-only without an allow entry) because Unit-1 safety is contingent on it, then the egress gates. ONLY once the remaining gates (#2, #4–#10, #12–#15) are VERIFIED (gate #11 is a Unit-1 trust precondition, not a spec-phase block), run `sdd-spec` (encode the 2b end-state as Given/When/Then with RFC-2119 keywords, the delivery-ordering invariant AND its fail-closed machine check, the positive expected-set assertion covering both the Slice-1 gate and the named 2a HA-05.x amendment, the root-owned prompt-file ownership, and the hermetic-wall behavior incl. the 80/123/53/Squid-uid constraints) and `sdd-design` (resolve the firewall/Squid topology incl. the ECH fallback, the exact reviewed allowlist derived from observed `-p` runs, and the transparent-redirect mechanics) — these two can run in parallel from this proposal.
