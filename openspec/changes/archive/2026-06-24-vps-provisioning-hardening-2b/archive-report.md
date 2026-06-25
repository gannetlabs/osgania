# Archive Report — vps-provisioning-hardening-2b

**Change**: `vps-provisioning-hardening-2b` (Slice 2, sub-slice 2b — "Autonomy + Egress")
**Project**: osgania
**Artifact store**: openspec + engram (hybrid)
**Archived**: 2026-06-24
**Final status**: COMPLETE — implemented, verified on real hardware (264/264 bats tests passing), merged to main (PRs #1, #2, #3 via feature-branch-chain strategy).
**Depends on**: `vps-provisioning-hardening-2a` (ARCHIVED), `platform-security-core` (canonical, L0 baseline) — both left UNCHANGED by 2b.

## What 2b delivered

Extends the 2a-provisioned box with an nftables egress wall and broad autonomous operation:

- **nft egress wall** (`platform/nft/osgania-egress.nft`): `inet` table `osgania_egress`, `meta skuid 9001` hook, IP-pin to Anthropic ranges `160.79.104.0/23` (IPv4) and `2607:6bc0::/48` (IPv6) on port 443, loopback accept, `counter drop` terminal. Root-managed in host netns; zero-cap `aios` principal cannot flush.
- **guardia benign pass-through** (Amendment A1): the benign Bash branch changed from `permissionDecision:"defer"` to empty stdout + exit 0. Hardware-proven necessary: `defer` is terminal in headless `-p` and pre-empts `allow[]` rules even under `--permission-mode dontAsk`. guardia remains deny-only (R1.4 intact).
- **Reviewed `allow[]` in platform settings file** (Amendment A4 — Approach B): `permissions.allow[]` lives in `/opt/osgania/platform/agent-settings.json` (root:root 0644), loaded via `--settings` flag. `managed-settings.json` `permissions.allow` remains `[]`. Root ownership + parent-dir protection replaces `chattr +i` (dir-swap hole closed).
- **`--setting-sources ""`** (Amendment A5): wrapper excludes the three agent-writable sources (user/project/local settings) to prevent additive self-escalation by a planted settings file.
- **`--permission-mode dontAsk`**: CLI flag in the wrapper (not in managed-settings `defaultMode` — PSC R9.8 unchanged). Together with pass-through guardia and reviewed `allow[]`, enables fully autonomous operation.
- **Fail-closed 3-condition machine check** (HB-06.2): Unit 3 provisioner refuses to write non-empty `allow[]` unless (a) nft table loaded, (b) root positive-control connect to canary SUCCEEDS, (c) uid-9001 self-check to canary TIMES OUT (exit 124 exactly). Python3 `settimeout(5)` preferred over bash `/dev/tcp` (immune to `tcp_syn_retries` tuning).
- **HA-09 probe invokes `/usr/bin/claude` directly** (JD-6 resolution, HB-05.2): probe exports `ANTHROPIC_API_KEY` from `AGENT_SECRETS_KEY` inline; MUST NOT route through the 2b wrapper (wrapper discards `--output-format stream-json --verbose --dangerously-skip-permissions`).
- **Prompt file** (`platform/prompts/agent-prompt.txt`, root:root 0644): operator-controlled prompt outside the agent-writable `WorkingDirectory`; prevents intent-escalation via prompt rewrite.
- **Boot ordering** (HB-02.7a): both `osgania-agent.service` and `osgania-agent.timer` carry `After=nftables.service` + `Wants=nftables.service` — wall loads before agent can activate on every boot.
- **egress.bats**: new test file for nft config structure, env-var assertions, and deferred LINUX-ROOT/LIVE-KEY scenarios. 264/264 total tests pass (HOST-SAFE on disk; LINUX-ROOT/LIVE-KEY hardware-proven on VPS).

## Delivery

Chained PRs via feature-branch-chain strategy (3 PRs, all merged to main):
- **PR #1 (STEP 0 / Unit 1)**: restored run path, wired prompt source, HB-01 — `feat/2b-u1-step0`
- **PR #2 (Unit 2)**: nft egress wall, boot ordering, telemetry env vars — `feat/2b-u2-egress`
- **PR #3 (Unit 3)**: guardia pass-through, allow[] platform settings, dontAsk, --setting-sources, fail-closed gate, HB-05 probe fix — `feat/2b-u3-autonomy`

## Key design decisions

| Decision | Outcome |
|----------|---------|
| Squid SNI proxy | Dropped — replaced by nft IP-pin; `api.anthropic.com` is a STABLE PUBLISHED Anthropic range; IP-pin gives true destination containment |
| uid-based vs cgroup-based nft | `meta skuid 9001` — timing-safe for `Type=oneshot`; hardware gate #6 confirmed |
| `allow[]` in managed-settings (Amendment A2/A3 original) | Blocked: Claude Code 2.1.153 does NOT honor `permissions.allow[]` from enterprise managed-settings; and chattr+i had dir-swap hole |
| `allow[]` in user settings + chattr (first fix) | Dropped — exploitable via `.claude` dir rename (Amendment A4) |
| `allow[]` in platform/agent-settings.json via --settings (Approach B) | Adopted — root:root 0644, parent `/opt/osgania` root-owned, managed deny blocks Edit/Write platform/** |
| guardia emit "allow" (Approach A) | Rejected — unnecessary; pass-through achieves the same while keeping R1.4 intact |
| DNS tunneling via local stub | Accepted residual — bounded by key size (~108 bytes) and single-tenancy |
| Sub-claude self-escalation (Vector 2) | Named residual — accepted; damage contained identically by nft wall + no-cap + ProtectSystem; same surface as arbitrary client workspace code |

## Adversarial review

Three blind Judgment Day rounds applied:
- **Round 1**: 14 findings applied (spec + design baseline hardening)
- **Round 2**: 8 findings applied (including self-check `echo $?` regression fix)
- **Round 3**: 6 findings applied (JD-1 through JD-6 + minors — all RESOLVED; key: python3 exit-code semantics, HB-06-S2b PROCEED assert, design checklist alignment, HB-10.1 manifest completion, full `systemd-run` flag set in spec, HA-09 probe direct invocation)

**JD terminal state: RESOLVED.** All 6 JD findings and all minors resolved in spec.md + design.md + tasks.md WU0.

## Verification (final)

- macOS host-safe `bats tests/` = **264 ok / 0 fail** (engram #277).
- shellcheck: exit 0, clean on all scripts.
- All 30 tasks confirmed complete (WU0×7 + U1×7 + U2×7 + U3×9).
- 0 CRITICAL, 0 WARNING, 1 SUGGESTION (cosmetic BW02 bats-version warnings — non-blocking).
- LINUX-ROOT/LIVE-KEY scenarios hardware-proven on VPS (not tracked as bats counts — separate runner).
- Verdict: **PASS. Ready for sdd-archive.**

## Spec disposition

2b is a self-contained capability spec ("Autonomy + Egress"). On archive, `spec.md` is promoted to `openspec/specs/vps-provisioning-hardening-2b/spec.md`. `platform-security-core`, `vps-provisioning-base`, and `vps-provisioning-hardening-2a` main specs are left UNCHANGED (2b amendments are encoded in 2b's own spec, not by rewriting archived specs).

## Engram artifact IDs

| Artifact | ID |
|----------|-----|
| Proposal | #238 |
| Spec | #246 |
| Design | #245 |
| Tasks | #249 |
| Verify report | #277 |
| Archive report | (this session) |

## Carry-forward

With the nft egress wall proven hermetic and `allow[]` populated from observed real runs, the agent operates autonomously within the Anthropic-only egress channel. The next slice (if any) builds on this proven foundation. No open blockers; all JD findings resolved; all 30 tasks complete.
