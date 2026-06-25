# Verify Report — vps-provisioning-hardening-2b

**Change**: `vps-provisioning-hardening-2b` (Slice 2b — "Autonomy + Egress")
**Project**: osgania
**Verified**: 2026-06-24 (pre-archive gate; change already merged to main, head 8173330)
**Status**: **PASS** — 0 CRITICAL, 0 WARNING, 1 SUGGESTION (cosmetic)
**Engram**: `sdd/vps-provisioning-hardening-2b/verify-report` (#277)

## Method

Verification ran against the implementation live on `main` (the change was merged via
feature-branch-chain before archive). Runtime/hardware behaviors were treated as recorded
evidence (engram #251, #269, #275 — hardware-proven on the disposable VPS, dual-judge ×3);
this report validates **spec-contract conformance** of the code on disk, not first-time
runtime correctness.

Ground truth was established directly on disk (not taken from any agent self-report):

- `bats tests/` → **264 ok / 0 fail, exit 0** (the `BW02` lines are benign bats-version
  warnings, not failures).
- `shellcheck platform/bin/agent-run.sh platform/hooks/{camara,guardia}.sh
  scripts/{provision-agent,provision,run-live-key-tests}.sh` → **exit 0, clean**
  (local shellcheck 0.11.0; the box's stricter 0.9.0 also passed per #269).
- All `tasks.md` checkboxes checked.

## Requirements conformance (HB-01 … HB-10)

Every spec requirement maps to implementation on disk with a covering test. Selected
load-bearing rows (full matrix in engram #277):

| Requirement | Evidence (file:line) | Test |
|---|---|---|
| HB-01.3 — canonical exec line `--settings "$AGENT_SETTINGS_FILE" --setting-sources ""` | `platform/bin/agent-run.sh:50` | HB-01-S2 |
| HB-01.8 — `-p` guard via arg loop (not substring) | `platform/bin/agent-run.sh:31-39` | HB-01-S2b |
| HB-02.1 — `table inet osgania_egress`, `meta skuid 9001 jump aios_egress` | `platform/nft/osgania-egress.nft:23-35` | HB-02-S1 |
| HB-02.2/.4 — both Anthropic CIDRs as single-source provisioner constants | `scripts/provision-agent.sh:55-56`; `platform/nft/osgania-egress.nft:29-32` | HB-02-S2 |
| HB-02.7a — `After=`/`Wants=nftables.service` on BOTH service + timer | `platform/systemd/osgania-agent.{service,timer}` | HB-02-S2c/S2d |
| HB-03.2/A4 — managed `allow==[]` always; reviewed allow in platform file | `scripts/provision-agent.sh:564-570`, `:1285-1302` | HB-03-S1/S2/S5/S6 |
| HB-03.7/A5 — `--setting-sources ""` blocks additive self-escalation | `platform/bin/agent-run.sh:50` | HB-01-S2; hardware #269 |
| HB-05.2 — HA-09 probe calls `/usr/bin/claude` directly, no `dontAsk` | `scripts/provision-agent.sh:930-942` | HB-05-S1 |
| HB-06.2 — 3-condition fail-closed gate, uid-9001 exit **exactly** 124 | `scripts/provision-agent.sh:1151-1238` | HB-06-S2d; hardware U3-T8 |
| HB-10.2 — shellcheck clean | `shellcheck` exit 0 (6 scripts) | HA-05-S5/HA-06-S5 |

## Independent orchestrator confirmation (anchors re-checked on disk)

The three contract anchors were re-verified directly (not trusted from the verify agent):

1. **Exec line** — `platform/bin/agent-run.sh:50`:
   `exec /usr/bin/claude --permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p "$(cat "$PROMPT_FILE")"` — both flags present.
2. **Managed allow==[] invariant** — `scripts/provision-agent.sh:527-570`: `expected_allow="[]"`,
   `live_allow="$(jq -cS '.permissions.allow' "$f")"`, fail-closed on mismatch.
3. **Egress + gate** — CIDRs `ANTHROPIC_EGRESS_V4="160.79.104.0/23"` / `V6="2607:6bc0::/48"`
   (`:55-56`), nft `meta skuid 9001 jump aios_egress`, gate `except TimeoutError: sys.exit(124)`
   with the mandatory `TimeoutError`-before-`OSError` ordering (`:1190`, `:1222`).

## Findings

- **CRITICAL**: 0
- **WARNING**: 0
- **SUGGESTION**: `BW02` bats-version warnings in `tests/provision-agent.bats`
  (lines 1011, 1019, 1024). Add `bats_require_minimum_version 1.5.0` to silence. Non-blocking;
  tests pass identically.

## Verdict

**PASS — ready for archive.** Implementation faithfully matches the 2b contract; tests green;
shellcheck clean; runtime behaviors hardware-proven and recorded. The one open item is cosmetic.
