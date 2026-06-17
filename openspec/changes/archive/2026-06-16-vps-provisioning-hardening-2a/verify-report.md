# Verify Report — vps-provisioning-hardening-2a

**Date**: 2026-06-16
**Phase**: sdd-verify (fresh-context independent review)
**Status**: PASS (warnings remediated)

## Test evidence
- macOS host-safe: `bats tests/` = **224 ok / 0 fail** (LINUX-ROOT + LIVE-KEY tiers correctly skip-gated).
- VPS (root@147.93.187.127, real systemd, Ubuntu 24.04 / bash 5.2 / GNU grep): full mutation tier via `scripts/run-live-key-tests.sh` = **224 ok / 0 fail / 1 skip** (the skip is HA-12-S1 OPERATOR-MANUAL).
- `shellcheck -s bash` clean on all four scripts (`provision-agent.sh`, `run-live-key-tests.sh`, `agent-run.sh`, `guardia.sh`).

## Drift checks (normative literals verified verbatim — 0 CRITICAL)

| Check | Result |
|-------|--------|
| HA-15.2 `/proc/(self\|thread-self\|[0-9]+\|\$\$\|\$BASHPID\|\$[A-Za-z_][A-Za-z0-9_]*\|\$\{[^}]*\})(/task/[^/]+)?/environ` ERE — spec vs `guardia.sh` | IDENTICAL |
| HA-09 permissionMode oracle — `bypassPermissions`→FAILED(non-zero), `default`→VERIFIED, empty→UNVERIFIED | matches `_classify_bypass_probe` |
| No two-marker (`.probe-alive`/`.probe-leak`) logic left in the live probe | confirmed (comments only) |
| HA-05.1c obsolete-helper cleanup (`rm -f anthropic-key.sh`) | present in `install_wrapper` |
| HA-06 `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` only (NOT API_KEY); `LimitCORE=0`; `RestrictAddressFamilies`; `LoadCredential` | matches unit |
| HA-15.5a `/dev/tcp`,`/dev/udp` substring deny | present |
| HA-13-S1 re-tiered LINUX-ROOT (audit log +a, no live tool) | matches test (`skip_unless_linux_root_mutation`) |

## Warnings — all remediated
- **W-1** tasks.md WU-1..WU-6 sub-checkboxes were unchecked despite "COMPLETE" banners → ticked.
- **W-2** WU-4 GREEN bullet referenced the superseded two-marker oracle → corrected to the permissionMode oracle.
- **W-3** `_assert_r9_r12_invariant` tolerates a pre-existing `apiKeyHelper` key → **NOT a drift**: HA-05.3 requires 2a to leave `managed-settings.json` byte-identical (read-only) and to ADD no key; rejecting a pre-existing `apiKeyHelper` would violate the "do not touch managed-settings" contract. Correct as-is.
- **S-1 / S-2** stale test-file comments (HA-08-S1 title, suite header count) → corrected.

## Verdict
PASS — implementation matches spec, design, and tasks on every normative requirement; no archive blockers. The Phase-4 hardware findings (managed `disableBypassPermissionsMode` neutralizes the bypass flag → permissionMode oracle; the agent defers all bash autonomously) are encoded in the re-amended ADR-5 / HA-09 and verified on the real systemd unit.

## Note for Slice 2b
As configured (`defaultMode: default`, `allow: []`, `disableBypassPermissionsMode: disable`), the headless agent DEFERS every Bash tool (no approver in `-p`) — maximally safe for 2a's guardrail goal, but the agent performs no autonomous work. 2b must add an allowlist / approval path for the agent to execute its task.
