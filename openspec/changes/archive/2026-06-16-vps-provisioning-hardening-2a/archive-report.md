# Archive Report — vps-provisioning-hardening-2a

**Change**: `vps-provisioning-hardening-2a` (Slice 2, sub-slice 2a — "Run the agent")
**Project**: osgania
**Artifact store**: openspec
**Archived**: 2026-06-16
**Final status**: COMPLETE — implemented, hardened, verified on real hardware, remediated, verified by fresh review.
**Depends on**: `vps-provisioning-base` (Slice 1), `platform-security-core` (L0 baseline) — both archived, both left UNCHANGED by 2a.

## What 2a delivered
Extends a Slice-1-provisioned box with the agent runtime + launch layer:
- **Node/CLI runtime**: Node ≥ 18, Claude Code CLI pinned at 2.1.153.
- **Launch wrapper** `platform/bin/agent-run.sh` (root:root 0755): sources the Anthropic key from the systemd `LoadCredential` tmpfs (`$CREDENTIALS_DIRECTORY`), `tr`-normalizes whitespace (SC-1), exports `ANTHROPIC_API_KEY`, fails closed, `exec`s the CLI.
- **systemd unit** `platform/systemd/osgania-agent.service` + `.timer`: `ExecStart`=wrapper, `User=aios`, `LoadCredential`, `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN`, `LimitCORE=0`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `ProtectSystem=strict`, `WorkingDirectory=/opt/osgania/client`.
- **guardia.sh step 7.5** (env-dump + bash-native egress denial, HA-15) — the speed-bump mitigation for the post-pivot env-key exposure.
- **provision-agent.sh** — idempotent provisioner: installs the wrapper (and removes the obsolete pre-pivot `anthropic-key.sh`), verifies `managed-settings.json` read-only, writes the units, runs the live defense-in-depth probe, enables the timer (no `--now`, SC-2).

## THE PIVOT (ADR-1 SUPERSEDED → ADR-6)
`apiKeyHelper` was abandoned: Claude Code CLI 2.1.153 cannot spawn it as the non-root `aios` user (engram `architecture/apikeyhelper-aios-auth-blocker`). The key is now delivered as `ANTHROPIC_API_KEY` via the root-owned `ExecStart` wrapper. Accepted trade-off: the key enters the agent's `/proc/<pid>/environ`; mitigated by single-tenancy + the guardia env-dump speed-bump (HA-15) + the 2b egress firewall (the real exfil wall).

## Phases
1. **Design + spec** (pivot rework): ADR-1 superseded; ADR-6 (wrapper) + ADR-7 (env-dump) new; ADR-3/ADR-5 amended. Blind 5-lens adversarial review → 22 findings applied.
2. **Implementation** (strict TDD): wrapper created, helper deleted, unit reworked, guardia step 7.5, provision-agent reworked, tests reworked.
3. **Blind adversarial attack** on guardia step 7.5 + the wrapper: 5-attacker panel + orchestrator's own battery EXECUTED real bypasses. Found **4 false positives** (printenv on filenames; `-p` inside quoted args) + cheap verb variants. 7 matcher tightenings applied, re-verified by a 92-case orig-vs-patched battery (0 benign regression). +HA-15-S8/S9/S10.
4. **VPS verification** (real systemd unit, root@147.93.187.127): auth via wrapper PROVEN (`apiKeySource: ANTHROPIC_API_KEY`); guardia 51/51 on GNU grep; DNS works under `RestrictAddressFamilies` (no AF_NETLINK); chattr +a holds. **Finding**: managed `disableBypassPermissionsMode: "disable"` neutralizes `--dangerously-skip-permissions` (stream-json `permissionMode` stays `default`) → the headless agent DEFERS every Bash tool → the two-marker probe could never reach VERIFIED.
4.5. **Remediation**: re-amended ADR-5 / HA-09 to a deterministic `permissionMode` oracle (`_classify_bypass_probe`) → probe now reports VERIFIED on the VPS; fixed `install_wrapper` obsolete-helper cleanup (HA-05-S1); re-tiered HA-13-S1 (LIVE-KEY→LINUX-ROOT, append covered host-safe by camara.bats CA-01/CA-02); added `scripts/run-live-key-tests.sh` (key-deletion guard, root-caused to Slice-1 `deprovision_aios_state`).
5. **Verify + archive**: fresh-context sdd-verify = PASS (0 CRITICAL; warnings remediated). This archive.

## Verification (final)
- macOS host-safe `bats tests/` = **224 ok / 0 fail**.
- VPS full mutation tier (LINUX-ROOT + LIVE-KEY, via the safe runner) = **224 ok / 0 fail / 1 skip**.
- `shellcheck` clean on all four scripts.
- Drift: none — all normative spec literals match code verbatim (see `verify-report.md`).

## Spec disposition
2a is a self-contained capability spec ("Run the agent"). On archive, `spec.md` is promoted to `openspec/specs/vps-provisioning-hardening-2a/spec.md`. `platform-security-core` and `vps-provisioning-base` main specs are left UNCHANGED (2a alters neither; HA-15 extends PSC R2 but the archived PSC text is not rewritten — see ADR-7).

## Carry-forward to Slice 2b
With `defaultMode: default` + `allow: []` + `disableBypassPermissionsMode: disable`, the headless agent does NO autonomous bash work (every tool call defers — maximally safe for 2a's guardrails). 2b must add an allowlist / approval path for the agent to perform its actual task. The real exfil wall (egress firewall) is also 2b's.
