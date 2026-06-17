# Tasks: vps-provisioning-hardening-2a ("Run the agent")

**Change**: `vps-provisioning-hardening-2a`
**Spec**: `openspec/changes/vps-provisioning-hardening-2a/spec.md` (13 requirements, 39 scenarios)
**Design**: `openspec/changes/vps-provisioning-hardening-2a/design.md` (ADR-1 through ADR-5)
**TDD mode**: STRICT — every implementation cluster follows RED → GREEN → shellcheck
**Platform**: macOS dev box (bats-core + shellcheck installed) → Ubuntu VPS for Linux-root clusters

---

> ## ⚠️ PIVOT (2026-06-16) — this checklist is being REWORKED
>
> The `[x]` items in the historical phases below reflect the ORIGINAL apiKeyHelper implementation, which is SUPERSEDED by the ANTHROPIC_API_KEY-wrapper pivot (design ADR-6/ADR-7; spec HA-05/06/08/09 reworked + new HA-15). They are **historical**, not current state. The authoritative Phase-2 (pivot) task list is the section immediately below.

---

## PIVOT REWORK — Phase 2 task list (authoritative; supersedes the historical phases below)

**Mode:** STRICT TDD — each work unit is RED (write failing scenario) → GREEN (implement) → shellcheck. Source of truth: the reworked `spec.md` (HA-05/06/08/09 + HA-15, 46 scenarios) and `design.md` (ADR-3 amended, ADR-5/6/7). **Not a git repo** → no commits/PRs; the chained-PR / delivery-strategy machinery in the historical "Review Workload Forecast" is MOOT.

> **✅ WU-1..WU-6 COMPLETE + VERIFIED ON DISK (macOS, 2026-06-16):** `bats tests/` = **221 ok / 0 fail** (HOST-SAFE pass; LINUX-ROOT + LIVE-KEY skip-gated for the Phase-4 VPS run; ZERO Slice-1 regression). `shellcheck -s bash scripts/provision-agent.sh platform/bin/agent-run.sh platform/hooks/guardia.sh` = all exit 0. guardia step 7.5 (env-dump + /dev/tcp) RED→GREEN verified; orchestrator eyeballed the guardia/wrapper diffs. **Two fixes the inline TDD surfaced:** (a) SC-2 (probe/timer race) was only described in Phase 1, never written — now applied to spec+design+code (probe runs BEFORE `enable`, no `--now`); (b) bats here is last-command-only (NO errexit) — added `|| return 1` gating to multi-assert pivot tests so a non-last regression can't pass silently.

> **✅ WU-7 (Phase-3 blind adversarial hardening) COMPLETE + VERIFIED ON DISK (macOS, 2026-06-16):** blind 5-attacker panel + orchestrator's own attack battery found **4 false positives** (printenv firing on filenames; `-p` firing inside quoted args) and a set of cheap verb variants. All re-verified by the orchestrator executing the attacks against a patched copy (92-case before/after battery, 0 benign regressions), then applied to `guardia.sh` (7 matcher tightenings) under strict TDD. `bats tests/` = **224 ok / 0 fail** (221 + new HA-15-S8/S9/S10, each `|| return 1`-gated); `shellcheck` all 3 clean. spec.md (HA-15.1/.2/.3 + S8/S9/S10) and design.md (ADR-7 EREs + provenance) updated. NEXT: Phase 4 (real systemd unit on the VPS).

### WU-1 — Launch wrapper + remove obsolete helper
- [x] RED: in `tests/provision-agent.bats`, the reworked HA-05-S4 (wrapper body invariant: `exec /usr/bin/claude "$@"`, no `--bare`, key sourced only from `$CREDENTIALS_DIRECTORY`, exports `ANTHROPIC_API_KEY`), HA-05-S5 (wrapper shellcheck), HA-08-S4 (loads key + strips `\r`/whitespace, empty→exit≠0, missing `CREDENTIALS_DIRECTORY`→exit≠0, forwards `-p`). Confirm they FAIL first.
- [x] GREEN: create `platform/bin/agent-run.sh` exactly per spec HA-05.1 (incl. `tr -d '[:space:]'` normalization + non-empty check). `rm platform/bin/anthropic-key.sh`.
- [x] shellcheck `platform/bin/agent-run.sh` → exit 0.

### WU-2 — Service unit
- [x] RED: HA-06-S1 (all directives incl. `ExecStart=…/agent-run.sh -p`, `Environment=XDG_STATE_HOME`, `LimitCORE=0`, `UnsetEnvironment=ANTHROPIC_AUTH_TOKEN` and NOT `ANTHROPIC_API_KEY`), HA-06-S2 (`--bare` guard on unit AND wrapper), HA-06-S3 (forbidden tokens), HA-07-S1, HA-08-S1.
- [x] GREEN: rewrite `platform/systemd/osgania-agent.service` to the spec HA-06.1 directive set.

### WU-3 — guardia.sh hardening (SECURITY CRUX — step 7.5)
- [x] RED: in `tests/guardia.bats`, HA-15-S1 (deny verbs incl. bare `declare`/`typeset`, `compgen -A variable/export`, `local -p`), S2 (`/proc/(self|N|$$|$BASHPID|${…})/environ`), **S3 (MUST defer `set -e`/`declare -i`/`export FOO=bar`/`env VAR=val cmd`/`env -u`/`env -i` — false-positive guard, load-bearing)**, S4 (R2.1–R2.6 regression unchanged), S5 (defer interpreters + `echo $VAR`), S6 (deny `/dev/tcp`,`/dev/udp` → `net-builtin`), S7 (ordering: combined match denies with the INHERITED reason).
- [x] GREEN: insert step 7.5 into `platform/hooks/guardia.sh` (env-dump + net-builtin matchers, precise EREs per HA-15.1a, reason prefixes `env-dump` / `net-builtin`), placed AFTER R2.5/R2.6, before the default defer. Preserve R1/R3/R4 (exit 0, defer-on-malformed, no FS reads). *(Phase-3 hardened: +S8/S9/S10, 7 matcher tightenings — see WU-7.)*
- [x] shellcheck `platform/hooks/guardia.sh` → exit 0.

### WU-4 — provision-agent.sh rework
- [x] RED: HA-05-S1 (wrapper installed root:root 0755; `anthropic-key.sh` absent), HA-05-S2/S3 (managed-settings byte-identical / read-only R9–R12 verify, NO write), HA-09-S1/S2/S3 (probe classification + exit codes), HA-06-S4.
- [x] GREEN: rework `scripts/provision-agent.sh` — `install_key_helper`→`install_wrapper` (+ `rm -f` obsolete `anthropic-key.sh`, HA-05.1c); `upsert_apikey_helper`→`verify_managed_settings` (read-only structural assert, NO write); `run_layer3_probe`→`run_defense_in_depth_probe` — RE-AMENDED in Phase-4 to the deterministic permissionMode oracle (`_classify_bypass_probe`: `default`→VERIFIED / `bypassPermissions`→FAILED+non-zero / empty→UNVERIFIED), replacing the two-marker oracle; `build_service_unit` to new directives; drop all apiKeyHelper logic; keep AUDIT_LOG-unset assertion; wire `main()`.
- [x] shellcheck `scripts/provision-agent.sh` → exit 0.

### WU-5 — test helper
- [x] Update `tests/test_helper.bash` `deprovision_agent_state`: remove `anthropic-key.sh` → `agent-run.sh`; DROP the `jq del(.apiKeyHelper)` block (2a no longer touches managed-settings). shellcheck clean.

### WU-6 — Full green gate (macOS, verified on disk by orchestrator)
- [x] `bats tests/` → all HOST-SAFE green, LINUX-ROOT/LIVE-KEY skip (not fail), ZERO Slice-1 (provision.bats / guardia.bats / camara.bats / managed-settings.bats) regressions.
- [x] `shellcheck -s bash scripts/provision-agent.sh platform/bin/agent-run.sh platform/hooks/guardia.sh` → all exit 0.
- [x] Orchestrator reads the `guardia.sh` + `agent-run.sh` diffs by eye (security code) before Phase 3.

### WU-7 — Phase-3 blind adversarial hardening (SECURITY CRUX) ✅
- [x] Blind 5-attacker panel EXECUTED bypasses + false-positive probes against `guardia.sh` step 7.5 + the wrapper (not reading tests); orchestrator ran its own attack battery in parallel.
- [x] Wrapper `agent-run.sh` attacked: fail-closed on all 4 error paths, CRLF/space normalization correct, `"$@"` forwarded as literal argv — NO findings, no change.
- [x] 4 false positives confirmed (filename `printenv.sh`/`printenv.md`; quoted `-p` in `echo`/`git commit`) + cheap verb variants (redirect, `-p` cluster, `readonly -p`, `compgen -ve`, `env --null`, `/proc/$VAR/environ`, thread-self, `/task/<tid>`).
- [x] RED: HA-15-S8 (FP→defer), S9 (verb variants→deny), S10 (/proc indirection→deny) in `tests/guardia.bats`, each `|| return 1`-gated. Confirmed failing on the unpatched matchers.
- [x] GREEN: 7 matcher tightenings applied to `platform/hooks/guardia.sh` (+ comments). Orchestrator re-verified by executing every attack + the full benign control set against a patched copy: 92/92, 0 benign regression.
- [x] `bats tests/` = 224 ok / 0 fail; `shellcheck -s bash` all 3 scripts exit 0.
- [x] spec.md (HA-15.1/.2/.3 normative text + ERE + S8/S9/S10 scenarios + traceability) and design.md (ADR-7 target forms + ERE + Phase-3 provenance) updated. Residuals (interpreters/echo/`${!x}`/getent/cmd-subst/path-split/dead `/Dev/Tcp`) documented, NOT fixed (speed-bump scope, HA-15.6).

### WU-8 — Phase-4 VPS verification + remediation ✅
- [x] Verified conclusively on the REAL systemd unit (root@147.93.187.127): (i) auth via wrapper (`apiKeySource: ANTHROPIC_API_KEY`, PONG/NETOK); guardia.bats 51/51 on GNU grep / bash 5.2; (iv) SC-3 DNS works under `RestrictAddressFamilies` (no AF_NETLINK needed); chattr +a holds.
- [x] FINDING: managed-settings `disableBypassPermissionsMode: "disable"` neutralizes `--dangerously-skip-permissions` (stream-json `permissionMode` stays `default`) → the headless agent DEFERS every Bash tool → the old two-marker probe can NEVER reach VERIFIED (and HA-13-S1's live append can't happen).
- [x] RE-AMENDED ADR-5 / HA-09: probe → deterministic `permissionMode` oracle (`_classify_bypass_probe` + reworked `run_defense_in_depth_probe`); ADV-F03a-d rewritten; HA-09-S2 updated; print_summary updated. On VPS the probe now reports **VERIFIED**.
- [x] FIX install_wrapper: `rm -f` obsolete `anthropic-key.sh` (HA-05-S1 cleanup gap).
- [x] RE-TIER HA-13-S1 LIVE-KEY→LINUX-ROOT: verify provisioned audit log exists + chattr +a (the append is covered host-safe by camara.bats CA-01/CA-02; a live append is impossible under bypass-disabled).
- [x] KEY-DELETION guard: root-caused to Slice-1 `deprovision_aios_state` (`rm -rf /etc/osgania` wipes the operator key); added `scripts/run-live-key-tests.sh` (suite-level backup/restore via trap).
- [x] RESULT: macOS host-safe `bats tests/` = **224 ok / 0 fail**; VPS full mutation tier via the safe runner = **224 ok / 0 fail / 1 skip** (was 222/2/2 before remediation); shellcheck all 4 scripts clean; operator key restored. spec.md (HA-09 + HA-13-S1 + contracts table + 49-scenario count) + design.md (ADR-5 re-amendment) synced.

---

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 750–950 (provision-agent.sh ~350 LOC, anthropic-key.sh ~5 LOC, 2 unit templates ~60 LOC total, provision-agent.bats ~350 LOC, test_helper additions ~30 LOC) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: host-safe layer (test file + script functions + templates + shellcheck); PR 2: Linux-root + LIVE-KEY integration |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | All HOST-SAFE tests green on macOS + shellcheck clean | PR 1 | Covers 19 scenarios; zero mutation; merge to main |
| 2 | LINUX-ROOT + LIVE-KEY integration green on disposable VPS | PR 2 | Requires real Ubuntu + optionally a live key; depends on PR 1 |

> **Decision required before sdd-apply**: with `delivery_strategy: ask-on-risk` and a High risk forecast, the orchestrator MUST confirm whether to use `stacked-to-main`, `feature-branch-chain`, or `size:exception` before implementation begins.

---

## Tier Classification

| Tier | Scenarios | Task clusters |
|------|-----------|---------------|
| HOST-SAFE (macOS, real RED→GREEN now) | HA-01-S1, HA-01-S2, HA-01-S3, HA-02-S3, HA-03-S2, HA-03-S3, HA-05-S2, HA-05-S3, HA-05-S4, HA-05-S5, HA-06-S1, HA-06-S2, HA-06-S3, HA-06-S5, HA-07-S1, HA-08-S1, HA-08-S2, HA-08-S3 | P1–P5 |
| LINUX-ROOT (disposable VPS, no key needed) | HA-02-S1, HA-02-S2, HA-03-S1, HA-03-S4, HA-04-S1, HA-04-S2, HA-05-S1, HA-06-S4, HA-06-S6, HA-07-S2, HA-08-S2 (mutation path), HA-08-S3 (mutation path), HA-09-S1, HA-09-S3, HA-10-S1, HA-10-S2, HA-11-S1, HA-11-S2, HA-11-S3 | P6–P8 |
| LINUX-ROOT + LIVE-KEY | HA-08-S4, HA-09-S2, HA-13-S1 | P8 |
| OPERATOR-MANUAL (documented checklist only, not automated) | HA-12-S1 | P9 |

---

## Phase 1: Foundation — test_helper additions + fixture (HOST-SAFE)

- [x] 1.1 **[RED]** Add `skip_unless_live_key` helper to `tests/test_helper.bash`: skips unless `LIVE_KEY_AVAILABLE=1` AND `/etc/osgania/secrets/anthropic-api-key` exists; emits `"requires live API key at /etc/osgania/secrets/anthropic-api-key (UNVERIFIED)"`. Satisfies: HA-08-S4, HA-09-S2, HA-13-S1 guard.
- [x] 1.2 **[RED]** Add `deprovision_agent_state` helper to `tests/test_helper.bash`: best-effort teardown of `npm uninstall -g @anthropic-ai/claude-code`, `systemctl disable --now osgania-agent.timer osgania-agent.service 2>/dev/null || true`, remove unit files, `rm -rf /opt/osgania/client /opt/osgania/platform/bin/anthropic-key.sh`; guarded by `skip_unless_linux_root_mutation`. Satisfies: idempotency test isolation (HA-10-S1, HA-10-S2).
- [x] 1.3 **[RED]** Add `load_managed_settings_fixture` helper to `tests/test_helper.bash`: copies `platform/managed-settings.json` into `BATS_TMPDIR/managed-settings-fixture.json` and exports `MANAGED_SETTINGS_FIXTURE`; callable from HOST-SAFE tests without touching the live box. Satisfies: HA-05-S2, HA-05-S3, HA-05-S4.
- [x] 1.4 **[GREEN]** Implement the three helpers in `tests/test_helper.bash`; run `shellcheck -s bash tests/test_helper.bash` — exit 0. Satisfies: HA-14.2 (shellcheck clean).
- [x] 1.5 **[SHELLCHECK]** `shellcheck -s bash tests/test_helper.bash` MUST exit 0 with no warnings. (Paired task per config rule.)

---

## Phase 2: Shell files scaffolding (HOST-SAFE RED setup)

- [x] 2.1 Create `platform/bin/anthropic-key.sh` with the exact body from ADR-1/HA-05.1:
  ```sh
  #!/usr/bin/env bash
  # /opt/osgania/platform/bin/anthropic-key.sh — root:root 0755
  set -euo pipefail
  cat "${CREDENTIALS_DIRECTORY}/anthropic-api-key"
  ```
  Satisfies: HA-05.1, HA-14.1.
- [x] 2.2 **[SHELLCHECK — anthropic-key.sh]** `shellcheck -s bash platform/bin/anthropic-key.sh` MUST exit 0. Satisfies: HA-05-S5, HA-14.2. This is the paired shellcheck task for `anthropic-key.sh`.
- [x] 2.3 Create `platform/systemd/osgania-agent.service` with the EXACT directive set from HA-06.1/ADR-3. File is the repo template; the installer writes it to `/etc/systemd/system/`. Satisfies: HA-14.1, HA-06.1.
- [x] 2.4 Create `platform/systemd/osgania-agent.timer` with the EXACT content from HA-07.1/ADR-3. Satisfies: HA-14.1, HA-07.1.
- [x] 2.5 Create `scripts/provision-agent.sh` as an empty executable skeleton with: `#!/usr/bin/env bash`, `set -euo pipefail`, the `main "$@"` / `BASH_SOURCE` guard (`[[ "${BASH_SOURCE[0]}" == "$0" ]] && main "$@"`), and stub function stubs for: `check_preconditions`, `install_node`, `install_cli`, `create_workspace`, `install_key_helper`, `upsert_apikey_helper`, `write_units`, `run_layer3_probe`, `print_summary`. Set `chmod +x scripts/provision-agent.sh`. Satisfies: HA-14.1, HA-14.3.

---

## Phase 3: HOST-SAFE test cluster A — preconditions + dry-run

_Covers: HA-01-S1, HA-01-S2, HA-01-S3. Tier: HOST-SAFE._

- [x] 3.1 **[RED]** Write `tests/provision-agent.bats` with file header, `load test_helper`, `PROVISION_AGENT="${BATS_TEST_DIRNAME}/../scripts/provision-agent.sh"`, `setup()` (source provision-agent.sh; prepend `BATS_TMPDIR/bin` to PATH), `teardown()` (clean BATS_TMPDIR/bin). Add failing tests:
  - `@test "HA-01-S1 missing aios account causes abort"` — stubs `getent` to return 1 for aios; sources and calls `check_preconditions`; asserts exit > 0 and stderr mentions aios.
  - `@test "HA-01-S2 invalid managed-settings.json causes abort"` — writes `{bad}` to a temp file; exports `MANAGED_SETTINGS_PATH=<tmpfile>`; asserts abort with message.
  - `@test "HA-01-S3 --check dry-run exits 0 and prints plan without mutation"` — invokes `bash "$PROVISION_AGENT" --check`; asserts exit 0; asserts no npm/apt/claude invocation (check no mutation stubs called).
  Satisfies: HA-01.1, HA-01.2, HA-01.4.
- [x] 3.2 **[GREEN]** Implement `check_preconditions` in `scripts/provision-agent.sh`:
  - Check `getent passwd aios` returns UID 9001 + GID 9001; abort with message if absent.
  - Check `${MANAGED_SETTINGS_PATH:-/etc/claude-code/managed-settings.json}` exists and passes `jq .`; abort with message if not.
  - Check `lsattr /var/log/osgania/audit.jsonl` contains `a` flag; abort with message if not (skip lsattr check in `--check` mode? no — spec says run all precondition checks).
  - Check `systemctl --version` exits 0; abort if not (HA-01.3).
  - If `--check` flag is set: print provisioning plan (list of steps that would run) and exit 0 WITHOUT running any mutation step. Satisfies: HA-01-S1, HA-01-S2, HA-01-S3.
- [x] 3.3 **[SHELLCHECK — provision-agent.sh]** `shellcheck -s bash scripts/provision-agent.sh` MUST exit 0. Paired task per config rule. Re-run after every implementation step in this phase.

---

## Phase 4: HOST-SAFE test cluster B — Node version branch + CLI pin logic

_Covers: HA-02-S3, HA-03-S2, HA-03-S3. Tier: HOST-SAFE._

- [x] 4.1 **[RED]** In `tests/provision-agent.bats`, add failing tests:
  - `@test "HA-02-S3 node>=18 present: NodeSource branch NOT taken"` — stub `node` returning `v20.1.0`; call `install_node` sourced function; assert npm-nodesource stub NOT invoked.
  - `@test "HA-02-S3 node<18 present: NodeSource 20.x branch IS taken"` — stub `node` returning `v16.0.0`; assert NodeSource install path IS taken.
  - `@test "HA-03-S2 CLI already at pin: npm install NOT invoked"` — stub `claude` returning `2.1.153`; call `install_cli`; assert `npm install -g` stub NOT called.
  - `@test "HA-03-S3 CLI at older version: npm install IS invoked"` — stub `claude` returning `2.1.100`; call `install_cli`; assert `npm install -g @anthropic-ai/claude-code@2.1.153` stub IS called.
  Satisfies: HA-02.1, HA-02.4, HA-03.3.
- [x] 4.2 **[GREEN]** Implement `install_node` in `scripts/provision-agent.sh`:
  - Parse `node --version` (strip leading `v`); compare semver major >= 18.
  - If >= 18: skip apt install, log "Node already >= 18, skipping install".
  - If < 18 or absent: run NodeSource 20.x setup + `apt-get install -y nodejs`.
  - Always run `apt-mark hold nodejs npm` (add-only, idempotent). Satisfies: HA-02.1, HA-02.3, HA-02.4.
- [x] 4.3 **[GREEN]** Implement `install_cli` in `scripts/provision-agent.sh`:
  - Run `claude --version`; parse version string (strip non-numeric prefix); compare semver >= 2.1.153.
  - If already at 2.1.153: skip `npm install -g`, log "CLI already at pin".
  - If below 2.1.153: run `npm install -g @anthropic-ai/claude-code@2.1.153`; re-run version check and abort if still below floor.
  - Store installed version in a variable for use by `print_summary`. Satisfies: HA-03.1, HA-03.2, HA-03.3, HA-03.4.
- [x] 4.4 **[SHELLCHECK]** `shellcheck -s bash scripts/provision-agent.sh` MUST exit 0. Paired.

---

## Phase 5: HOST-SAFE test cluster C — unit-file content assembly + forbidden-token guards

_Covers: HA-06-S1, HA-06-S2, HA-06-S3, HA-07-S1, HA-08-S1, HA-08-S2, HA-08-S3, HA-05-S2, HA-05-S3, HA-05-S4, HA-05-S5. Tier: HOST-SAFE._

- [x] 5.1 **[RED]** In `tests/provision-agent.bats`, add failing tests for service unit string assembly (all sourced-function, no disk write):
  - `@test "HA-06-S1 service unit contains all required directives"` — call `build_service_unit` (returns string); assert each of the 30 directives listed in HA-06.1 is present.
  - `@test "HA-06-S2 --bare guard: ExecStart must not contain --bare"` — same string; assert no `--bare` token; assert `ExecStart=/usr/bin/claude -p` present.
  - `@test "HA-06-S3 forbidden tokens absent: MemoryDenyWriteExecute, AUDIT_LOG=, Environment=ANTHROPIC_API_KEY"` — same string; assert each is absent.
  - `@test "HA-07-S1 timer unit contains placeholder cadence"` — call `build_timer_unit`; assert OnCalendar=daily, RandomizedDelaySec=3600, Persistent=true, WantedBy=timers.target.
  - `@test "HA-08-S1 UnsetEnvironment includes both ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN"` — service unit string; assert `UnsetEnvironment=ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN`.
  - `@test "HA-08-S2 AUDIT_LOG not set at end of run"` — mock full run in a subshell; assert `AUDIT_LOG` is unset in environment.
  - `@test "HA-08-S3 key value never appears in unit file or stdout"` — run `bash "$PROVISION_AGENT" --check` with dummy env; assert neither "sk-test-DUMMY" nor API key pattern in output or assembled unit string.
  Satisfies: HA-06.1, HA-06.2, HA-06.3, HA-06.4, HA-07.1, HA-07.2, HA-08.1, HA-08.3, HA-08.5, HA-08.6.
- [x] 5.2 **[RED]** Add failing tests for managed-settings jq upsert (against `MANAGED_SETTINGS_FIXTURE`):
  - `@test "HA-05-S2 jq upsert adds apiKeyHelper to fixture"` — call `upsert_apikey_helper "$MANAGED_SETTINGS_FIXTURE" "$BATS_TMPDIR/out.json"`; assert `.apiKeyHelper == "/opt/osgania/platform/bin/anthropic-key.sh"` and valid JSON.
  - `@test "HA-05-S3 R9-R12 structural invariant: all existing keys present after upsert"` — verify `.permissions.deny | length == 6`; verify all 6 entries; verify `.permissions.allow == []`, `.permissions.defaultMode == "default"`, `.permissions.disableBypassPermissionsMode == "disable"`, `.allowManagedHooksOnly == true`; verify guardia hook and camara hook entries present.
  - `@test "HA-05-S4 apiKeyHelper upsert is idempotent"` — apply upsert twice; assert no duplicate key; assert valid JSON; assert `.apiKeyHelper` value unchanged.
  Satisfies: HA-05.3, HA-05.4, HA-05.5, HA-05.6, HA-10.1 (upsert path).
- [x] 5.3 **[GREEN]** Implement `build_service_unit` function in `scripts/provision-agent.sh`: returns the exact unit file string from HA-06.1 as a heredoc. Before returning, assert the string does NOT contain `--bare`; if it does, exit 1 with error. Assert NOT containing `MemoryDenyWriteExecute`, `AUDIT_LOG=`, `Environment=ANTHROPIC_API_KEY`. Satisfies: HA-06.1, HA-06.2, HA-06.3.
- [x] 5.4 **[GREEN]** Implement `build_timer_unit` function in `scripts/provision-agent.sh`: returns the exact timer unit string from HA-07.1 as a heredoc. Satisfies: HA-07.1.
- [x] 5.5 **[GREEN]** Implement `upsert_apikey_helper <settings_file> [output_file]` in `scripts/provision-agent.sh`: runs the `jq --arg h /opt/osgania/platform/bin/anthropic-key.sh '.apiKeyHelper = $h'` upsert (write atomically via temp file + `mv`); re-validates with `jq .`; runs structural invariant checks (R9–R12) — aborts with exit 1 and named failed assertion if any check fails. Satisfies: HA-05.3, HA-05.4, HA-05.5, HA-05.6.
- [x] 5.6 **[SHELLCHECK]** `shellcheck -s bash scripts/provision-agent.sh` MUST exit 0. Paired.
- [x] 5.7 **[SHELLCHECK — anthropic-key.sh re-verify]** `shellcheck -s bash platform/bin/anthropic-key.sh` MUST exit 0. Verify no drift since Phase 2.

---

## Phase 6: HOST-SAFE test cluster D — helper script shellcheck + full host-safe bats green

_Covers: HA-05-S5, HA-06-S5. Tier: HOST-SAFE._

- [x] 6.1 **[RED]** Add shellcheck-as-bats-test entries in `tests/provision-agent.bats`:
  - `@test "HA-05-S5 anthropic-key.sh passes shellcheck"` — `run shellcheck -s bash platform/bin/anthropic-key.sh`; assert `$status -eq 0`.
  - `@test "HA-06-S5 provision-agent.sh passes shellcheck"` — `run shellcheck -s bash scripts/provision-agent.sh`; assert `$status -eq 0`.
  Satisfies: HA-14.2.
- [x] 6.2 **[GREEN]** Ensure both shellcheck-as-test assertions pass (no new warnings introduced). Satisfies: HA-14.2.
- [x] 6.3 **Full HOST-SAFE green gate**: run `bats tests/provision-agent.bats` on macOS. All HOST-SAFE scenarios MUST be green. All LINUX-ROOT / LIVE-KEY scenarios MUST be skipped (not failed). Record skip counts in a comment block at top of `tests/provision-agent.bats`. Satisfies: HA-14.3 (file exists and runs), HA-14.2 (shellcheck clean within bats).
  RESULT: 19 PASS, 23 SKIP, 0 FAIL — confirmed on macOS dev box.

---

## Phase 7: LINUX-ROOT test cluster — full installation + systemd + Slice-1 invariants

_All tasks in this phase: SKIP on macOS (skip_unless_linux_root_mutation). Run on disposable Ubuntu 24.04/26.04 + PROVISION_TEST_ALLOW_MUTATION=1 + root._

_Covers: HA-02-S1, HA-02-S2, HA-03-S1, HA-03-S4, HA-04-S1, HA-04-S2, HA-05-S1, HA-06-S4, HA-06-S6, HA-07-S2, HA-08-S2 (mutation path), HA-08-S3 (mutation path), HA-09-S1, HA-09-S3, HA-10-S1, HA-10-S2, HA-11-S1, HA-11-S2, HA-11-S3._

- [x] 7.1 **[RED — WRITTEN, VPS-DEFERRED for GREEN]** Add Linux-root failing tests in `tests/provision-agent.bats` (all begin with `skip_unless_linux_root_mutation`):
  NOTE: Tests are written and skip correctly on macOS. GREEN verification requires Ubuntu 24.04/26.04 + root + PROVISION_TEST_ALLOW_MUTATION=1.
  - `@test "HA-02-S1 node>=18 and npm present after provisioning"` — run full provisioner; `node --version` >= 18; `npm --version` exits 0.
  - `@test "HA-02-S2 nodejs and npm packages are held"` — `apt-mark showhold` contains nodejs and npm.
  - `@test "HA-03-S1 claude version is 2.1.153 after provisioning"` — `claude --version` contains 2.1.153.
  - `@test "HA-03-S4 provisioning summary contains CLI version string"` — run provisioner; capture output; assert version string present.
  - `@test "HA-04-S1 /opt/osgania/client exists aios:aios 700"` — `stat -c '%U:%G %a'` returns `aios:aios 700`.
  - `@test "HA-04-S2 workspace mode re-asserted on re-run"` — first run; chmod 755 client/; second run; stat returns 700.
  - `@test "HA-05-S1 anthropic-key.sh installed root:root 755"` — stat returns `root:root 755`; test -x exits 0.
  - `@test "HA-06-S4 service unit on disk after provisioning"` — `systemctl show osgania-agent.service` exits 0; unit file contains required directives; forbidden tokens absent.
  - `@test "HA-06-S6 agent run produces no XDG/EROFS permission errors"` — after a timer-triggered or direct start attempt; `journalctl -u osgania-agent` has no Permission denied / EROFS / XDG errors.
  - `@test "HA-07-S2 timer enabled after provisioning"` — `systemctl is-enabled osgania-agent.timer` exits 0 and contains "enabled".
  - `@test "HA-08-S2 AUDIT_LOG not set (Linux mutation path)"` — run provisioner; assert AUDIT_LOG unset in post-run env.
  - `@test "HA-08-S3 key value absent from unit file and stdout (Linux path)"` — run with dummy test key at secrets path; assert key value absent from unit file content and stdout.
  - `@test "HA-09-S1 Layer-3 status recorded as one of VERIFIED/UNVERIFIED/FAILED"` — run provisioner; capture output; assert exactly one of the three status strings present.
  - `@test "HA-09-S3 UNVERIFIED when key absent"` — ensure no key at secrets path; run provisioner; assert "Layer-3: UNVERIFIED" in output; assert exit 0.
  - `@test "HA-10-S1 re-run exits 0 with no duplicate units or re-install"` — run twice; assert exit 0; exactly one .service + one .timer in list-unit-files; claude version unchanged.
  - `@test "HA-10-S2 re-run does not corrupt audit log or +a flag"` — run twice; assert same inode; +a flag still set.
  - `@test "HA-11-S1 aios account intact after 2a"` — UID 9001, GID 9001, shell nologin, home /nonexistent; not in sudo/admin.
  - `@test "HA-11-S2 secrets dir mode intact after 2a"` — stat returns root:root 700.
  - `@test "HA-11-S3 audit +a flag intact after 2a"` — lsattr shows `a` flag.
  Satisfies: HA-02.1, HA-02.2, HA-02.3, HA-03.1, HA-03.2, HA-03.4, HA-04.1, HA-04.2, HA-05.1, HA-05.2, HA-06.1, HA-06.5, HA-06.7, HA-07.3, HA-08.1, HA-08.5, HA-08.6, HA-09.2, HA-09.3, HA-10.1, HA-10.2, HA-10.3, HA-11.1, HA-11.2, HA-11.3.
- [x] 7.2 **[GREEN — IMPLEMENTED, VPS-DEFERRED for integration test]** Implement remaining functions in `scripts/provision-agent.sh`:
  - `create_workspace`: `install -d -o aios -g aios -m 0700 /opt/osgania/client`. Satisfies: HA-04.1, HA-04.2.
  - `install_key_helper`: `install -o root -g root -m 0755 "${REPO_ROOT}/platform/bin/anthropic-key.sh" /opt/osgania/platform/bin/anthropic-key.sh`. Satisfies: HA-05.1, HA-05.2.
  - `write_units`: call `build_service_unit` → write to `/etc/systemd/system/osgania-agent.service` atomically; call `build_timer_unit` → write to `/etc/systemd/system/osgania-agent.timer` atomically; run `systemctl daemon-reload`; run `systemctl enable --now osgania-agent.timer`. Satisfies: HA-06.1, HA-06.5, HA-06.6, HA-07.3.
  - `run_layer3_probe`: check if `/etc/osgania/secrets/anthropic-api-key` exists AND `claude` is available; if not → print "Layer-3: UNVERIFIED (key absent or CLI not installed)" and return 0; if yes → run probe command; classify VERIFIED/FAILED based on exit code + output; if FAILED → print "Layer-3: FAILED — bypass flag was accepted" and exit 1. Satisfies: HA-09.1, HA-09.2, HA-09.3, HA-09.4.
  - `print_summary`: print non-secret summary (version, paths, Layer-3 status); assert `AUDIT_LOG` is unset (`[ -z "${AUDIT_LOG:-}" ]` or `! env | grep -q "^AUDIT_LOG="`). Satisfies: HA-03.4, HA-08.6, HA-11.1.
  - Wire `main()` to call all steps in order (steps 0–8 per design execution model). Satisfies: HA-14.1, HA-14.3.
- [x] 7.3 **[SHELLCHECK]** `shellcheck -s bash scripts/provision-agent.sh` MUST exit 0 after all implementations in 7.2. Paired shellcheck for the final form of `provision-agent.sh`. RESULT: exit 0, no warnings.

---

## Phase 8: LIVE-KEY test cluster

_All tasks in this phase: SKIP unless LIVE_KEY_AVAILABLE=1 AND key file present. Tier: LINUX-ROOT + LIVE-KEY._

_Covers: HA-08-S4, HA-09-S2, HA-13-S1._

- [x] 8.1 **[RED — WRITTEN, LIVE-KEY-DEFERRED for GREEN]** Add LIVE-KEY failing tests in `tests/provision-agent.bats` (begin with `skip_unless_live_key`):
  NOTE: Tests are written and skip correctly. GREEN verification requires LIVE_KEY_AVAILABLE=1 + real key at /etc/osgania/secrets/anthropic-api-key.
  - `@test "HA-08-S4 apiKeyHelper reads key when CREDENTIALS_DIRECTORY provided"` — `runuser -u aios -- env CREDENTIALS_DIRECTORY=/etc/osgania/secrets /opt/osgania/platform/bin/anthropic-key.sh`; assert exit 0; assert stdout non-empty and contains no error message; assert stdout matches key file content.
  - `@test "HA-09-S2 FAILED probe causes non-zero exit"` — simulated FAILED condition (if ever reproduced — skip if policy is correctly enforced; document that this scenario validates the error path and will show UNVERIFIED when mode-lock is working); assert non-zero exit and FAILED surfaced in output.
  - `@test "HA-13-S1 agent run appends audit record and +a flag persists"` — `systemctl start osgania-agent.service`; assert exit 0; assert at least one new JSON line appended to audit.jsonl; assert each line is valid JSON with ts/session_id/tool_name/decision fields; assert lsattr shows `a` flag still set.
  Satisfies: HA-08.4, HA-09.4, HA-06.1, HA-06.7, platform-security-core R5.5.
- [x] 8.2 **[GREEN — IMPLEMENTED]** No additional implementation needed — the LIVE-KEY tests exercise existing implementation wired in Phases 5 and 7. `run_layer3_probe` is implemented and correctly classifies VERIFIED vs FAILED via `_classify_layer3_probe`. Satisfies: HA-09.2, HA-09.3.

---

## Phase 9: Rollback checklist (OPERATOR-MANUAL — HA-12-S1)

_This phase produces a documented manual checklist, not automated bats tests. Tier: OPERATOR-MANUAL._

- [x] 9.1 **[MANUAL CHECKLIST — DOCUMENTED]** The HA-12-S1 rollback procedure is documented as a comment block inside `tests/provision-agent.bats` (the HA-12-S1 test entry), including all 6 steps from HA-12.1, the MUST NOT constraints from HA-12.2, and the Slice-1 end-state verification assertions from HA-12.3. Satisfies: HA-12.1, HA-12.2, HA-12.3.

---

## Phase 10: Final integration + handoff

- [x] 10.1 **Full bats green on macOS**: `bats tests/provision-agent.bats` — 19 PASS (HOST-SAFE green), 23 SKIP (LINUX-ROOT + LIVE-KEY + OPERATOR-MANUAL), 0 FAIL. Full suite `bats tests/`: 197 total (no regressions in Slice-1 tests).
- [x] 10.2 **Dual shellcheck clean**: `shellcheck -s bash scripts/provision-agent.sh platform/bin/anthropic-key.sh` — both exit 0, zero warnings. Satisfies: HA-14.2.
- [x] 10.3 **File structure verification**: all 5 files from HA-14.1 exist: `scripts/provision-agent.sh`, `platform/bin/anthropic-key.sh`, `platform/systemd/osgania-agent.service`, `platform/systemd/osgania-agent.timer`, `tests/provision-agent.bats`. Satisfies: HA-14.1, HA-14.3.
- [ ] 10.4 **Handoff note — VPS (LINUX-ROOT, no key)**:
  On a disposable Ubuntu 24.04/26.04 box with `PROVISION_TEST_ALLOW_MUTATION=1` and root:
  - Run Slice-1 `provision.sh` first (2a preconditions require it).
  - Then `sudo PROVISION_TEST_ALLOW_MUTATION=1 bats tests/provision-agent.bats`.
  - Expected: HA-02-S1/S2, HA-03-S1/S4, HA-04-S1/S2, HA-05-S1, HA-06-S4/S6, HA-07-S2, HA-08-S2/S3, HA-09-S1/S3, HA-10-S1/S2, HA-11-S1/S2/S3 green. LIVE-KEY tests skip as UNVERIFIED.
- [ ] 10.5 **Handoff note — VPS + LIVE-KEY**:
  Additionally requires a real Anthropic API key at `/etc/osgania/secrets/anthropic-api-key` (operator-supplied, not committed):
  - `sudo PROVISION_TEST_ALLOW_MUTATION=1 LIVE_KEY_AVAILABLE=1 bats tests/provision-agent.bats`.
  - Expected: HA-08-S4, HA-09-S2, HA-13-S1 green. Layer-3 probe reports VERIFIED if mode-lock enforced by installed CLI, or FAILED (hard finding).

---

## Scenario Coverage Table (all 39 scenarios — zero orphans)

| Scenario | Requirement | Tier | Task |
|----------|-------------|------|------|
| HA-01-S1 | HA-01.1, HA-01.2 | HOST-SAFE | 3.1 / 3.2 |
| HA-01-S2 | HA-01.1, HA-01.2 | HOST-SAFE | 3.1 / 3.2 |
| HA-01-S3 | HA-01.4 | HOST-SAFE | 3.1 / 3.2 |
| HA-02-S1 | HA-02.1, HA-02.2 | LINUX-ROOT | 7.1 / 7.2 |
| HA-02-S2 | HA-02.3 | LINUX-ROOT | 7.1 / 7.2 |
| HA-02-S3 | HA-02.1, HA-02.4 | HOST-SAFE | 4.1 / 4.2 |
| HA-03-S1 | HA-03.1, HA-03.2 | LINUX-ROOT | 7.1 / 7.2 |
| HA-03-S2 | HA-03.3 | HOST-SAFE | 4.1 / 4.3 |
| HA-03-S3 | HA-03.3 | HOST-SAFE | 4.1 / 4.3 |
| HA-03-S4 | HA-03.4 | LINUX-ROOT | 7.1 / 7.2 |
| HA-04-S1 | HA-04.1, HA-04.2 | LINUX-ROOT | 7.1 / 7.2 |
| HA-04-S2 | HA-04.2, HA-10.1 | LINUX-ROOT | 7.1 / 7.2 |
| HA-05-S1 | HA-05.1, HA-05.2 | LINUX-ROOT | 7.1 / 7.2 |
| HA-05-S2 | HA-05.3, HA-05.4 | HOST-SAFE | 5.2 / 5.5 |
| HA-05-S3 | HA-05.6 | HOST-SAFE | 5.2 / 5.5 |
| HA-05-S4 | HA-05.4, HA-10.1 | HOST-SAFE | 5.2 / 5.5 |
| HA-05-S5 | HA-14.2 | HOST-SAFE | 2.2 / 6.1 |
| HA-06-S1 | HA-06.1, HA-06.4, HA-06.7 | HOST-SAFE | 5.1 / 5.3 |
| HA-06-S2 | HA-06.2 | HOST-SAFE | 5.1 / 5.3 |
| HA-06-S3 | HA-06.3 | HOST-SAFE | 5.1 / 5.3 |
| HA-06-S4 | HA-06.1, HA-06.5 | LINUX-ROOT | 7.1 / 7.2 |
| HA-06-S5 | HA-14.2 | HOST-SAFE | 6.1 / 6.2 |
| HA-06-S6 | HA-06.7 | LINUX-ROOT | 7.1 / 7.2 |
| HA-07-S1 | HA-07.1, HA-07.2 | HOST-SAFE | 5.1 / 5.4 |
| HA-07-S2 | HA-06.6, HA-07.3 | LINUX-ROOT | 7.1 / 7.2 |
| HA-08-S1 | HA-06.4, HA-08.3 | HOST-SAFE | 5.1 / 5.3 |
| HA-08-S2 | HA-08.6, HA-11.1 | HOST-SAFE / LINUX-ROOT | 5.1 / 7.1 |
| HA-08-S3 | HA-08.1, HA-08.5 | HOST-SAFE / LINUX-ROOT | 5.1 / 7.1 |
| HA-08-S4 | HA-08.4 | LIVE-KEY | 8.1 / 8.2 |
| HA-09-S1 | HA-09.2, HA-09.3 | LINUX-ROOT | 7.1 / 7.2 |
| HA-09-S2 | HA-09.4 | LINUX-ROOT / LIVE-KEY | 8.1 / 8.2 |
| HA-09-S3 | HA-09.2, HA-09.3 | LINUX-ROOT | 7.1 / 7.2 |
| HA-10-S1 | HA-10.1, HA-10.2 | LINUX-ROOT | 7.1 / 7.2 |
| HA-10-S2 | HA-10.3, HA-11.2 | LINUX-ROOT | 7.1 / 7.2 |
| HA-11-S1 | HA-11.1 | LINUX-ROOT | 7.1 / 7.2 |
| HA-11-S2 | HA-11.1, HA-11.3 | LINUX-ROOT | 7.1 / 7.2 |
| HA-11-S3 | HA-11.1, HA-11.2 | LINUX-ROOT | 7.1 / 7.2 |
| HA-12-S1 | HA-12.1, HA-12.2, HA-12.3 | OPERATOR-MANUAL | 9.1 |
| HA-13-S1 | HA-06.1, HA-06.7, PSC R5.5 | LINUX-ROOT / LIVE-KEY | 8.1 / 8.2 |

**Total: 39 scenarios | Zero orphans confirmed.**

---

## Rough Size Estimate

| File | Estimated LOC |
|------|--------------|
| `scripts/provision-agent.sh` | 300–370 LOC |
| `platform/bin/anthropic-key.sh` | 5 LOC |
| `platform/systemd/osgania-agent.service` | 35 LOC |
| `platform/systemd/osgania-agent.timer` | 10 LOC |
| `tests/provision-agent.bats` | 320–380 LOC |
| `tests/test_helper.bash` (additions) | 30–40 LOC |
| **Total** | **700–840 LOC** |

> Note: this project is NOT a git repo — LOC estimate is for effort and review planning only, not for PR diff splitting.

---

## Parallelism Notes

- Phases 1 and 2 are independent and can run in parallel.
- Phase 3 depends on Phase 2 (provision-agent.sh scaffold must exist to source it).
- Phases 4 and 5 depend on Phase 3 (test file and script exist).
- Phase 6 depends on Phases 4 and 5 (all HOST-SAFE tests written).
- Phases 7 and 8 depend on Phase 6 (HOST-SAFE green on macOS first).
- Phase 9 (rollback checklist) can be written any time after Phase 5.
- Phase 10 depends on all previous phases.
