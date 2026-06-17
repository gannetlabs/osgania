# Tasks: vps-provisioning-base

**Change**: vps-provisioning-base (Slice 1 of 2 — the deterministic OS baseline)
**Project**: osgania
**Artifact store**: openspec
**TDD mode**: STRICT — write failing test → implement to green → shellcheck lint
**Test runner**: `bats tests/`  |  **Lint**: `shellcheck scripts/**/*.sh`
**Note**: bats-core and shellcheck MUST be installed before running: `brew install bats-core shellcheck`

---

## Environment Split (read before applying)

This is a macOS dev machine. Target is Ubuntu Linux. The split governs WHEN each task cluster is verified:

**macOS-TDD-able NOW (real red → green)**: pure/host-safe logic extracted into sourceable
functions in `scripts/provision.sh` — argument parsing, `--check` mode output and exit,
`/etc/os-release` parsing, OS-version branching, version string comparison (`>= v2.1.153`),
semver compare helper, mode/owner string assembly, precondition-report formatting, and any
string/format helpers. `provision.sh` MUST guard its main entrypoint with:
```bash
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
```
so bats can `source scripts/provision.sh` and test functions without executing the installer.

**Linux + root + ext4 ONLY (write tests now, gate with SKIP, verify later)**: the actual
mutating assertions — aios user created (`getent`/`id`), platform tree perms (`stat`), secrets
dir mode, audit dir+file mode, `lsattr` showing `a`, `chattr +a` truncation-blocked (PV-27),
jq installed (`which jq`), managed-settings installed, live mode-lock test, CLI version. These
tests are written now with:
```bash
skip_unless_linux_root_mutation()  # helper in tests/test_helper.bash
```
They run and go green only in a disposable Ubuntu 26.04/24.04 environment (VM or privileged
container with `--cap-add LINUX_IMMUTABLE` on an ext4 volume). Running `bats tests/` on macOS
will `skip` them — that is correct and expected behavior. These are a VERIFY-PHASE DEPENDENCY:
the orchestrator/operator must re-run `bats tests/` in the Linux environment to get full green.

---

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed files | 2 new files (`scripts/provision.sh`, `tests/provision.bats`) + 1 extended (`tests/test_helper.bash`) |
| Estimated provision.sh LOC | ~280–340 lines |
| Estimated provision.bats LOC | ~300–380 lines |
| Estimated test_helper.bash addition | ~25–35 lines |
| Total estimated new lines | ~620–760 lines |
| 400-line budget risk | High |
| Chained PRs recommended | No — this project is NOT a git repo; no PR workflow |
| Delivery strategy | exception-ok (non-git project; size is for effort/review judgment only) |
| Chain strategy | N/A |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: N/A
400-line budget risk: High

### Suggested Work Units (for effort sequencing — not PRs)

| Unit | Goal | Cluster | Macros-runnable? |
|------|------|---------|------------------|
| 1 | test_helper extension + bats scaffold | Phase 1 | Yes |
| 2 | `--check`/arg-parsing tests + implementation | Phase 2 | Yes |
| 3 | OS-detect + precondition function tests + implementation | Phase 3 | Yes |
| 4 | Semver compare + version-pin logic tests + implementation | Phase 4 | Yes |
| 5 | Mutating step tests (SKIP-gated) + implementation body | Phase 5 | Tests: Yes (skip). Impl: Linux-deferred |
| 6 | Idempotency + collision-abort tests + shellcheck clean | Phase 6 | Tests: Yes (skip). Impl: Linux-deferred |
| 7 | Full suite pass (macOS subset) + shellcheck lint pass | Phase 7 | Yes |

---

## Phase 1 — Infrastructure: Test Scaffold & Helper Extension

> Deliverable: the test infrastructure that all later phases depend on.
> All tasks in this phase are macOS-runnable.

- [x] **1.1** [RED] Add `skip_unless_linux_root_mutation()` helper to `tests/test_helper.bash`.
  Body: `[[ "$EUID" -eq 0 && "${PROVISION_TEST_ALLOW_MUTATION:-0}" == "1" ]] || skip "requires Linux root + PROVISION_TEST_ALLOW_MUTATION=1"`.
  Maps to design § "Verification approach" / gate strategy for Linux-only assertions.

- [x] **1.2** Create `tests/provision.bats` with the file header, `load test_helper`, and empty stubs
  (one `@test` per PV scenario, each body = `skip "stub"` initially). This gives the failing RED
  baseline: `bats tests/provision.bats` exits non-zero only because stubs are incomplete, not because
  setup is broken. PV-01 through PV-27 each get a named stub.

- [x] **1.3** Create `scripts/provision.sh` skeleton: shebang `#!/usr/bin/env bash`, `set -euo pipefail`,
  the `BASH_SOURCE` main guard (`[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"`), and empty
  function stubs (`parse_args`, `detect_os`, `semver_gte`, `check_preconditions`, `report_plan`,
  `run_provision`, `main`). No logic yet — file must be sourceable without executing side effects.
  Requirement: R1 (all precondition logic), R1.7 (--check mode).

- [x] **1.4** [LINT] Run `shellcheck scripts/provision.sh` — skeleton must be lint-clean before any
  logic is added. Fix any warnings in the skeleton.

---

## Phase 2 — Argument Parsing & `--check` Mode (macOS-TDD)

> PV-25 covered here. Fully runnable on macOS via `source scripts/provision.sh` in bats.

- [x] **2.1** [RED] Write bats test for `parse_args` (PV-25 partial):
  - `parse_args --check` sets `CHECK_MODE=1`
  - `parse_args` (no args) sets `CHECK_MODE=0`
  - `parse_args --unknown-flag` exits non-zero with usage message to stderr
  Test uses `source scripts/provision.sh` and calls `parse_args` directly.
  Spec: R1.7.

- [x] **2.2** [GREEN] Implement `parse_args()` in `scripts/provision.sh`: parse `$@`, set
  `CHECK_MODE` variable, emit usage+exit on unknown flags.
  Spec: R1.7.

- [x] **2.3** [RED] Write bats test for `report_plan()` (PV-25 full):
  - When `CHECK_MODE=1`, `report_plan` prints a non-empty plan to stdout listing all
    planned mutations (user, paths, modes, chattr) and exits 0.
  - No actual filesystem state is touched during `report_plan` (assert no side effects
    by checking that no temp files are created in `$BATS_TMPDIR`).
  Spec: R1.7.

- [x] **2.4** [GREEN] Implement `report_plan()`: print the planned provisioning steps in human-readable
  form without executing any of them. Output MUST mention: `aios` user creation, platform tree paths
  + modes, policy path, secrets dir, audit dir+file + chattr, jq, CLI pin, AUDIT_LOG assertion.
  Spec: R1.7.

- [x] **2.5** [LINT] Run `shellcheck scripts/provision.sh` — must be clean after Phase 2 additions.

---

## Phase 3 — OS Detection & Precondition Functions (macOS-TDD)

> PV-15, PV-26 partially covered here (the abort logic is testable by mocking the check functions).
> These are pure/host-safe: no real `/etc/os-release`, use fixtures. Fully macOS-runnable.

- [x] **3.1** [RED] Write bats test for `detect_os()`:
  - Given a fixture `/etc/os-release` with `ID=ubuntu VERSION_ID=26.04` → returns version `26.04`, sets `OS_TARGET=ubuntu-2604`.
  - Given `ID=ubuntu VERSION_ID=24.04` → `OS_TARGET=ubuntu-2404`.
  - Given `ID=debian` → exits non-zero with stderr message identifying unsupported OS.
  - Given `VERSION_ID=22.04` → exits non-zero with stderr message identifying unsupported version.
  Spec: R1.1, R1.2.
  Implementation note: `detect_os` reads from a path, default `/etc/os-release`; test passes a
  fixture file via an override variable `OS_RELEASE_PATH="${BATS_TMPDIR}/os-release"`.

- [x] **3.2** [GREEN] Implement `detect_os()` in `scripts/provision.sh`: parse `ID` and
  `VERSION_ID` from `${OS_RELEASE_PATH:-/etc/os-release}`, validate ubuntu + (26.04|24.04),
  set `OS_VERSION` and `OS_TARGET`, abort with actionable error otherwise.
  Spec: R1.1, R1.2.

- [x] **3.3** [RED] Write bats test for `check_required_tools()`:
  - When all required tools are present (mock via `PATH` override pointing to stub binaries
    in `$BATS_TMPDIR`) → returns 0.
  - When `chattr` is missing → exits non-zero, stderr contains "chattr".
  - When `useradd` AND `adduser` are both missing → exits non-zero, stderr contains "useradd".
  Spec: R1.5. Maps to PV-26.

- [x] **3.4** [GREEN] Implement `check_required_tools()`: verify `chattr`, `lsattr`, one of
  `useradd`/`adduser`, `install`, `stat`, `getent` are on PATH. Abort with missing tool name on
  first failure. Also verify `jq` installable (simulate with `apt-get -s install jq` on Linux;
  on the check path just verify `command -v jq || true` and note it will be installed).
  Spec: R1.5, R1.6.

- [x] **3.5** [RED] Write bats test for `check_ext4()`:
  - Mock `stat -f -c %T` output to return `ext2/ext3` → exits 0 (ext4-family accepted).
  - Mock to return `tmpfs` → exits non-zero, stderr contains "tmpfs".
  - Mock to return `overlayfs` → exits non-zero, stderr contains "overlayfs".
  Implementation note: `check_ext4` uses a configurable target path variable `EXT4_CHECK_PATH`
  (default `/var/log`); test sets it to a dummy path and stubs `stat` via PATH override.
  Spec: R1.4, R1.4a. Maps to PV-15.

- [x] **3.6** [GREEN] Implement `check_ext4()`: stat `${EXT4_CHECK_PATH:-/var/log}` for filesystem
  type, accept ext4-family (including `ext2/ext3`), abort with detected type name otherwise.
  Spec: R1.4, R1.4a.

- [x] **3.7** [LINT] Run `shellcheck scripts/provision.sh` — must be clean after Phase 3 additions.

---

## Phase 4 — Semver Compare & CLI Version Logic (macOS-TDD)

> PV-17, PV-20 covered here. Pure string logic — fully macOS-runnable.

- [x] **4.1** [RED] Write bats test for `semver_gte()`:
  - `semver_gte "2.1.153" "2.1.153"` → exit 0
  - `semver_gte "2.1.200" "2.1.153"` → exit 0
  - `semver_gte "3.0.0" "2.1.153"` → exit 0
  - `semver_gte "2.1.152" "2.1.153"` → exit 1
  - `semver_gte "2.0.999" "2.1.153"` → exit 1
  - `semver_gte "1.99.99" "2.1.153"` → exit 1
  Spec: R9.3.

- [x] **4.2** [GREEN] Implement `semver_gte(v1 floor)` in `scripts/provision.sh`: split on `.`,
  compare major/minor/patch numerically, return 0 if v1 >= floor, 1 otherwise.
  Spec: R9.3.

- [x] **4.3** [RED] Write bats test for `assert_cli_version()`:
  - Mock `claude --version` output as `"Claude Code 2.1.200"` → exits 0, no WARNING in output.
  - Mock output as `"Claude Code 2.1.100"` (below floor) → exits 0 (NOT abort), stdout or stderr
    contains "WARNING" and "Layer-3".
  - Mock output as `"Claude Code 2.1.153"` → exits 0, no warning.
  Implementation note: `assert_cli_version` calls a configurable `CLAUDE_BIN` variable
  (default `claude`); tests set `CLAUDE_BIN` to a stub script in `$BATS_TMPDIR`.
  Spec: R9.1, R9.3. Maps to PV-17, PV-20.

- [x] **4.4** [GREEN] Implement `assert_cli_version()`: call `${CLAUDE_BIN:-claude} --version`,
  extract version string, call `semver_gte`, emit WARNING + Layer-3 flag if below floor but
  do NOT abort. Record version string for summary output.
  Spec: R9.1, R9.3.

- [x] **4.5** [RED] Write bats test for `check_audit_log_env()`:
  - When `AUDIT_LOG` is not set → exits 0.
  - When `AUDIT_LOG` is set (export it) → exits non-zero, stderr contains "AUDIT_LOG".
  Spec: R10.1, R10.2. Maps to PV-21.

- [x] **4.6** [GREEN] Implement `check_audit_log_env()`: assert `AUDIT_LOG` is unset in the
  current environment; exit non-zero with error if it is set.
  Spec: R10.1, R10.2.

- [x] **4.7** [RED] Write bats test for `format_summary()`:
  - Given populated provision state variables (OS version, CLI version, Layer-3 status
    VERIFIED/UNVERIFIED, list of applied paths) → output is non-empty, contains all path
    strings, contains Layer-3 status token, contains version string, contains SSH-seal warning.
  Spec: R2.5, R9.2, R9.4, R9.5. Maps to PV-18, PV-19.

- [x] **4.8** [GREEN] Implement `format_summary()`: print the non-secret provisioning summary —
  paths+modes+owners applied, installed CLI version string, DISABLE_AUTOUPDATER install-time note,
  Slice 2 DISABLE_AUTOUPDATER forward dependency note, Layer-3 status (VERIFIED / UNVERIFIED),
  SSH-seal warning for `aios`. MUST NOT print any secret value.
  Spec: R2.5, R9.2, R9.4, R9.5.

- [x] **4.9** [LINT] Run `shellcheck scripts/provision.sh` — must be clean after Phase 4 additions.

---

## Phase 5 — Mutating Step Implementation (Linux-Deferred; Tests Written Now)

> All tests in this phase use `skip_unless_linux_root_mutation` and are SKIP on macOS.
> Implementation is written now but verified only in a disposable Ubuntu VM/container.
> PV-01..PV-16, PV-21 covered here.

### 5A — aios account (PV-01, PV-02, PV-03, PV-04)

- [x] **5.1** [RED] Write bats tests for aios account creation (SKIP-gated):
  - PV-01: `getent passwd aios` shows UID=9001, GID=9001, shell=/usr/sbin/nologin, home=/nonexistent;
    `stat /nonexistent` exits non-zero.
  - PV-02: `id -nG aios` output does not contain "sudo" or "admin".
  - PV-03: pre-create a stub user with UID 9001 named "collide"; run provision.sh; assert non-zero exit,
    stderr contains UID collision message, no `aios` account created.
  - PV-04: pre-create a group with GID 9001 named "other"; assert non-zero exit, stderr contains GID
    collision message.
  Spec: R2.1, R2.2, R2.3, R2.4, R2.6, R2.7.

- [x] **5.2** [GREEN] Implement `create_aios_account()` in `scripts/provision.sh`:
  - Check `getent group 9001` → if exists and name ≠ "aios", abort with GID collision error.
  - `getent group aios &>/dev/null || groupadd -g 9001 aios`
  - Check `getent passwd 9001` → if exists and name ≠ "aios", abort with UID collision error.
  - `id aios &>/dev/null || useradd -r -u 9001 -g 9001 -s /usr/sbin/nologin --home-dir /nonexistent --no-create-home aios`
  - `passwd -l aios`
  - Assert aios NOT in sudo/admin groups.
  Spec: R2.1, R2.2, R2.3, R2.4, R2.6, R2.7, R2.8.

### 5B — Platform tree (PV-05, PV-06, PV-07, PV-08)

- [x] **5.3** [RED] Write bats tests for platform tree (SKIP-gated):
  - PV-05: `stat -c '%U:%G %a'` on `/opt/osgania/platform` = "root:aios 750"; same for `hooks/`.
  - PV-06: same stat on `guardia.sh` and `camara.sh` = "root:aios 750"; `test -x` both = exit 0.
  - PV-07: `test -f /opt/osgania/platform/managed-settings.json` = non-zero exit.
  - PV-08: `test -d /opt/osgania/client` = non-zero exit.
  Spec: R3.1, R3.2, R3.3, R3.4, R3.7, R3.8.

- [x] **5.4** [GREEN] Implement `install_platform_tree()` in `scripts/provision.sh`:
  - `install -d -o root -g aios -m 0750 /opt/osgania/platform`
  - `install -d -o root -g aios -m 0750 /opt/osgania/platform/hooks`
  - `install -o root -g aios -m 0750 "${REPO_ROOT}/platform/hooks/guardia.sh" /opt/osgania/platform/hooks/guardia.sh`
  - `install -o root -g aios -m 0750 "${REPO_ROOT}/platform/hooks/camara.sh" /opt/osgania/platform/hooks/camara.sh`
  - Assert `managed-settings.json` is NOT placed under platform/.
  Spec: R3.1–R3.8.

### 5C — Operator policy + secrets dir (PV-09, PV-10)

- [x] **5.5** [RED] Write bats tests for policy + secrets (SKIP-gated):
  - PV-09: `stat -c '%U:%G %a' /etc/claude-code/managed-settings.json` = "root:root 644";
    `jq . /etc/claude-code/managed-settings.json` exits 0 with non-empty stdout.
  - PV-10: `stat -c '%U:%G %a' /etc/osgania/secrets` = "root:root 700"; directory is empty.
  Spec: R4.1, R4.2, R4.3, R4.4, R5.1, R5.2, R5.3.

- [x] **5.6** [GREEN] Implement `install_operator_policy()` and `create_secrets_dir()`:
  - `install -d -o root -g root -m 0755 /etc/claude-code`
  - `install -o root -g root -m 0644 "${REPO_ROOT}/platform/managed-settings.json" /etc/claude-code/managed-settings.json`
  - `jq . /etc/claude-code/managed-settings.json > /dev/null` (validate JSON post-install)
  - `install -d -o root -g root -m 0700 /etc/osgania/secrets`
  Spec: R4.1–R4.4, R5.1–R5.3.

### 5D — Audit dir + file + chattr (PV-11, PV-12, PV-13, PV-14, PV-15, PV-27)

- [x] **5.7** [RED] Write bats tests for audit tree (SKIP-gated):
  - PV-11: `stat -c '%U:%G %a' /var/log/osgania` = "root:aios 750".
  - PV-12: `stat -c '%U:%G %a' /var/log/osgania/audit.jsonl` = "root:aios 620".
  - PV-13: `lsattr /var/log/osgania/audit.jsonl` output contains "a" flag.
  - PV-14: `stat -f -c %T /var/log/osgania` reports ext4-family.
  - PV-15: mock non-ext4 FS check → provision.sh exits non-zero before creating audit.jsonl.
  - PV-27: write a line to audit.jsonl, then attempt truncation via `> /var/log/osgania/audit.jsonl`;
    assert the truncation fails (non-zero) and content is preserved.
  Spec: R1.4, R6.1–R6.5, R7.1–R7.6.

- [x] **5.8** [GREEN] Implement `create_audit_tree()` in `scripts/provision.sh`:
  - `install -d -o root -g aios -m 0750 /var/log/osgania`
  - `[ -f /var/log/osgania/audit.jsonl ] || install -o root -g aios -m 0620 /dev/null /var/log/osgania/audit.jsonl`
  - `chattr +a /var/log/osgania/audit.jsonl` (add-only operator, never `-a`)
  - `lsattr /var/log/osgania/audit.jsonl | grep -q 'a'` (verify armed)
  Spec: R6.1–R6.5, R7.1–R7.6.

### 5E — jq install (PV-16)

- [x] **5.9** [RED] Write bats test for jq install (SKIP-gated):
  - PV-16: after provision.sh completes, `which jq` exits 0 with non-empty path.
  Spec: R8.1, R8.2, R8.3.

- [x] **5.10** [GREEN] Implement `install_jq()` in `scripts/provision.sh`:
  - `which jq &>/dev/null || apt-get install -y jq`
  - Verify: `which jq` returns non-empty path after install.
  Spec: R8.1, R8.2, R8.3, R8.4.

### 5F — CLI pin + live mode-lock (PV-17, PV-18, PV-19, PV-20)

- [x] **5.11** [RED] Write bats tests for CLI pin (SKIP-gated):
  - PV-17: `claude --version` exits 0, version string parses, is >= v2.1.153.
  - PV-18: provisioning summary output contains the CLI version string and a note that
    DISABLE_AUTOUPDATER was set during install; also contains the Slice 2 forward dependency note.
  - PV-19: provisioning output contains "Layer-3: VERIFIED" or "Layer-3: UNVERIFIED".
  - PV-20: when CLI version is below floor, provision.sh exits 0 (does NOT abort), output
    contains "WARNING" and "Layer-3".
  Spec: R9.1, R9.2, R9.2a, R9.3, R9.4, R9.5.

- [x] **5.12** [GREEN] Implement `install_cli()` in `scripts/provision.sh`:
  - Version-equality check before re-installing.
  - `DISABLE_AUTOUPDATER=1` install invocation of pinned version (>= v2.1.153).
  - `assert_cli_version` (reuse Phase 4 function).
  - Live mode-lock test: attempt `--dangerously-skip-permissions` or effective-policy introspection;
    record VERIFIED/UNVERIFIED result for `format_summary`.
  Spec: R9.1, R9.2, R9.3, R9.4, R9.5.

- [x] **5.13** [LINT] Run `shellcheck scripts/provision.sh` — must be clean after Phase 5 additions.

---

## Phase 6 — Idempotency & `main()` Wiring (Linux-Deferred)

> PV-21, PV-22, PV-23, PV-24 covered here. Tests are SKIP-gated.

- [x] **6.1** [RED] Write bats tests for idempotency (SKIP-gated):
  - PV-22: run provision.sh twice; `getent passwd aios` returns exactly one entry; `id -u aios` = 9001; exit 0.
  - PV-23: run twice with pre-existing audit.jsonl content; same inode, same content, `lsattr` still shows "a".
  - PV-24: run once; manually chmod `/opt/osgania/platform` to 0755; run again; mode restored to 750.
  Spec: R11.1–R11.6.

- [x] **6.2** [RED] Write bats test for AUDIT_LOG env assertion (macOS-safe if AUDIT_LOG not set):
  - PV-21 (macOS-runnable portion): `check_audit_log_env` called from `main` — `AUDIT_LOG` must be
    unset at end of run. Test sources provision.sh and calls `check_audit_log_env` with and without
    `AUDIT_LOG` set.
  Already covered by task 4.5/4.6 for the function; this task writes the integration-level assertion
  that `main` calls it as its final step.
  Spec: R10.1, R10.2.

- [x] **6.3** [GREEN] Implement `main()` in `scripts/provision.sh` — wire the ordered phase calls:
  ```
  parse_args "$@"
  if [[ "$CHECK_MODE" -eq 1 ]]; then report_plan; exit 0; fi
  detect_os
  check_preconditions     # check_required_tools + check_ext4 + systemd check
  create_aios_account
  install_platform_tree
  install_jq
  install_operator_policy
  create_secrets_dir
  create_audit_tree
  install_cli
  check_audit_log_env
  format_summary
  ```
  Includes systemd liveness check inline in `check_preconditions` (`systemctl --version`).
  Spec: R1.1–R1.7, R2–R11 (all requirements wired through the ordered steps).

- [x] **6.4** [LINT] Run `shellcheck scripts/provision.sh` — final lint pass on the complete file.

---

## Phase 7 — Full Suite Pass & Handoff

> All tasks in this phase are macOS-runnable (the Linux-gated tests will SKIP cleanly, not fail).

- [x] **7.1** Run `bats tests/provision.bats` on macOS. Assert:
  - All macOS-safe tests (Phase 2–4 function tests + PV-21 env check + PV-25 --check mode) are GREEN.
  - All Linux-gated tests (PV-01..PV-16, PV-22..PV-24, PV-27 and parts of PV-17..PV-20) are SKIPPED
    with the message "requires Linux root + PROVISION_TEST_ALLOW_MUTATION=1".
  - Zero FAIL results.
  RESULT: 125 total (53 from provision.bats + 72 from existing suites), 20 skipped, 0 failed.

- [x] **7.2** Run `shellcheck scripts/**/*.sh` — must exit 0 with no warnings across both
  `scripts/provision.sh` and `platform/hooks/guardia.sh` + `platform/hooks/camara.sh`
  (existing hooks must not regress).
  RESULT: EXIT 0, zero warnings.

- [x] **7.3** Handoff note (record in apply-progress for the verify phase):
  **Linux-environment verification required** — the following PV scenarios are SKIPPED on macOS
  and MUST be re-run in a disposable Ubuntu 26.04 VM or privileged container (`--cap-add LINUX_IMMUTABLE`
  on ext4) with `PROVISION_TEST_ALLOW_MUTATION=1` as root:
  PV-01, PV-02, PV-03, PV-04, PV-05, PV-06, PV-07, PV-08, PV-09, PV-10, PV-11, PV-12, PV-13,
  PV-14, PV-15, PV-16, PV-17 (live), PV-18 (live), PV-19 (live), PV-20 (live), PV-22, PV-23,
  PV-24, PV-27.
  PV-25 (--check mode) and PV-21 (AUDIT_LOG env) are macOS-green.
  PV-26 (missing tool abort) is macOS-testable via PATH stub (mark as done in Phase 3).

---

## PV Scenario Coverage Table

| Scenario | Requirement(s) | Task | Env |
|----------|---------------|------|-----|
| PV-01 | R2.1, R2.2 | 5.1, 5.2 | Linux-deferred |
| PV-02 | R2.3, R2.4 | 5.1, 5.2 | Linux-deferred |
| PV-03 | R2.6 | 5.1, 5.2 | Linux-deferred |
| PV-04 | R2.7 | 5.1, 5.2 | Linux-deferred |
| PV-05 | R3.1, R3.2 | 5.3, 5.4 | Linux-deferred |
| PV-06 | R3.3, R3.4 | 5.3, 5.4 | Linux-deferred |
| PV-07 | R3.7 | 5.3, 5.4 | Linux-deferred |
| PV-08 | R3.8 | 5.3, 5.4 | Linux-deferred |
| PV-09 | R4.1, R4.2, R4.4 | 5.5, 5.6 | Linux-deferred |
| PV-10 | R5.1, R5.2 | 5.5, 5.6 | Linux-deferred |
| PV-11 | R6.1, R6.5 | 5.7, 5.8 | Linux-deferred |
| PV-12 | R6.2, R6.4 | 5.7, 5.8 | Linux-deferred |
| PV-13 | R7.1, R7.3 | 5.7, 5.8 | Linux-deferred |
| PV-14 | R1.4, R7.5 | 5.7 | Linux-deferred |
| PV-15 | R1.4 | 3.5, 3.6, 5.7 | macOS (stub) + Linux-deferred (real) |
| PV-16 | R8.1, R8.2 | 5.9, 5.10 | Linux-deferred |
| PV-17 | R9.1, R9.3 | 4.3, 4.4, 5.11, 5.12 | macOS (stub) + Linux-deferred (live) |
| PV-18 | R9.2, R9.2a | 4.7, 4.8, 5.11, 5.12 | macOS (stub) + Linux-deferred (live) |
| PV-19 | R9.4, R9.5 | 4.7, 4.8, 5.11, 5.12 | macOS (stub) + Linux-deferred (live) |
| PV-20 | R9.3 | 4.3, 4.4, 5.11 | macOS (stub) + Linux-deferred (live) |
| PV-21 | R10.1, R10.2 | 4.5, 4.6, 6.2 | macOS-safe |
| PV-22 | R11.1, R11.2 | 6.1, 6.3 | Linux-deferred |
| PV-23 | R11.1, R11.5, R11.6 | 6.1, 6.3 | Linux-deferred |
| PV-24 | R11.2 | 6.1, 6.3 | Linux-deferred |
| PV-25 | R1.7 | 2.1–2.4 | macOS-safe |
| PV-26 | R1.5 | 3.3, 3.4 | macOS-safe (PATH stub) |
| PV-27 | R7.1, R7.6 | 5.7, 5.8 | Linux-deferred |

**All 27 PV scenarios are mapped. None is orphaned.**

macOS-runnable (green or skip-clean): PV-15 (stub), PV-17 (stub), PV-18 (stub), PV-19 (stub), PV-20 (stub), PV-21, PV-25, PV-26.
Linux-deferred (skip on macOS, require disposable Ubuntu env): PV-01..PV-14, PV-16, PV-22..PV-24, PV-27.

---

## Size Estimate

| File | Estimated LOC |
|------|--------------|
| `scripts/provision.sh` | 280–340 |
| `tests/provision.bats` | 300–380 |
| `tests/test_helper.bash` (additions) | 25–35 |
| **Total new lines** | **605–755** |

Total tasks: **36** (across 7 phases)
Parallel-capable: Phase 1 is prerequisite; Phases 2, 3, 4 can proceed concurrently after Phase 1 scaffold; Phase 5 tasks 5A–5F can be worked in sequence within Phase 5 once Phase 3/4 functions exist; Phase 6 requires Phase 5; Phase 7 requires all prior phases.
