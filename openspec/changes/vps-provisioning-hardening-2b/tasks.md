# Tasks: vps-provisioning-hardening-2b ("Autonomy + Egress")

**Change**: `vps-provisioning-hardening-2b`
**Project**: osgania
**Artifact store**: openspec + engram
**Generated**: 2026-06-17
**Status**: tasks
**Depends on**: `vps-provisioning-hardening-2a` (ARCHIVED, canonical)

---

## Quick-path summary

| Phase | Task count | Bats tier | PR |
|-------|-----------|-----------|-----|
| WU0 — Contract finalization | 7 tasks (sequential) — **COMPLETE** | HOST-SAFE (doc edits) | Pre-PR; no code |
| U1 — STEP 0: restore run path | 7 tasks (sequential within unit) | HOST-SAFE + LINUX-ROOT + LIVE-KEY | PR-1 → tracker |
| U2 — nft egress wall | 7 tasks (sequential within unit) | HOST-SAFE + LINUX-ROOT + LIVE-KEY | PR-2 → U1 branch |
| U3 — Broad autonomy | 9 tasks (sequential within unit) | HOST-SAFE + LINUX-ROOT + LIVE-KEY | PR-3 → U2 branch |
| **Total** | **30 tasks** | | |

**WU0 is DONE (planning phase).** All 7 WU0 tasks (contract-finalization doc edits for JD-1…JD-6 + minors) are Applied. Implementation begins at U1.

**DELIVERY-ORDERING INVARIANT (non-negotiable):** U2 MUST be proven hermetic (PR-2 merged to tracker) BEFORE U3's allow[] is enabled. Enforced at two layers: (1) feature-branch-chain PR ordering — U3 targets U2's branch and cannot merge without U2; (2) fail-closed provisioner gate in U3 (HB-06.2) that refuses to write a non-empty allow[] if the wall is absent or the uid-9001 self-check connects.

---

## WU0 — Contract finalization (resolve Judgment Day Round-3 deferred findings)

> These are **spec.md / design.md text edits only**. No implementation code. All 7 tasks MUST be completed before any U1–U3 implementation task begins. They ensure the downstream implementation tasks derive from a clean, internally-consistent contract.

> WU0 tasks run SEQUENTIALLY; each produces a doc edit that a later WU0 task or U1+ task reads.

---

### WU0-T1 — JD-1: Align python3 self-check to distinguish timeout (exit 124) from refused — [Applied.]

**Findings resolved**: JD-1

**What to edit**:

1. **spec.md, section HB-06.2b** — In the python3 alternative code block, replace the one-liner:
   ```python
   sys.exit(0 if s.connect_ex(('1.1.1.1',443))==0 else 1)
   ```
   with a form that catches `socket.timeout` specifically and exits 124, lets all other errors exit 1:
   ```python
   import socket,sys
   s=socket.socket()
   s.settimeout(5)
   r=s.connect_ex(('1.1.1.1',443))
   if r==0: sys.exit(0)
   try:
     import errno
     if r==errno.ETIMEDOUT: sys.exit(124)
   except: pass
   sys.exit(1)
   ```
   Note: the ETIMEDOUT path is the PROCEED signal (exit 124); exit 0 = connected = REFUSE; any other non-zero (ECONNREFUSED, exception, etc.) = REFUSE (exit 1, fail-closed).

2. **spec.md, section HB-06.2b** — Update the "Fail-closed exit semantics" bullet to align: the BLOCKED result for python3 is also exit 124 (not just "non-zero"); any non-124 non-0 python3 exit → REFUSE.

3. **design.md, section §5** — Update the python3 code block to the same timeout-distinguishing form as above. Update the prose "exit 1 means not connected; the provisioner additionally distinguishes..." to: "exit 124 = ETIMEDOUT = wall PRESENT = PROCEED; exit 0 = connected = REFUSE; any other exit = REFUSE."

**Verification**: After edits, search both files for `sys.exit(0 if` — must return zero results. [Applied.]

---

### WU0-T2 — JD-2: Fix HB-06-S2b to assert exit 124 (not "non-zero") on the PROCEED branch — [Applied.]

**Findings resolved**: JD-2

**What to edit**:

1. **spec.md, section HB-06-S2b** — In the second GIVEN/THEN block (the "wall IS loaded" scenario):
   - Change: `THEN it exits non-zero (the TCP connect TIMES OUT — wall is present)`
   - To: `THEN it exits 124 (the TCP connect TIMES OUT — wall is present; `timeout` exits 124 on timeout)`
   - Add a note: `AND the provisioner gate interprets exit 124 as WALL OK → PROCEED; any other non-zero exit is REFUSE (fail-closed)`

2. **spec.md, section HB-06-S2b note** — Update the note at the bottom:
   - Change: `non-zero = blocked = wall present = PROCEED`
   - To: `exit 124 = blocked = wall present = PROCEED; non-124 non-0 = ambiguous = REFUSE`

**Verification**: Search spec.md for `non-zero` within the HB-06-S2b section — only the REFUSE/wall-absent branch should say "non-zero"; the PROCEED branch must say "124". [Applied.]

---

### WU0-T3 — JD-3: Align design.md Checklist fail-closed bullet to body forms — [Applied.]

**Findings resolved**: JD-3

**What to edit**:

1. **design.md, section "Checklist"**, the fail-closed activation gate bullet — Replace the stale form:
   - Remove: references to `socket.create_connection` (body uses `connect_ex`)
   - Remove: bare `timeout` (body uses `/bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/..."'`)
   - Replace with canonical forms (matching §5 body exactly):
     ```
     bash form:   /bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/<canary>/443"'  (NOT /bin/sh)
     python3 form: connect_ex() + socket.timeout catch → exit 124 (per JD-1 fix)
     ```
   - Ensure the bullet also notes: `exit-0=REFUSE, exit-124=PROCEED, other=REFUSE`.

**Verification**: Search design.md for `create_connection` — must return zero results after edit. [Applied.]

---

### WU0-T4 — JD-4: Complete HB-10.1 manifest (add systemd units; annotate guardia.sh) — [Applied.]

**Findings resolved**: JD-4

**What to edit**:

1. **spec.md, section HB-10.1** — Add two rows to the manifest table under `platform/systemd/`:
   ```
   platform/
     systemd/
       osgania-agent.service  — 2b-updated: adds After=nftables.service + Wants=nftables.service
                                + DISABLE_TELEMETRY=1 + DISABLE_ERROR_REPORTING=1 (HB-02.7a, HB-02.8)
       osgania-agent.timer    — 2b-updated: adds After=nftables.service + Wants=nftables.service
                                (HB-02.7a)
   ```

2. **spec.md, section HB-10.1** — Annotate the `guardia.sh` manifest entry to read:
   ```
   hooks/
     guardia.sh  — updated: benign branch = pass-through (HB-04; was defer)
                   (Unit 3 ONLY — MUST NOT ship in U1/U2 PRs; guardia stays 2a defer version through U1+U2)
   ```

**Verification**: HB-10.1 manifest must contain exactly these paths after the edit: `scripts/provision-agent.sh`, `platform/bin/agent-run.sh`, `platform/hooks/guardia.sh` (annotated Unit-3 only), `platform/nft/osgania-egress.nft`, `platform/prompts/agent-prompt.txt`, `platform/systemd/osgania-agent.service`, `platform/systemd/osgania-agent.timer`, `tests/provision-agent.bats`, `tests/guardia.bats`, `tests/egress.bats`. [Applied.]

---

### WU0-T5 — JD-5: Align spec HB-06.2b systemd-run invocation to design §5 full flag set — [Applied.]

**Findings resolved**: JD-5

**What to edit**:

1. **spec.md, section HB-06.2b** — In the self-check code block under "(b) Live hermetic self-check BLOCKED", replace the bare `systemd-run --uid=9001` snippet with the full flag set from design §5:
   ```bash
   systemd-run --uid=9001 --gid=9001 --pipe --quiet --collect \
     --property=RestrictAddressFamilies='AF_INET AF_INET6' \
     --property=Environment='' \
     /bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"' </dev/null
   ```
   or the python3 equivalent with the same flags (updated per JD-1).

2. Add a reference: "Design §5 is the authoritative full form. Implementers MUST use the design §5 form."

**Verification**: Search spec.md for `systemd-run` within HB-06.2b — the invocation must contain `--gid=9001`, `--pipe`, `--quiet`, `--collect`, and `--property=Environment=''`. [Applied.]

---

### WU0-T6 — JD-6: Refactor HA-09 probe to invoke /usr/bin/claude directly (RESOLVED)

**Findings resolved**: JD-6

**Corrected finding (replaces the prior wrong conclusion that JD-6 was "not regressive"):**

The 2a probe invokes the wrapper as:
```bash
"$wrapper" -p --output-format stream-json --verbose --dangerously-skip-permissions 'Reply with the single word: ok'
```

This was safe in 2a because the 2a wrapper was a TRANSPARENT PASS-THROUGH (`exec /usr/bin/claude "$@"`) — all args reached claude. The 2b wrapper is different: it hardcodes `exec /usr/bin/claude --permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"` and DISCARDS `"$@"` entirely (beyond the HB-01.8 `-p` presence guard). Routing the probe through the 2b wrapper causes TWO failures:

1. `--output-format stream-json --verbose --dangerously-skip-permissions` are DISCARDED → no stream-json `init` event → `permissionMode` field absent → oracle unreadable → **HB-05.1 BROKEN**.
2. `--permission-mode dontAsk` is INJECTED into the probe path → **HB-05.2 VIOLATED**.

The HB-01.8 `-p` guard passes (probe does pass `-p`), but the guard is irrelevant to the breakage — the damage is the arg-discarding and dontAsk injection in the wrapper's fixed exec line.

**Resolution**: The HA-09 probe MUST invoke `/usr/bin/claude` DIRECTLY, exporting `ANTHROPIC_API_KEY` inline from `AGENT_SECRETS_KEY` (`/etc/osgania/secrets/anthropic-api-key` — `CREDENTIALS_DIRECTORY` is a systemd LoadCredential var set only at service runtime; the provisioner runs outside systemd), with no `--permission-mode dontAsk`. The probe tests the managed-settings layer, which is independent of the wrapper. See implementation task U1-T7.

**What to edit (contract changes — done by this task in the context of the JD-6-REAL fix)**:

1. **spec.md, section HB-01.3** — Add the note that the 2b wrapper is a production launcher (not transparent), `"$@"` is discarded beyond the `-p` guard, and verification paths needing different claude args MUST invoke claude directly. [Applied.]

2. **spec.md, section HB-05.2** — Rewritten: probe invokes `/usr/bin/claude` directly, exports `ANTHROPIC_API_KEY` itself from `AGENT_SECRETS_KEY` (`/etc/osgania/secrets/anthropic-api-key` — `CREDENTIALS_DIRECTORY` is runtime-only; probe uses the persistent on-disk path), MUST NOT include `--permission-mode dontAsk`, MUST NOT call `"$wrapper"` / `agent-run.sh`. [Applied.]

3. **spec.md, section HB-05.4** — New sub-requirement: probe's direct-claude invocation MUST still produce a stream-json `init` event with `permissionMode != "bypassPermissions"` (VERIFIED), because `disableBypassPermissionsMode:"disable"` remains in managed-settings and neutralizes `--dangerously-skip-permissions` regardless of wrapper. [Applied.]

4. **spec.md, scenario HB-05-S1** — Updated to assert: (1) probe calls `/usr/bin/claude` directly (NOT `"$wrapper"` / `agent-run.sh`); (2) probe does NOT contain `--permission-mode dontAsk`; (3) probe contains `--dangerously-skip-permissions`; (4) probe contains `--output-format stream-json`. [Applied.]

5. **spec.md, Deferred JD table, JD-6 row** — Marked RESOLVED with the direct-invocation decision. [Applied.]

6. **design.md, §3** — Added the "PRODUCTION LAUNCHER, not transparent pass-through" note and the HA-09 probe direct-invocation rationale. JD-6 marked RESOLVED in the Deferred review findings section. [Applied.]

7. **tasks.md, U1-T2** — Updated source assertion to match the new direct-claude probe form (assertions 1–4 from HB-05-S1). See U1-T2 below.

8. **tasks.md, U1-T3** — Added note that the wrapper intentionally discards `"$@"` and that the probe is handled separately by U1-T7.

9. **tasks.md, U1-T7 (NEW)** — Implementation task: refactor the HA-09 probe to call claude directly.

**Verification**: After all contract edits, search all three files for `"$wrapper"` in the context of probe invocations — must return zero positive results; only negative assertion comments allowed. Search for "not regressive" / "no probe modification needed" — must return zero results.

---

### WU0-T7 — Final blind re-judge of self-check contract + manifest area

**What**: Optional but recommended adversarial micro-review of the WU0 edits (the self-check exit-code contract and the HB-10.1 manifest section) before implementation begins. Run a single blind judge pass scoped to:
- The HB-06.2b self-check exit semantics (JD-1+JD-2 fixes)
- The design §5 Checklist bullet (JD-3 fix)
- The HB-10.1 manifest completeness (JD-4 fix)

**Exit criterion**: Judge returns APPROVED or only SUGGESTIONs (no WARNING or CRITICAL) on these sections.

**Note**: This task is OPTIONAL — if the team is confident in WU0-T1 through WU0-T6, skip it and proceed to U1. If any judge returns a WARNING or CRITICAL on the scoped sections, fix before proceeding.

---

## U1 — STEP 0: Restore the run path + wire prompt source

> PR-1: targets the tracker branch.
> **guardia.sh stays the 2a defer-emitting version in this unit.** Pass-through MUST NOT ship in U1.
> Exit criterion: `systemctl start osgania-agent.service` runs `claude -p`, box alive, at least one audit record in `/var/log/osgania/audit.jsonl`, journal does NOT contain "Input must be provided".

> U1 tasks run SEQUENTIALLY (each task is a prerequisite for the next).

---

### U1-T1 — [TEST] Write bats scenarios for wrapper content and prompt-file assertions (HOST-SAFE)

**Tier**: HOST-SAFE
**Bats file**: `tests/provision-agent.bats`
**Requirements satisfied**: HB-01.3, HB-01.4, HB-01.6, HB-01.8, HB-03.4 (partial)
**Scenarios covered**: HB-01-S2, HB-01-S2b, HB-01-S4, HB-01-S5

Write (or update) the following `@test` blocks in `tests/provision-agent.bats`:

1. **HB-01-S2** — assert `platform/bin/agent-run.sh` (2b version) contains:
   - the canonical exec line `exec /usr/bin/claude --permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"` (exact string match)
   - `--permission-mode dontAsk` appears BEFORE `-p` in that exec line
   - `$PROMPT_FILE` is double-quoted and holds the canonical path
   - does NOT contain `--bare`
   - does NOT contain `exec /usr/bin/claude "$@"` (the old 2a exec line)

2. **HB-01-S2b** — assert wrapper exits non-zero when invoked without `-p`:
   - source the wrapper-under-test in a subshell that stubs out `exec` and asserts non-zero exit
   - assert stderr contains a message indicating `-p` is required

3. **HB-01-S4** — assert the `PROMPT_FILE` variable in the wrapper equals `/opt/osgania/platform/prompts/agent-prompt.txt` and does NOT begin with `/opt/osgania/client`.

4. **HB-01-S5** — assert the assembled `osgania-agent.service` unit string (call `build_service_unit` from the provisioner) contains exactly `ExecStart=/opt/osgania/platform/bin/agent-run.sh -p`, does NOT contain `--bare`, does NOT contain `--permission-mode`.

**Run**: `bats tests/provision-agent.bats` on macOS — these tests MUST fail (RED) before implementation.

---

### U1-T2 — [TEST] Write bats scenario for probe-invocation source assertions (HOST-SAFE)

**Tier**: HOST-SAFE
**Bats file**: `tests/provision-agent.bats`
**Requirements satisfied**: HB-05.2, HB-05.4
**Scenarios covered**: HB-05-S1

Write the `@test` block:

1. **HB-05-S1** — four grep-based source assertions against `scripts/provision-agent.sh` (the `run_defense_in_depth_probe` function body):
   - **(1) Direct invocation**: the probe invocation calls `/usr/bin/claude` as the binary, NOT `"$wrapper"` or `agent-run.sh`. Assert: the probe block contains `/usr/bin/claude` AND does NOT contain `"$wrapper"` as the invoked binary. (The 2a form called `"$wrapper"`; the 2b form calls claude directly — this MUST fail RED against 2a source and GREEN after U1-T7.)
   - **(2) No dontAsk**: the probe invocation block does NOT contain the substring `--permission-mode dontAsk`.
   - **(3) Has dangerously-skip-permissions**: the probe invocation contains `--dangerously-skip-permissions`.
   - **(4) Has output-format stream-json**: the probe invocation contains `--output-format stream-json`.

**Run**: `bats tests/provision-agent.bats` — assertion (1) MUST fail (RED) against the 2a source (which calls `"$wrapper"`). Assertions (2)–(4) should pass against the 2a source if the probe already contains those flags. All four MUST be GREEN after U1-T7.
**Note**: JD-6 resolution. The 2a probe called `"$wrapper"` (safe only because 2a wrapper was transparent); the 2b wrapper discards args and injects dontAsk, breaking the oracle. U1-T7 fixes the probe by calling claude directly.

---

### U1-T3 — [IMPLEMENT] Update `platform/bin/agent-run.sh` (wrapper 2b)

**Tier**: HOST-SAFE (file edit on macOS)
**Requirements satisfied**: HB-01.3, HB-01.4, HB-01.6, HB-01.7, HB-01.8, HB-03.4
**Files changed**: `platform/bin/agent-run.sh`

**Changes (exact)**:

1. Add `PROMPT_FILE="/opt/osgania/platform/prompts/agent-prompt.txt"` as a variable declaration after the `ANTHROPIC_API_KEY` export block (lines 14–16 of the current wrapper).

2. Add the `-p` standalone guard immediately before the exec line:
   ```bash
   # HB-01.8: guard against direct interactive invocation without -p
   _found_p=0
   for _arg in "$@"; do
       [[ "$_arg" == "-p" ]] && _found_p=1 && break
   done
   if [[ "$_found_p" -eq 0 ]]; then
       printf 'agent-run.sh: -p argument is required; refusing to exec claude without it\n' >&2
       exit 1
   fi
   unset _found_p _arg
   ```

3. Replace the final `exec /usr/bin/claude "$@"` with:
   ```bash
   exec /usr/bin/claude --permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"
   ```

4. Preserve ALL lines above (auth block, `set -euo pipefail`, CREDENTIALS_DIRECTORY check, ANTHROPIC_API_KEY export).

5. Run `shellcheck -s bash platform/bin/agent-run.sh` — MUST exit 0 with no warnings.

**Important — intentional arg-discard (JD-6):** This change makes the wrapper a PRODUCTION LAUNCHER that hardcodes the entire claude invocation. `"$@"` is no longer forwarded to claude; only the HB-01.8 `-p` guard checks it. Any caller that needs to pass different claude args (e.g. `--output-format stream-json --dangerously-skip-permissions`) MUST NOT go through this wrapper — see U1-T7 for the HA-09 probe refactor that handles this consequence.

**Run tests**: `bats tests/provision-agent.bats` — HB-01-S2, HB-01-S2b, HB-01-S4 MUST now pass (GREEN).

---

### U1-T4 — [IMPLEMENT] Add `platform/prompts/agent-prompt.txt` template

**Tier**: HOST-SAFE (file creation on macOS)
**Requirements satisfied**: HB-01.3, HB-01.4
**Files changed**: `platform/prompts/agent-prompt.txt` (NEW)

**Changes**:

1. Create the file `platform/prompts/agent-prompt.txt` with a placeholder operator prompt:
   ```
   You are the Osgania autonomous agent. Review the task list and complete the next pending task.
   ```
   (Exact content is operator-configurable; this is the repo template.)

2. Update `scripts/provision-agent.sh` `install_wrapper()` step (or add a new `install_prompt_file()` function called from `main` Step 4) to:
   - Copy `platform/prompts/agent-prompt.txt` to `/opt/osgania/platform/prompts/agent-prompt.txt`
   - Set ownership: `chown root:root /opt/osgania/platform/prompts/agent-prompt.txt`
   - Set mode: `chmod 0644 /opt/osgania/platform/prompts/agent-prompt.txt`
   - The parent directory `/opt/osgania/platform/prompts/` must be created with `install -d -o root -g root -m 0755` if absent.

3. Add a `--bare` lint check in `install_wrapper()` that also checks `platform/bin/agent-run.sh` source content for the `--bare` token (HB-01.6 + HB-06.2's `provision-agent.sh` lint).

4. Run `shellcheck -s bash scripts/provision-agent.sh` — MUST exit 0.

**Run tests**: `bats tests/provision-agent.bats` — HB-01-S5 MUST now pass (GREEN).

---

### U1-T5 — [IMPLEMENT] Update `platform/systemd/osgania-agent.service` (2b: telemetry env + nftables ordering prep)

**Tier**: HOST-SAFE (file edit on macOS)
**Requirements satisfied**: HB-02.8, HB-02.7a (partial — the unit is updated in U1 so it is ready when U2 installs it; the nftables ordering is required by U2's exit criterion)
**Files changed**: `platform/systemd/osgania-agent.service`

**Changes**:

1. Add two `Environment=` lines after the existing `Environment=DISABLE_AUTOUPDATER=1` line:
   ```
   Environment=DISABLE_TELEMETRY=1
   Environment=DISABLE_ERROR_REPORTING=1
   ```

2. Add boot-ordering directives in the `[Unit]` section (after `Wants=network-online.target`):
   ```
   After=nftables.service
   Wants=nftables.service
   ```

3. The `ExecStart=` line MUST remain byte-identical: `ExecStart=/opt/osgania/platform/bin/agent-run.sh -p`. Do NOT add `--permission-mode` or any other flag here.

4. Update `build_service_unit()` in `scripts/provision-agent.sh` to match the new unit content (the function is the source of truth for the written unit; the repo file `platform/systemd/osgania-agent.service` must be byte-identical to what `build_service_unit()` produces).

5. Run `shellcheck -s bash scripts/provision-agent.sh` — MUST exit 0.

**Run tests**: `bats tests/provision-agent.bats` — HB-01-S5 (ExecStart assertion), HB-02-S2c (After/Wants), HB-02-S3 (telemetry env) MUST now pass.

**Note**: HB-02-S2c and HB-02-S3 bats scenarios are written in U2-T1; they MUST exist (even if failing) before this task makes them GREEN.

---

### U1-T6 — [IMPLEMENT] Update `platform/systemd/osgania-agent.timer` (2b: nftables ordering)

**Tier**: HOST-SAFE (file edit on macOS)
**Requirements satisfied**: HB-02.7a
**Files changed**: `platform/systemd/osgania-agent.timer`

**Changes**:

1. Add boot-ordering directives in the `[Unit]` section:
   ```
   After=nftables.service
   Wants=nftables.service
   ```

2. Update `build_timer_unit()` in `scripts/provision-agent.sh` to match.

3. Run `shellcheck -s bash scripts/provision-agent.sh` — MUST exit 0.

**Run tests**: `bats tests/provision-agent.bats` — HB-02-S2d MUST now pass.
**Note**: The HB-02-S2d scenario is written in U2-T1 (it is a HOST-SAFE assertion; write it there, make it GREEN here by completing U1-T6 before U2-T1 runs — or accept it RED in U1 and GREEN in U2-T1's pass).

---

### U1-T7 — [IMPLEMENT] Refactor the HA-09 probe in `scripts/provision-agent.sh` to invoke `/usr/bin/claude` directly

**Tier**: HOST-SAFE for the source/grep assertion (HB-05-S1) + LINUX-ROOT/LIVE-KEY for the live probe-survival run (HB-05.1)
**Requirements satisfied**: HB-05.1, HB-05.2, HB-05.4
**Files changed**: `scripts/provision-agent.sh`

**Changes (inside `run_defense_in_depth_probe`):**

1. Remove the `"$wrapper"` call (the 2a form: `"$wrapper" -p --output-format stream-json --verbose --dangerously-skip-permissions '<prompt>' </dev/null`).

2. Replace it with a direct claude invocation that exports `ANTHROPIC_API_KEY` inline:
   ```bash
   # JD-6 resolution: probe calls /usr/bin/claude DIRECTLY — do NOT route through
   # agent-run.sh (the 2b wrapper is a production launcher that discards "$@" and
   # injects --permission-mode dontAsk, destroying both probe oracles).
   # Read from AGENT_SECRETS_KEY (persistent on-disk path), NOT CREDENTIALS_DIRECTORY:
   # the provisioner runs outside systemd, so the LoadCredential dir is unset here. Spec HB-05.2.
   local _probe_key
   _probe_key="$(tr -d '[:space:]' < "${AGENT_SECRETS_KEY}")"
   ANTHROPIC_API_KEY="$_probe_key" \
     /usr/bin/claude -p \
       --output-format stream-json \
       --verbose \
       --dangerously-skip-permissions \
       'Reply with the single word: ok' </dev/null
   ```
   The probe MUST NOT include `--permission-mode dontAsk`. The `ANTHROPIC_API_KEY` is exported inline for the probe invocation only; it MUST NOT persist in the provisioner environment after the call.

3. The rest of the probe logic (parsing the stream-json `init` event, reading `permissionMode`, setting `AGENT_PROBE_STATUS`) MUST remain unchanged.

4. Run `shellcheck -s bash scripts/provision-agent.sh` — MUST exit 0.

**Run tests**: `bats tests/provision-agent.bats` — HB-05-S1 assertions (1)–(4) MUST now ALL pass (GREEN):
- (1) probe block contains `/usr/bin/claude` and does NOT contain `"$wrapper"` as the invoked binary.
- (2) probe block does NOT contain `--permission-mode dontAsk`.
- (3) probe block contains `--dangerously-skip-permissions`.
- (4) probe block contains `--output-format stream-json`.

**Live verification** (LINUX-ROOT/LIVE-KEY, deferred to VPS): after U3 is active, run `run_defense_in_depth_probe` and assert `AGENT_PROBE_STATUS=VERIFIED` — i.e. the stream-json `init` event arrives with `permissionMode != "bypassPermissions"`, confirming HB-05.1 is preserved via the direct invocation. See U3-T9.

---

**U1 EXIT CRITERION**: `build_service_unit()` in the provisioner produces a unit string that passes all HOST-SAFE assertions (HB-01-S2, HB-01-S2b, HB-01-S4, HB-01-S5, HB-02-S2c, HB-02-S3, HB-05-S1). LINUX-ROOT/LIVE-KEY scenario HB-01-S6 (service starts, produces audit record) is deferred to live testing on the disposable VPS via `scripts/run-live-key-tests.sh`.

---

## U2 — nft IP-pin egress wall

> PR-2: targets the U1 branch.
> guardia.sh stays the 2a defer-emitting version. allow[] stays `[]`.
> Exit criterion: from uid 9001, only 443→Anthropic-range + loopback leave; everything else DROPs; root unaffected; `claude -p` works end-to-end under the wall.

> U2 tasks run SEQUENTIALLY.

---

### U2-T1 — [TEST] Write bats scenarios for nft ruleset structure and unit ordering (HOST-SAFE) — [Applied.]

**Tier**: HOST-SAFE
**Bats file**: `tests/egress.bats` (NEW file)
**Requirements satisfied**: HB-02.1, HB-02.2, HB-02.4, HB-02.7a, HB-02.8, HB-02.9
**Scenarios covered**: HB-02-S1, HB-02-S2, HB-02-S2c, HB-02-S2d, HB-02-S3

Create `tests/egress.bats` and write:

1. **HB-02-S1** — assert `platform/nft/osgania-egress.nft` (to be created in U2-T3) contains:
   - `table inet osgania_egress`
   - `meta skuid 9001 jump aios_egress`
   - `chain aios_egress`
   - `counter drop`
   - does NOT contain `cgroup`

2. **HB-02-S2** — assert the same file contains:
   - `ip daddr 160.79.104.0/23 tcp dport 443 accept`
   - `ip6 daddr 2607:6bc0::/48 tcp dport 443 accept`
   - `ip daddr 127.0.0.0/8 accept`
   - `ip6 daddr ::1/128 accept`

3. **HB-02-S2c** — assert `platform/systemd/osgania-agent.service` contains `After=nftables.service` and `Wants=nftables.service` (or `Requires=nftables.service`).

4. **HB-02-S2d** — assert `platform/systemd/osgania-agent.timer` contains `After=nftables.service` and `Wants=nftables.service` (or `Requires=nftables.service`).

5. **HB-02-S3** — assert the assembled `build_service_unit()` output contains `Environment=DISABLE_TELEMETRY=1` and `Environment=DISABLE_ERROR_REPORTING=1`.

**Run**: `bats tests/egress.bats` on macOS — HB-02-S1 and HB-02-S2 MUST fail (RED) because `platform/nft/osgania-egress.nft` does not yet exist. HB-02-S2c, HB-02-S2d, HB-02-S3 should pass GREEN if U1-T5 and U1-T6 are complete.

---

### U2-T2 — [TEST] Write bats scenarios for live nft behavior (LINUX-ROOT + LIVE-KEY deferred) — [Applied.]

**Tier**: LINUX-ROOT and LINUX-ROOT/LIVE-KEY (deferred to disposable VPS)
**Bats file**: `tests/egress.bats`
**Requirements satisfied**: HB-02.1, HB-02.3, HB-02.6, HB-02.9, HB-07.1, HB-07.2, HB-07.3
**Scenarios covered**: HB-02-S2b, HB-02-S4, HB-02-S5, HB-02-S6, HB-02-S7, HB-02-S8, HB-02-S9

Write the following `@test` blocks in `tests/egress.bats` with `skip "LINUX-ROOT required"` guards:

1. **HB-02-S2b** — idempotency: run Unit 2 step twice; assert exactly ONE `osgania_egress` table in `nft list ruleset`.
2. **HB-02-S4** — after Unit 2 provisioning: `nft list table inet osgania_egress` exits 0; output contains `aios_egress`, `meta skuid 9001`, `counter drop`.
3. **HB-02-S5** — uid 9001 blocked from `1.1.1.1:443`; drop counter increments.
4. **HB-02-S6** (LIVE-KEY) — uid 9001 can reach `160.79.104.10:443` (TLS handshake).
5. **HB-02-S7** (LIVE-KEY) — uid 9001 can reach `2607:6bc0::10:443` (TLS handshake, if IPv6 available).
6. **HB-02-S8** — root retains full access to `1.1.1.1:443`.
7. **HB-02-S9** (LIVE-KEY) — real `claude -p` under the wall: `terminal_reason=completed`, `is_error=false`, `apiKeySource=ANTHROPIC_API_KEY`.

These tests MUST be added with skip guards now (TDD: write them, even if they cannot run until the VPS is ready).

---

### U2-T3 — [IMPLEMENT] Create `platform/nft/osgania-egress.nft` — [Applied.]

**Tier**: HOST-SAFE (file creation on macOS)
**Requirements satisfied**: HB-02.1, HB-02.2, HB-02.4
**Files changed**: `platform/nft/osgania-egress.nft` (NEW)

**Exact content (semantically equivalent to the hardware-proven ruleset from design §2)**:

```nft
# osgania-egress.nft — per-uid 9001 egress IP-pin
# Hardware-proven 2026-06-17. DO NOT MODIFY without operator review.
# CIDRs are Anthropic's published stable inbound range. See provision-agent.sh constants.
table inet osgania_egress {
  chain out {
    type filter hook output priority 0; policy accept;
    meta skuid 9001 jump aios_egress
  }
  chain aios_egress {
    ip  daddr 127.0.0.0/8                   accept
    ip6 daddr ::1/128                       accept
    ip  daddr 160.79.104.0/23 tcp dport 443 accept
    ip6 daddr 2607:6bc0::/48  tcp dport 443 accept
    counter drop
  }
}
```

Note: The CIDR values are defined as provisioner constants in `scripts/provision-agent.sh` (`ANTHROPIC_EGRESS_V4` / `ANTHROPIC_EGRESS_V6`) and are the SINGLE authoritative source (design §2 / HB-02.2). The repo `.nft` file is a TEMPLATE containing `@@ANTHROPIC_EGRESS_V4@@` and `@@ANTHROPIC_EGRESS_V6@@` placeholder tokens — NOT literal CIDRs. `unit2_install_egress_wall()` renders the template via `sed` substitution at install time, producing a rendered file with the exact CIDR values from the constants. The rendered output, with the proven CIDRs, is byte-equivalent to the hardware-proven ruleset. To update the CIDRs, edit only the provisioner constants and re-provision; never hardcode CIDRs in the template.

**Run tests**: `bats tests/egress.bats` — HB-02-S1 and HB-02-S2 MUST now pass (GREEN).

---

### U2-T4 — [IMPLEMENT] Add Unit 2 provisioner step (nft install + idempotency + boot-load) — [Applied. HOST-SAFE: write+shellcheck only; execution deferred to VPS.]

**Tier**: LINUX-ROOT (VPS only — no macOS mutation)
**Requirements satisfied**: HB-02.1, HB-02.5, HB-02.7, HB-02.7a, HB-02.9, HB-02.10
**Files changed**: `scripts/provision-agent.sh`

Add a `unit2_install_egress_wall()` function to `scripts/provision-agent.sh` that:

1. Asserts no Docker/Coolify is installed (hard prerequisite check: `docker info` must fail or be absent).

2. Creates `/etc/osgania/nft/` if absent; copies `platform/nft/osgania-egress.nft` to `/etc/osgania/nft/osgania-egress.nft` (`root:root 0644`).

3. **Idempotent install (HB-02.9)**: before loading, run `nft delete table inet osgania_egress 2>/dev/null || true` (delete-before-recreate), then `nft -f /etc/osgania/nft/osgania-egress.nft`.

4. **Boot-load persistence (HB-02.7)**: add an `include` line to `/etc/nftables.conf` (Ubuntu 24.04's `nftables.service` config) if not already present:
   ```
   include "/etc/osgania/nft/osgania-egress.nft"
   ```
   Ensure `nftables.service` is enabled: `systemctl enable nftables.service`.

5. **Document the uid-isolation assumption (HB-02.10)**: add a comment block to the function noting that apt (`_apt`/root), NTP (`systemd-timesync`), and upstream DNS (`systemd-resolved`) are confirmed to run under separate uids; the nft wall is uid-9001-scoped and does NOT affect those services.

6. Run `shellcheck -s bash scripts/provision-agent.sh` — MUST exit 0.

7. Call `unit2_install_egress_wall` from `main()` at the appropriate step (after `write_units`, before the defense-in-depth probe).

**VPS execution**: Run via `scripts/run-live-key-tests.sh` on the disposable VPS. This task MUTATES the VPS (nft table install, nftables.conf edit, systemctl enable). Use `trap 'restore' EXIT INT TERM` pattern with `</dev/null` discipline on any `systemd-run` calls within this step.

---

### U2-T5 — [TEST + VERIFY] Run LINUX-ROOT live nft scenarios on disposable VPS

**Tier**: LINUX-ROOT (via `scripts/run-live-key-tests.sh`)
**Requirements satisfied**: HB-02.1, HB-02.3, HB-02.6, HB-02.9, HB-07.1, HB-07.3
**Scenarios**: HB-02-S2b (idempotency), HB-02-S4 (table loaded), HB-02-S5 (uid-9001 blocked), HB-02-S8 (root unaffected)

On the disposable VPS after U2-T4 has run:
1. Execute `scripts/run-live-key-tests.sh` targeting `tests/egress.bats`.
2. Confirm HB-02-S2b, HB-02-S4, HB-02-S5, HB-02-S8 all pass.
3. Record pass/fail results in a brief log comment in the PR body.

**VPS execution**: This task requires real Linux root. It does NOT require a live API key for this subset (HB-02-S5/S8 only need a network socket attempt, no actual API call). Use `PROVISION_TEST_ALLOW_MUTATION=1`; LIVE-KEY scenarios (HB-02-S6/S7/S9) run in U2-T6.

---

### U2-T6 — [TEST + VERIFY] Run LIVE-KEY scenarios on disposable VPS (Anthropic reachability + e2e)

**Tier**: LINUX-ROOT/LIVE-KEY (via `scripts/run-live-key-tests.sh`)
**Requirements satisfied**: HB-07.1, HB-07.2, HB-07.4
**Scenarios**: HB-02-S6 (Anthropic IPv4), HB-02-S7 (Anthropic IPv6), HB-02-S9 (real `claude -p` e2e)

On the disposable VPS with a real API key and after U2-T4+U2-T5 pass:
1. Execute `scripts/run-live-key-tests.sh` with `LIVE_KEY_AVAILABLE=1`.
2. Confirm HB-02-S6, HB-02-S7, HB-02-S9 pass.
3. Confirm reboot persistence (HB-07.4): reboot the box; run `nft list ruleset`; confirm `osgania_egress` table reloads.

**U2 EXIT CRITERION (hardware)**: uid 9001 reaches Anthropic v4+v6 on 443; uid 9001 to `1.1.1.1` DROPs; root unaffected; real `claude -p "Reply with ok"` returns `is_error:false`, `terminal_reason:completed`, `apiKeySource:ANTHROPIC_API_KEY`.

---

### U2-T7 — [VERIFY] shellcheck sweep + HOST-SAFE bats full pass — [Applied.]

**Tier**: HOST-SAFE
**Requirements satisfied**: HB-10.2

Before submitting PR-2:
1. `shellcheck -s bash scripts/provision-agent.sh` — exit 0.
2. `shellcheck -s bash platform/bin/agent-run.sh` — exit 0.
3. `shellcheck -s bash platform/hooks/guardia.sh` — exit 0.
4. `bats tests/` (HOST-SAFE tier, skipping LINUX-ROOT) — all HOST-SAFE tests GREEN.
5. Confirm `bats tests/egress.bats` HOST-SAFE scenarios (HB-02-S1, HB-02-S2, HB-02-S2c, HB-02-S2d, HB-02-S3) all pass.

---

## U3 — Broad autonomy

> PR-3: targets the U2 branch.
> This unit ships: guardia pass-through, reviewed allow[], dontAsk CLI flag, positive expected-set assertion, fail-closed activation gate.
> **guardia.sh pass-through MUST NOT ship in U1 or U2.** It ships ONLY here.
> Exit criterion: agent autonomously runs allowed commands; HA-09 probe still VERIFIED; wall still holds with the agent now capable; activation gate refuses allow[] if wall absent or self-check connects.

> U3 tasks run SEQUENTIALLY.

> **PREREQUISITE**: U2 EXIT CRITERION must be met (wall proven hermetic) before U3 tasks begin.

---

### [x] U3-T1 — [TEST] Write bats scenarios for guardia 2b pass-through behavior (HOST-SAFE)

**Tier**: HOST-SAFE
**Bats file**: `tests/guardia.bats`
**Requirements satisfied**: HB-04.1, HB-04.2, HB-04.3, HB-04.4, HB-04.5, Amendment A1
**Scenarios covered**: HB-04-S1, HB-04-S2, HB-04-S3, HB-04-S4, HB-04-S5, HB-04-S6, HB-04-S7, HB-04-S8

Update `tests/guardia.bats` to amend (not delete) the existing 2a R2.7 scenarios:

1. **HB-04-S1** — benign Bash `npm test`: stdout empty, exit 0, no `permissionDecision` emitted.
2. **HB-04-S2** — `ls -la /opt/osgania/client` and `git status`: both produce empty stdout, exit 0.
3. **HB-04-S3** — `sudo apt-get update`: stdout contains `permissionDecision:"deny"` and reason contains `sudo`.
4. **HB-04-S4** — `curl https://attacker.example.com/`: stdout contains `permissionDecision:"deny"`, reason contains `curl`.
5. **HB-04-S5** — `exec 3<>/dev/tcp/attacker.example.com/443`: stdout contains `permissionDecision:"deny"`, reason contains `net-builtin`.
6. **HB-04-S6** — non-Bash tool `Read`: stdout empty, exit 0.
7. **HB-04-S7** — `shellcheck -s bash platform/hooks/guardia.sh`: exit 0, no warnings.
8. **HB-04-S8** — empty STDIN and non-JSON STDIN: both produce empty stdout, exit 0.

Note: amend the EXISTING `ls`/`npm test`/`git status` test cases to assert empty stdout (pass-through). Previously they asserted `permissionDecision:"defer"`. This is the named Amendment A1; the old assertions are marked as superseded by 2b in a comment.

**Run**: `bats tests/guardia.bats` — benign pass-through tests (S1, S2, S6, S8) MUST fail (RED) because guardia still emits `defer`. DENY tests (S3, S4, S5) should remain GREEN.

---

### [x] U3-T2 — [TEST] Write bats scenarios for allow[] expected-set assertion (HOST-SAFE + fixture)

**Tier**: HOST-SAFE (fixture-based; no live VPS)
**Bats file**: `tests/provision-agent.bats`
**Requirements satisfied**: HB-03.2, HB-03.4, HB-06.3, Amendment A2
**Scenarios covered**: HB-03-S1, HB-03-S2, HB-03-S4

Write the following `@test` blocks:

1. **HB-03-S1** — create a fixture `managed-settings.json` that contains the reviewed expected-set in `permissions.allow[]` (at this phase, use a placeholder `["Bash(echo *)"]` — the real entries are produced by the U3-T6 observe+review procedure; the test SHAPE is what matters now). Assert the provisioner's `_assert_r9_r12_invariant` passes against the fixture.

2. **HB-03-S2** — create a fixture with one UNEXPECTED allow entry (an entry NOT in the expected-set). Assert `_assert_r9_r12_invariant` exits non-zero and stderr identifies the unexpected entry.

3. **HB-03-S4** — assert the fixture's `jq '.permissions.defaultMode'` returns `"default"` (dontAsk is NOT in managed-settings.json).

**Run**: `bats tests/provision-agent.bats` — HB-03-S2 MUST fail (RED) because the provisioner currently only checks `allow | length == 0`, not the expected-set membership. HB-03-S1 should fail too since allow[] is empty in the current provisioner.

---

### [x] U3-T3 — [TEST] Write bats scenarios for fail-closed gate (LINUX-ROOT deferred)

**Tier**: LINUX-ROOT (deferred to VPS)
**Bats file**: `tests/provision-agent.bats`
**Requirements satisfied**: HB-06.2a, HB-06.2b, HB-06.3, HB-06.4
**Scenarios covered**: HB-06-S1, HB-06-S2, HB-06-S2b, HB-06-S3

Write `@test` blocks with `skip "LINUX-ROOT required"` guards:

1. **HB-06-S1** — Unit 3 step aborts if nft table absent; managed-settings.json content byte-identical after run.
2. **HB-06-S2** — Unit 3 step aborts if hermetic self-check fails (wall loaded but uid-9001 connection succeeds — simulated by temporarily removing the drop rule in test harness).
3. **HB-06-S2b** — self-check exits 0 (wall absent → connect succeeds) → provisioner reads REFUSE; self-check exits 124 (wall present → timeout) → provisioner reads PROCEED. Include a `bats --timeout 10` envelope to prevent a hung connect from stalling the suite.
4. **HB-06-S3** (LIVE-KEY) — Unit 3 step proceeds when wall is present and hermetic; `permissions.allow` equals the reviewed expected-set.

---

### [x] U3-T4 — [TEST] Write LIVE-KEY scenario for autonomy behavioral contract (LINUX-ROOT/LIVE-KEY deferred)

**Tier**: LINUX-ROOT/LIVE-KEY (deferred)
**Bats file**: `tests/provision-agent.bats`
**Requirements satisfied**: HB-03.5, HB-05.1, HB-07.2
**Scenarios covered**: HB-03-S3, HB-01-S6 (survival of HA-09 probe after U3)

Write `@test` blocks with `skip "LIVE-KEY required"` guards:

1. **HB-03-S3** — non-allowlisted command auto-denies cleanly under dontAsk: `terminal_reason:completed`, `permission_denials` contains the denied command, command does NOT execute.
2. **HA-09 probe survival after U3** — run `run_defense_in_depth_probe` after U3 is active; assert `AGENT_PROBE_STATUS=VERIFIED`.

---

### [x] U3-T5 — [IMPLEMENT] Update `platform/hooks/guardia.sh` (2b: benign pass-through)

**Tier**: HOST-SAFE (file edit on macOS)
**Requirements satisfied**: HB-04.1, HB-04.2, HB-04.3, HB-04.4, HB-04.5, Amendment A1
**Files changed**: `platform/hooks/guardia.sh`

**Exact changes (design §1)**:

1. **Remove `emit_defer()` from all non-deny branches**:
   - Lines 41–45 (`emit_defer()` helper function): KEEP the function body as-is for now (it may still be referenced), but remove ALL CALLS to it outside of deny logic.

2. **Line 307, Step 8 default (R2.7 benign tail)**: Replace `emit_defer` with `exit 0`. The comment above it MUST be updated:
   ```bash
   # ---------------------------------------------------------------------------
   # Step 8 — default: pass-through (PSC R2.7-2b amendment: was defer, now exit 0)
   # Hardware gate #1 exp6 proved: defer is TERMINAL in headless -p; pass-through
   # lets the normal flow (deny[] → ask → allow[]) decide. Unit 3 only (2b).
   # ---------------------------------------------------------------------------
   exit 0
   ```

3. **Early-return branches** (non-Bash tool at Step 0, empty/invalid STDIN at Step 1): Change any `emit_defer` calls to `exit 0` (empty stdout). Comment each with the gate-#1 rationale.

4. **Remove the `emit_defer()` function body** if no deny path calls it (after removing all non-deny callers). If needed, remove the dead function to avoid shellcheck warnings.

5. Run `shellcheck -s bash platform/hooks/guardia.sh` — MUST exit 0 with no warnings.

**Run tests**: `bats tests/guardia.bats` — all HB-04-S1 through HB-04-S8 MUST now pass (GREEN). DENY scenarios (S3, S4, S5) MUST still pass.

---

### U3-T6 — [IMPLEMENT] Derive `allow[]` via the §4 observe+review procedure (apply-time, VPS)

**Tier**: LINUX-ROOT/LIVE-KEY (manual + automated procedure, VPS)
**Requirements satisfied**: HB-03.1, HB-03.3
**Output**: The reviewed allow[] entries (these are an OUTPUT of this task, not pre-specified)

**Procedure (design §4, mandatory — DO NOT INVENT ENTRIES)**:

1. **Pre-conditions**: STEP 0 is complete; egress wall is loaded and hermetic (U2 exit criterion met); guardia pass-through is installed (U3-T5 complete); `permissions.allow` is still `[]`; `--permission-mode dontAsk` is in the wrapper (U1-T3 complete).

2. **Run representative tasks**: Start `osgania-agent.service` with a prompt that exercises the expected real workload (build, test, git operations). Use the actual `platform/prompts/agent-prompt.txt` or a representative override. Collect the stream-json output.

3. **Collect `permission_denials`**: From the stream-json events, extract every `Bash` command that auto-DENIED for lack of an allow entry. These are the CANDIDATE entries.

4. **Assemble candidate set**: Format as Claude Code `permissions.allow[]` entry strings (e.g., `"Bash(npm test)"`, `"Bash(git status)"`, `"Bash(python3 *)"`) — narrowed to the specific command forms actually needed, NOT `Bash(*)`.

5. **Human review gate (mandatory)**: The operator reviews each candidate entry and explicitly approves or rejects it. This is the gate where a person confirms each entry is intended. No entry may be added without explicit approval.

6. **Record the reviewed set**: Document the approved entries in a comment block in `scripts/provision-agent.sh` as `AGENT_EXPECTED_ALLOW` (the constant used by the positive expected-set assertion in U3-T7). Also record them in a brief log in the apply-progress artifact.

**Output constraint**: The allowed entries MUST come from observed denials, not invented. If the workload produces no denials, the reviewed set is `[]` and U3 adds no allow entries.

---

### [x] U3-T7 — [IMPLEMENT] Update `provision-agent.sh`: replace allow==[] with positive expected-set assertion; add fail-closed gate

**Tier**: LINUX-ROOT for gate (VPS) + HOST-SAFE for the assertion logic
**Requirements satisfied**: HB-03.2, HB-06.1, HB-06.2a, HB-06.2b, HB-06.3, HB-06.4, Amendment A2, Amendment A3
**Files changed**: `scripts/provision-agent.sh`

**Changes**:

1. **Add `AGENT_EXPECTED_ALLOW` constant** (near the top constants block, after `AGENT_WRAPPER_INSTALLED`):
   ```bash
   # AGENT_EXPECTED_ALLOW — the reviewed broad allowlist (design §4 observe+review output).
   # Exact entries are recorded by U3-T6. DO NOT invent entries; update only after human review.
   AGENT_EXPECTED_ALLOW='[ ... reviewed entries from U3-T6 ... ]'  # sorted JSON array
   ```

2. **Replace lines 452–459** (`allow | length == 0` check) with the positive expected-set assertion (design §6):
   ```bash
   # Check permissions.allow == AGENT_EXPECTED_ALLOW exactly (positive expected-set; Amendment A2)
   local live_allow expected_allow
   live_allow="$(jq -cS '.permissions.allow' "$f" 2>/dev/null)"
   expected_allow="$(printf '%s' "$AGENT_EXPECTED_ALLOW" | jq -cS '.')"
   if [[ "$live_allow" != "$expected_allow" ]]; then
       printf 'provision-agent.sh: INVARIANT FAILED: permissions.allow=%s, expected exactly %s\n' \
           "$live_allow" "$expected_allow" >&2
       return 1
   fi
   ```

3. **Add `unit3_fail_closed_gate()` function** implementing the full fail-closed activation gate (design §5, THREE conditions):
   - Check (a): `nft list table inet osgania_egress` exits 0 AND output contains `aios_egress` AND the `aios_egress` chain body contains `counter drop`. If absent → REFUSE with named error.
   - Check (b): Root positive-control connect (uid 0, no `systemd-run`). Attempt TCP connect to canary (`1.1.1.1:443`) as root. MUST succeed (exit 0). If the canary is unreachable from root, the canary is unsuitable → REFUSE. (Closes the canary fail-open: an upstream filter independently blocking the canary would produce the same uid-9001 timeout as a real wall.)
   - Check (c): uid-9001 hermetic self-check BLOCKED. Run via the full `systemd-run` invocation. PRIMARY form is `python3` (design §5 — immune to kernel `tcp_syn_retries` tuning; bash `/dev/tcp` is a fallback only):
     ```bash
     systemd-run --uid=9001 --gid=9001 --pipe --quiet --collect \
       --unit=osgania-egress-selfcheck \
       --property=RestrictAddressFamilies='AF_INET AF_INET6' \
       --property=Environment='' \
       python3 -c "import socket,sys
     s=socket.socket(); s.settimeout(5)
     try: s.connect(('1.1.1.1',443)); sys.exit(0)
     except TimeoutError: sys.exit(124)
     except OSError: sys.exit(1)" </dev/null || selfcheck_exit=$?
     ```
     `except TimeoutError` MUST precede `except OSError` (TimeoutError is a subclass of OSError).
     With `trap 'restore' EXIT INT TERM` backstop; `restore()` hardcodes the unit name.
   - Exit-code semantics for check (c):
     - Exit 0 = connected = wall ABSENT → REFUSE (do not write allow[]).
     - Exit 124 = timeout = wall PRESENT → PROCEED. This is the ONLY proceed signal.
     - Any other exit (1, ECONNREFUSED, etc.) → REFUSE (fail-closed).
   - All THREE must pass; any failure → `return 1` with named failure message; do NOT write allow[].
   - MUST include `</dev/null` on the `systemd-run` call.
   - MUST NOT include `ANTHROPIC_API_KEY` in the transient environment.

4. **Add a `unit3_write_allow()` function** that writes the reviewed `AGENT_EXPECTED_ALLOW` to `managed-settings.json` using `jq` and atomic `mv` (same pattern as 2a uses for other writes).

5. **Wire the gate in `main()`**: call `unit3_fail_closed_gate` before `unit3_write_allow`. If the gate fails, the provisioner aborts. Order: gate → write → `_assert_r9_r12_invariant` verify.

6. Run `shellcheck -s bash scripts/provision-agent.sh` — MUST exit 0.

**Run HOST-SAFE tests**: `bats tests/provision-agent.bats` — HB-03-S1, HB-03-S2, HB-03-S4 MUST now pass (GREEN).

---

### U3-T8 — [TEST + VERIFY] Run LINUX-ROOT fail-closed gate scenarios on disposable VPS

**Tier**: LINUX-ROOT (via `scripts/run-live-key-tests.sh`)
**Requirements satisfied**: HB-06.2a, HB-06.2b, HB-06.3, HB-06.4
**Scenarios**: HB-06-S1 (nft absent), HB-06-S2 (self-check connects), HB-06-S2b (exit-code semantics)

On the disposable VPS:
1. Temporarily flush the nft table; run Unit 3 step; assert it aborts with named error, managed-settings.json byte-identical.
2. Restore the nft table; temporarily remove the drop rule; run Unit 3 step; assert it aborts with named error.
3. Run HB-06-S2b: with wall absent, confirm self-check exits 0 (connects); with wall present, confirm exit 124 (timeout within 10s).
4. Record results in apply-progress.

---

### U3-T9 — [TEST + VERIFY] Run LIVE-KEY autonomy + probe-survival scenarios on disposable VPS

**Tier**: LINUX-ROOT/LIVE-KEY (via `scripts/run-live-key-tests.sh`)
**Requirements satisfied**: HB-03.5, HB-05.1, HB-06.2, HB-07.2
**Scenarios**: HB-06-S3, HB-03-S3, HA-09 probe survival after U3

On the disposable VPS with the full U3 posture active (wall hermetic, allow[] written, guardia pass-through, dontAsk CLI flag):

1. **HB-06-S3**: run Unit 3 step end-to-end; assert `permissions.allow` equals the reviewed expected-set; assert gate logged "PROCEED".
2. **HB-03-S3**: send a prompt that requests a command NOT in allow[]; assert `terminal_reason:completed`, denial logged, command not executed.
3. **HA-09 probe survival**: run `run_defense_in_depth_probe` (from `provision-agent.sh`) after U3; assert `AGENT_PROBE_STATUS=VERIFIED` (bypass oracle still holds).
4. **Wall still holds**: confirm `HB-02-S5` (uid 9001 blocked from `1.1.1.1:443`) still passes.

**U3 EXIT CRITERION**: All four points above pass. PR-3 is ready to merge to U2 branch. Tracker PR can then merge to main.

---

## Review Workload Forecast

| Unit | Estimated changed lines | Budget status |
|------|------------------------|---------------|
| WU0 — Contract finalization | ~60 lines (doc edits only) | Within budget |
| U1 — STEP 0 | ~135 lines (agent-run.sh +30, provision-agent.sh +65 [+15 for probe refactor U1-T7], service/timer units +20, bats +20) | Within budget |
| U2 — nft egress wall | ~150 lines (osgania-egress.nft +20, provision-agent.sh +70, egress.bats +60) | Within budget |
| U3 — Broad autonomy | ~180 lines (guardia.sh +5net, provision-agent.sh +80, provision-agent.bats +60, guardia.bats +35) | Within budget |
| **Total across all units** | **~525 lines** | Over single-PR budget |

**Chained PRs recommended: Yes**
**Chain strategy: `feature-branch-chain`**
- Tracker branch: `feature/vps-provisioning-hardening-2b` (draft, no-merge until all children merge in order)
- PR-1 (U1 STEP 0) → targets tracker branch
- PR-2 (U2 egress wall) → targets U1 branch
- PR-3 (U3 broad autonomy) → targets U2 branch
- Only tracker merges to main

**Size:exception needed per unit: No** — each unit is under 400 lines individually.

**Decision needed before apply: No** — the chain strategy is already cached (`feature-branch-chain`) and the delivery strategy is already set. The Review Workload Forecast confirms: proceed with chained PRs as planned, no `size:exception` required for any single unit.

**Delivery-ordering invariant (explicit):**
U2 proven hermetic on hardware (HB-07.1/HB-07.2 pass) is a hard prerequisite for PR-3 to be reviewed or merged. This is enforced at both layers: PR ordering (PR-3 targets U2 branch) and the fail-closed provisioner gate (unit3_fail_closed_gate refuses allow[] unless the wall is loaded and the uid-9001 self-check exits 124). A capable allowlist landing on a box without a proven wall is the worst-case failure mode; the double enforcement makes it impossible by process AND by code.

---

## Requirements-to-tasks map

| Requirement | Task(s) |
|-------------|---------|
| HB-01.1 | U1-T1 (test HB-01-S1 via LINUX-ROOT — see HB-01-S1 in spec) |
| HB-01.3, HB-03.4 | U1-T1 (HB-01-S2), U1-T3 |
| HB-01.4 | U1-T1 (HB-01-S4), U1-T4 |
| HB-01.3, HB-01.6 | U1-T1 (HB-01-S5), U1-T3 |
| HB-01.5 | U1 exit criterion / LIVE-KEY VPS |
| HB-01.7 | U1-T3 (preserved auth block) |
| HB-01.8 | U1-T1 (HB-01-S2b), U1-T3 |
| HB-02.1 | U2-T1 (HB-02-S1, HB-02-S2c), U2-T3, U2-T4 |
| HB-02.2, HB-02.4 | U2-T1 (HB-02-S2), U2-T3 |
| HB-02.5 | U2-T4 |
| HB-02.6, HB-07.3 | U2-T2 (HB-02-S8), U2-T5 |
| HB-02.7a | U1-T5, U1-T6, U2-T1 (HB-02-S2c/S2d) |
| HB-02.7 (reboot persistence) | U2-T4, U2-T6 |
| HB-02.8 | U1-T5, U2-T1 (HB-02-S3) |
| HB-02.9 | U2-T1 (HB-02-S2b), U2-T4 |
| HB-02.10 | U2-T4 (documented assumption) |
| HB-03.1 | U3-T6 |
| HB-03.2, Amendment A2 | U3-T2 (HB-03-S1), U3-T7 |
| HB-03.3 | U3-T6 |
| HB-03.4, PSC R9.8 | U3-T2 (HB-03-S4) |
| HB-03.5 | U3-T4 (HB-03-S3), U3-T9 |
| HB-04.1, Amendment A1 | U3-T1 (HB-04-S1), U3-T5 |
| HB-04.2 | U3-T1 (HB-04-S3/S4/S5), U3-T5 |
| HB-04.3 | U3-T1 (HB-04-S6), U3-T5 |
| HB-04.4, HB-10.2 | U3-T1 (HB-04-S7), U3-T5 |
| HB-04.5 | U3-T1 (HB-04-S8), U3-T5 |
| HB-05.1 | U1-T7 (direct probe invocation — HOST-SAFE source assertion), U3-T4, U3-T9 |
| HB-05.2 | U1-T2 (HB-05-S1 — updated 4-part source assertions), U1-T7 |
| HB-05.4 | U1-T2 (HB-05-S1 assertion 4), U1-T7 |
| HB-06.1 | U3-T7 (ordering enforced by gate) |
| HB-06.2a | U3-T3 (HB-06-S1), U3-T7, U3-T8 |
| HB-06.2b | WU0-T1/T2/T5 (contract fixes), U3-T3 (HB-06-S2/S2b), U3-T7, U3-T8 |
| HB-06.3 | U3-T3, U3-T7, U3-T8 |
| HB-06.4 | U3-T3 (HB-06-S3), U3-T9 |
| HB-06.5 | Delivery process (PR ordering invariant, no bats scenario) |
| HB-07.1 | U2-T2 (HB-02-S5/S6/S7), U2-T5/T6 |
| HB-07.2 | U2-T2 (HB-02-S9), U2-T6 |
| HB-07.4 | U2-T6 (reboot check) |
| HB-09.x | Documented in rollback section; no additional tasks |
| HB-10.1 | WU0-T4 (manifest update); all U1/U2/U3 implementation tasks (file creation) |
| HB-10.2 | U2-T7 (shellcheck sweep), all shellcheck steps in each task |

---

## Parallel vs sequential decision

All units are STRICTLY SEQUENTIAL:
- WU0 → U1 → U2 → U3 (ordering is the security property)
- Within each unit, tasks are sequential (each task's output is the next task's input)
- No parallel lanes — the fail-closed gate enforces runtime sequencing; the chained-PR structure enforces PR sequencing

**Within each unit, task order**:
- Always: TEST (write bats) → IMPLEMENT (write code, make tests GREEN) → VERIFY (run on VPS if LINUX-ROOT)
- HOST-SAFE tests are written and run on macOS; they MUST be RED before the implementation task and GREEN after.
- LINUX-ROOT/LIVE-KEY tests are written on macOS (with skip guards), run on the VPS after the implementation is merged to the unit branch.
