# Design: vps-provisioning-hardening-2b — Autonomy + Egress

**Change id**: `vps-provisioning-hardening-2b`
**Project**: osgania
**Artifact store**: openspec + engram
**Date**: 2026-06-17
**Reads**: `proposal.md` (APPROVED, R2+R3 hardware-proven). Derived ONLY from the proven content — the **"Linchpin verified on hardware"** and **"Egress simplified + PROVEN on hardware"** sections plus **ADR-1, ADR-3, ADR-4, ADR-6**. The Squid material (ADR-2, §3(B) Layer (ii), Unit 2b, the ADR-5 80/123/Squid-uid enumeration, gates #9/#15) is SUPERSEDED and is the source of NOTHING here.

---

## The decision in one paragraph

2b restores agent autonomy and builds the real exfil wall, delivered in **three chained units whose ORDER is itself the security property**: (1) STEP 0 restores the run path and wires a root-owned prompt file; (2) a hardware-proven nftables per-uid IP-pin egress wall to Anthropic's published range; (3) the broad allowlist + `dontAsk`-as-CLI-flag, gated by a fail-closed machine check that refuses to activate the allowlist unless the egress wall is loaded and a live hermetic self-check is BLOCKED. The broad allowlist demotes guardia from an exfil control to an anti-accident control; exfil containment now rests entirely on the nft egress wall plus single-tenancy. **No Squid, no transparent redirect, no second uid, no TLS-terminating proxy, no port 80/123 in the agent's egress.**

## Quick path (the review map)

| Unit | What ships | Hardware exit criterion | ~Review budget |
|------|-----------|-------------------------|----------------|
| **U1 — STEP 0** | Re-provision `agent-run.sh`, create `/opt/osgania/client`, root-owned prompt file, prompt-in-wrapper, telemetry-disable env | `systemctl start` runs `claude -p` against policy + produces an audit record; box alive; gate-#11 reconciled. Egress still open, allowlist NOT enabled. Safety of egress-open during U1 comes from the CURRENT guardia `defer` behavior (nothing executes while guardia defers benign Bash — the defer-terminal gate #1 result is the PROTECTION here). Gate #2 (dontAsk + pass-through stub) proved U3 is safe once the wall is up and the allowlist is active; it does not describe U1 safety. | ~120 lines |
| **U2 — Egress wall** | `table inet osgania_egress` (the PROVEN ruleset), root-installed in host netns, persisted + boot-loaded; refreshable CIDR constant; Docker-free assertion | From uid 9001 only 443→Anthropic-range + loopback leave; everything else DROP; root unaffected; `claude -p` works end-to-end under the wall; DNS + `RestrictAddressFamilies` coexist. Allowlist NOT enabled. | ~150 lines |
| **U3 — Broad autonomy** | guardia benign `defer`→pass-through; reviewed `allow[]`; `dontAsk` CLI flag; positive expected-set assertion; fail-closed activation gate; R9.8/R9.9 + HA-05.x amendments | Agent autonomously runs allowed commands; HA-09 probe still VERIFIED; wall still holds with the agent now capable; activation gate refuses to write `allow[]` if the wall is absent or the self-check connects. | ~180 lines |

**Chain strategy recommended: `feature-branch-chain`** (only the tracker merges to main → rollback control, which the ordering invariant requires). Confirmed by the user at apply time.

---

## Component map and data flow

```
                         HOST netns (root-managed, aios cannot touch)
  ┌───────────────────────────────────────────────────────────────────────┐
  │  nft: table inet osgania_egress                                         │
  │    chain out  (hook output, policy accept)                              │
  │       meta skuid 9001 jump aios_egress                                  │
  │    chain aios_egress                                                    │
  │       loopback accept · 160.79.104.0/23:443 accept ·                    │
  │       2607:6bc0::/48:443 accept · counter drop          ◄── THE WALL    │
  └───────────────────────────────────────────────────────────────────────┘
        ▲ uid 9001 packets filtered here                ▲ root/_apt/timesync/resolved = other uids, unfiltered
        │                                                
  ┌─────┴───────────────────────────────────────────────────────────────────┐
  │  osgania-agent.service  (User=aios uid 9001, Type=oneshot)               │
  │    ExecStart=/opt/osgania/platform/bin/agent-run.sh -p   (BYTE-IDENTICAL)│
  │    LoadCredential → wrapper exports ANTHROPIC_API_KEY                    │
  │    Environment+=DISABLE_TELEMETRY=1, DISABLE_ERROR_REPORTING=1           │
  │       │                                                                  │
  │       ▼  agent-run.sh                                                    │
  │    reads ROOT-OWNED prompt file (read-only to aios, outside RW subtree)  │
  │    exec claude --permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" \│
  │      --setting-sources "" -p "$(cat "$PROMPT_FILE")"  (Amendments A4+A5)  │
  │       │                                                                  │
  │       ▼  claude -p   (managed-settings.json + hooks active)             │
  │    Layer-1 deny[] (6 entries)  →  Layer-2 guardia (DENY-ONLY, benign     │
  │    branch now PASS-THROUGH)     →  permissions.allow[] auto-executes     │
  │                                    reviewed set; dontAsk auto-denies     │
  │                                    the unmatched tail cleanly            │
  └─────────────────────────────────────────────────────────────────────────┘
```

Permission precedence (Claude Code, unchanged): **deny → ask → allow, first-match-wins**. The 6 `deny[]` entries and guardia's DENY verdicts remain the absolute ceiling; `allow[]` is evaluated after deny and can never re-open an inherited deny.

---

## 1 — guardia pass-through mechanics (the gate-#1 fix)

**The mechanism proven on hardware (gate #1, exp1/2/3 vs exp6).** While guardia emits `permissionDecision:"defer"` for a benign Bash call, that defer is TERMINAL in headless `-p` and PRE-EMPTS settings `allow[]` — even under `dontAsk`. The allow rule only fires when guardia emits NOTHING (exit 0, no JSON decision) — exp6 EXECUTED. So the single load-bearing change is: guardia's benign tail stops emitting `defer` and instead falls through to a plain `exit 0`.

**Exact code delta in `platform/hooks/guardia.sh`** (real structure read on disk):

- Lines 41–45, `emit_defer()` helper: REMOVED from all non-deny branches. Hardware gate #1 proved that `permissionDecision:"defer"` is TERMINAL in headless `-p` and pre-empts the permission flow — including for non-Bash tools and malformed-input early-returns. Keeping `emit_defer` for these branches would block allowlisted non-Bash tools and break Amendment A1's uniformity. All non-deny branches now use pass-through (exit 0, empty stdout).
- Line 307, the Step-8 default `emit_defer` (the R2.7 benign tail): CHANGED to pass-through. After all DENY checks (Steps 2–7.5) have NOT matched, guardia emits NO decision and exits 0. Concretely: replace the terminal `emit_defer` call with a bare `exit 0` (emit nothing on STDOUT), guarded by a comment pointing at PSC R2.7-2b and gate #1/exp6.
- The early-return branches (non-Bash tool, empty/invalid STDIN, missing command): CHANGED to pass-through (exit 0, empty stdout). Previously these emitted `defer`; that was safe historically, but gate #1 proved `defer` is terminal — it would block allowlisted non-Bash tools (Read, Write, etc.) just as it blocked benign Bash. Pass-through lets the normal flow (deny[] → ask → allow[]) decide; gate #2 proved that under `dontAsk`, non-allowlisted tools auto-DENY cleanly, so pass-through is safe.
- Everything above line 303 (Steps 0–7.5: sudo, curl/wget, `rm -rf`, disk-wipe, secrets path, platform path, env-dump, `/dev/tcp`,`/dev/udp`) is BYTE-UNCHANGED. guardia still emits `deny` + exit 0 for every dangerous command; R1.4 holds (guardia never emits `allow`); R1.5 holds (always exits 0).

**guardia now has exactly ONE non-deny outcome: pass-through (exit 0, empty stdout).** It emits `deny` or it emits nothing. It never emits `allow`, `ask`, or `defer`.

**bats delta (named, not silent).** The existing R2.7 scenarios (GD-19 `ls -la`, GD-20 `npm test`, GD-21 `git status`) are amended to assert **NO PreToolUse decision is emitted** (empty STDOUT, exit 0) for benign Bash. The early-return cases (non-Bash tool, empty STDIN, malformed JSON — GD-24/GD-25) are also amended to assert pass-through (empty STDOUT, exit 0) — NOT defer, because defer is terminal. This is a flagged PSC R2.7 amendment owned by 2b (live-artifact pattern), not a rewrite of the archived `platform-security-core` text.

**Why A4 is NOT chosen.** A4 (guardia emits `permissionDecision:"allow"`) is viable on hardware (exp5 executed) but would amend R1.4 ("guardia never emits allow") and make guardia the allowlist enforcer — strictly more load-bearing for no benefit. Pass-through restores autonomy while preserving R1.4. Rejected.

**Accepted residual — VECTOR 2 (sub-claude self-escalation via client workspace code):**
A malicious Makefile/package.json/conftest.py in `/opt/osgania/client/` (run as aios via an allowlisted `make`/`npm test`/`pytest`) can write its own `~/.claude/settings.json` or `/opt/osgania/client/.claude/settings.json` with `allow:[Bash(*)]` and spawn `/usr/bin/claude` directly without `--setting-sources ""`, granting the sub-claude broad Bash. This is an **accepted residual** because: (a) it requires malicious code in the client workspace — the same surface the operator already accepts by allowlisting `make`/`pytest` to run arbitrary code; the sub-claude adds no new execution capability that the workspace code cannot already achieve directly; (b) the containment layers are identical — the nft wall blocks all non-Anthropic exfiltration regardless of how many claude processes run, `NoNewPrivileges=yes` + empty `CapabilityBoundingSet=` block privilege escalation, `ProtectSystem=strict` blocks writes to `/etc/`, `/usr/`, `/opt/osgania/platform/`, and `CAP_NET_ADMIN` is absent so the wall cannot be taken down. The `--setting-sources ""` flag in the PARENT wrapper (Amendment A5) closes the parent-claude path; this is the inherent arbitrary-code surface of the approved workspace model, not a new hole. Named: VECTOR 2 (see spec.md Tradeoffs and accepted residuals table).

---

## 2 — The nft egress wall (D1, PROVEN)

### The ruleset (reproduced verbatim from proposal §"Egress simplified" / memory #243)

```nft
table inet osgania_egress {
  chain out {
    type filter hook output priority 0; policy accept;
    meta skuid 9001 jump aios_egress
  }
  chain aios_egress {
    ip  daddr 127.0.0.0/8       accept
    ip6 daddr ::1/128           accept
    ip  daddr 160.79.104.0/23   tcp dport 443 accept
    ip6 daddr 2607:6bc0::/48    tcp dport 443 accept
    counter drop
  }
}
```

Properties proven on hardware (2026-06-17, trap-protected): uid 9001 reaches Anthropic v4+v6 on 443; uid 9001 to 1.1.1.1 / GitHub / Cloudflare-v6 / Datadog all DROP; root unaffected (policy accept, uid-scoped jump); real `claude -p "Reply with ok"` completes end-to-end (`apiKeySource:ANTHROPIC_API_KEY`, `result:"ok"`, `is_error:false`).

### Why this shape (decisions)

| Decision | Resolution |
|----------|-----------|
| Family | `table inet` (single table covers IPv4 + IPv6 in lockstep — gate #8). v6 is NOT an open bypass: Anthropic v6 `2607:6bc0::/48` is explicitly allowed, everything else v6 hits `counter drop`. |
| Scope | `meta skuid 9001` — `aios` is a dedicated uid with no other processes (gate #6: no cgroup-timing problem on `Type=oneshot`; skuid is stable from the first connect). apt (`_apt`/root), NTP (`systemd-timesync`), upstream DNS (`systemd-resolved`) are OTHER uids → the floor needs NO `:80`, NO `:123`, NO arbitrary-resolver `:53`. **ACCEPTED ASSUMPTION**: this UID isolation relies on apt/NTP/DNS services staying on their own service UIDs (not 9001). If any of these services were reconfigured to run as uid 9001, the wall would also block them — operator action required. Hardware gates #12/#13/#14 confirmed the assumption holds on the target box. |
| Default action | `counter drop` (not reject) — silent drop, with a counter for observability. The chain `policy accept` is irrelevant to uid 9001 because the jump's last rule drops; `policy accept` only governs other uids (root SSH/ops never locked out). |
| DNS coexistence | The agent's resolver is the local stub `127.0.0.53` (systemd-resolved), reached via loopback `accept`. Upstream DNS leaves the box from `systemd-resolved`'s uid, not 9001 — outside this chain. Proven: agent resolved + authed under the wall (gate #7). `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` in the unit is UNTOUCHED — the firewall lives in the host netns, not in the unit's address-family set, so there is no `EAFNOSUPPORT`/SC-3 regression. |

### Install / persist / boot-load

- **Owner**: root, in the host network namespace. The zero-cap, no-sudo `aios` (`CapabilityBoundingSet=` empty, not in sudo) cannot flush, edit, or add to the table.
- **Source of truth**: `platform/nft/osgania-egress.nft` (canonical repo path, consistent with spec HB-10.1 and scenario HB-02-S1/S2), installed by the provisioner to `/etc/osgania/nft/osgania-egress.nft` (`0644 root:root`).
- **Boot-load**: load it via the system nftables service. The provisioner `include`s the osgania ruleset from the persistent nft config (Ubuntu 24.04 `/etc/nftables.conf` is loaded by `nftables.service` on boot) so the wall survives reboot AND re-provision. The provisioner applies it immediately (`nft -f`) during the run AND ensures `nftables.service` is enabled, so there is no boot-window gap.
- **Boot ordering (HB-02.7a)**: `osgania-agent.service` (and `osgania-agent.timer`) MUST declare `After=nftables.service` and `Wants=nftables.service` so the wall is loaded before the agent can run on every boot. The provisioner Unit 2 step writes this ordering into the unit file.
- **Idempotency (HB-02.9)**: the ruleset begins by deleting any prior `table inet osgania_egress` before recreating it (delete-before-recreate) so re-provision is repeatable and never stacks duplicate chains. Running Unit 2 twice yields exactly one `osgania_egress` table.
- **Coexistence with DOCKER chains (gate #10)**: the box is Docker/Coolify-free; the provisioner asserts this (a future Docker install would insert DOCKER chains ahead of this table and must be reconciled — flagged as a hard prerequisite, OUT of 2b scope to solve).

### Refreshable CIDR constant (the only Anthropic-range coupling)

The two CIDRs `160.79.104.0/23` and `2607:6bc0::/48` are Anthropic's published, stable inbound range ("will not change without notice"). They MUST be a SINGLE-SOURCE provisioner constant (e.g. `ANTHROPIC_EGRESS_V4="160.79.104.0/23"`, `ANTHROPIC_EGRESS_V6="2607:6bc0::/48"` near the top of `provision-agent.sh` with the other decided literals at lines 23–34), templated into the `.nft` file at install time. **Tradeoff**: if Anthropic changes the range, the agent breaks until an operator edits these two constants and re-provisions. Mitigated by the published stability commitment; the cost of a range change is a one-value edit, not a redesign.

---

## 3 — The wrapper (`agent-run.sh`) changes (ADR-6 / P1)

Current wrapper (read on disk) ends at line 17: `exec /usr/bin/claude "$@"`, after exporting `ANTHROPIC_API_KEY` from `$CREDENTIALS_DIRECTORY`. 2b changes the exec line and adds telemetry-disable; the auth/export block (lines 8–16) is UNTOUCHED.

| Change | Resolution |
|--------|-----------|
| **Prompt source (P1)** | The wrapper reads an operator-controlled prompt file via `PROMPT_FILE` (canonical double-quoted variable) and execs the agent using the canonical form below. The prompt is supplied INSIDE the wrapper, so the unit's `ExecStart=… agent-run.sh -p` stays BYTE-IDENTICAL. |
| **Prompt-file canonical path** | Repo: `platform/prompts/agent-prompt.txt`. Installed: `/opt/osgania/platform/prompts/agent-prompt.txt`. Owner: `root:root`. Mode: `0644` (world-readable — aios CAN read, CANNOT write). Consistent with the real `platform/` → `/opt/osgania/platform/` mapping in `provision-agent.sh`. The `0640 root:aios` alternative is DROPPED — `0644` is simpler and sufficient since aios reading the prompt is expected and harmless; write-denial is the security property. The path is under `platform/`, which is already `Edit/Write`-denied (deny[] entries 5–6) AND guardia-denied (Step 7 R2.6) AND not in the unit's `ReadWritePaths`. |
| **`--permission-mode dontAsk` as a CLI flag** | Applied BEFORE `-p` in the canonical exec line, NOT set as the managed `defaultMode` field. Proven on hardware: dontAsk engages under managed `disableBypassPermissionsMode:disable` (it is NOT bypass) and gives clean auto-DENY for the unmatched tail. Because it is a CLI flag, managed `defaultMode` stays `"default"` → the HA-09 probe oracle survives. |
| **Telemetry disable** | Set at the unit level via `Environment=DISABLE_TELEMETRY=1` and `Environment=DISABLE_ERROR_REPORTING=1` (the unit already carries `Environment=` lines 13–18; add two). Belt-and-suspenders: the wall blocks Datadog regardless, but the agent shouldn't attempt the egress. |
| **Preserved** | LoadCredential→`ANTHROPIC_API_KEY` export (lines 8–16); `set -euo pipefail`; `exec` (single process, no extra subshell); the `--bare` ban (A7 rejected). |

**Canonical exec line (SINGLE FORM — no variants; Amendments A4+A5):**
```bash
AGENT_SETTINGS_FILE="/opt/osgania/platform/agent-settings.json"
PROMPT_FILE="/opt/osgania/platform/prompts/agent-prompt.txt"
exec /usr/bin/claude --permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p "$(cat "$PROMPT_FILE")"
```
Flag order: `--permission-mode dontAsk` → `--settings "$AGENT_SETTINGS_FILE"` → `--setting-sources ""` → `-p`. `--setting-sources ""` excludes agent-writable sources (user/project/local) so the agent cannot self-escalate by writing its own settings.json (additive allow[] hole — Amendment A5). `PROMPT_FILE` MUST be double-quoted everywhere. The canonical claude invocation is built entirely inside the wrapper — `"$@"` is NOT forwarded to the claude invocation (only the HB-01.8 `-p` guard checks it). ExecStart string in the unit is unchanged.

**IMPORTANT — the 2b wrapper is a PRODUCTION LAUNCHER, not a transparent pass-through.** Unlike the 2a wrapper (`exec /usr/bin/claude "$@"`), the 2b wrapper hardcodes the entire claude invocation: `--permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p "$(cat "$PROMPT_FILE")"`. It intentionally ignores `"$@"` beyond the HB-01.8 `-p` guard. Any additional arguments passed by the caller (e.g. `--output-format stream-json`, `--verbose`, `--dangerously-skip-permissions`) are SILENTLY DISCARDED. This is correct for production runs (the unit always passes only `-p`) but means the wrapper MUST NOT be used by verification paths that need different claude arguments.

**HA-09 probe — MUST invoke `/usr/bin/claude` DIRECTLY, not through the production wrapper (JD-6 resolution).** The HA-09 defense-in-depth probe must call `/usr/bin/claude -p --output-format stream-json --verbose --dangerously-skip-permissions '<prompt>'` directly. If it called the 2b production wrapper instead:
- The probe's `--output-format stream-json --verbose --dangerously-skip-permissions` would be DISCARDED → no stream-json `init` event → `permissionMode` field empty → oracle unreadable → **HB-05.1 BROKEN**.
- `--permission-mode dontAsk` would be INJECTED by the wrapper into the probe path → **HB-05.2 VIOLATED**.

The probe tests the managed-settings layer (`disableBypassPermissionsMode:"disable"` neutralizing `--dangerously-skip-permissions`), which is entirely independent of the wrapper. The probe MUST export `ANTHROPIC_API_KEY` itself from `AGENT_SECRETS_KEY` (`/etc/osgania/secrets/anthropic-api-key`), the provisioner's persistent on-disk key path, using the same `tr -d '[:space:]'` strip pattern as the wrapper — `CREDENTIALS_DIRECTORY` is a systemd LoadCredential variable set only at service runtime; the provisioner runs outside systemd, so the probe reads the persistent on-disk path instead — and then invoke `/usr/bin/claude` directly. The probe MUST NOT include `--permission-mode dontAsk`. Cross-ref HB-05.2 and HB-05.4.

**Wrapper guard (HB-01.8):** Before the exec, the wrapper MUST verify `-p` is present in `"$@"` as a **standalone positional argument** — iterate over `"$@"` (e.g. `for arg in "$@"; do [[ "$arg" == "-p" ]] && found=1; done`), NOT a `$*` substring match. A substring match would falsely trigger on a value argument containing the characters `-p`. If the standalone `-p` is absent, exit non-zero with a clear error and do NOT exec claude.

---

## 4 — How the exact `allow[]` is DERIVED (the METHOD, not the values)

The design DOES NOT enumerate the allow entries. It specifies the apply-time procedure and the assertion shape; the entries are produced by observation + human review during Unit 3.

**Derivation procedure (apply-time, runs only AFTER STEP 0 and AFTER the egress wall is proven):**

1. With the box in the proven posture (guardia pass-through, `allow:[]`, `dontAsk` CLI flag, egress wall LOADED), run a set of REAL representative `claude -p` tasks (build, test, git status/diff, the actual workload prompts the operator intends).
2. Capture, from the stream-json `permission_denials` events, every Bash command the agent attempts that auto-DENIED for lack of an allow entry. (Gate #2 proved interpreters/`cat`/writes auto-DENY cleanly; only `echo`-class read-only auto-runs — so the agent WILL surface the build/test/git commands it needs as denials.)
3. Assemble the candidate BROAD allowlist (D2: build/test/git, including interpreters node/python and git) from those OBSERVED commands — narrowed to the specific command forms actually needed, not `Bash(*)`.
4. **Human review** the candidate set before it is written. This is the gate where a person confirms each entry is intended.
5. Encode the reviewed set as (a) the literal `permissions.allow[]` in `managed-settings.json` and (b) the provisioner's positive expected-set constant (see §6).

The design's contract to tasks: the allow entries are an OUTPUT of step 4, recorded in the tasks/apply artifacts, NOT invented here. The spec asserts the SHAPE (positive expected-set) and the security properties (deny-first precedence still ceilings it; no `Bash(*)`; the reviewed set is exactly what the provisioner asserts).

---

## 5 — The fail-closed Unit-3 activation gate (ADR-3, non-negotiable)

The broad allowlist makes the agent a capable, scriptable principal. Enabling it while the wall is unproven = capable agent + leaky wall = worst case. So allowlist activation is a **fail-closed precondition**, enforced in `provision-agent.sh` BEFORE it writes a non-empty `allow[]`.

**The gate (machine check, same host, before writing `allow[]`):**

1. **(a) Wall loaded.** Assert `nft list table inet osgania_egress` succeeds AND the `aios_egress` chain contains the expected drop + the two Anthropic-range accepts (structural check, not just table existence). If absent → REFUSE.
2. **(b) Root positive-control connect SUCCEEDS (closes the canary fail-open).** As uid 0 (the provisioner itself, no `systemd-run`), attempt a TCP connect to the canary (`1.1.1.1:443`). This MUST SUCCEED (exit 0). This proves the canary is reachable on this network so a uid-9001 block is attributable to the wall, not the network. If this FAILS (canary unreachable even from root): the network independently blocks the canary → the canary is unsuitable → REFUSE and report the canary as unusable. Without this control, an upstream filter blocking `1.1.1.1:443` produces the same uid-9001 timeout as a real wall → false PROCEED → fail-open.
3. **(c) Live hermetic self-check BLOCKED.** As uid 9001 (via `systemd-run`), attempt a TCP connect to the SAME canary. It MUST be BLOCKED (times out, exit 124). If it CONNECTS (exit 0) → the wall is not actually containing uid 9001 → REFUSE.
4. Only if ALL THREE pass does the provisioner write the reviewed non-empty `allow[]`. Otherwise it aborts non-zero with a named failure and leaves `allow:[]` (fail closed — a re-provision, a Unit-2 rollback, or an out-of-order operator run cannot land a capable allowlist on a box whose wall is absent or flushed).

**Canary address (HB-06.2b).** The canary MUST be a routable, non-loopback address OUTSIDE the Anthropic ranges (`160.79.104.0/23`, `2607:6bc0::/48`) and OUTSIDE loopback (`127.0.0.0/8`, `::1/128`). Default canary: `1.1.1.1:443`. A canary inside the Anthropic range would always refuse (the wall allows those destinations); a loopback canary would always falsely pass (loopback is accepted by the wall).

**Running the self-check SAFELY as uid 9001 (gate-#2 box-safety lesson).** The self-check runs via a `systemd-run` transient from the root provisioner — it does NOT pass through guardia's hook, so a real connect tool is appropriate. Use `</dev/null`, a short timeout, and a `trap 'restore' EXIT INT TERM` backstop. The transient MUST run with a clean, minimal environment and MUST NOT receive `ANTHROPIC_API_KEY` (it only needs a TCP connect; no credentials are required or appropriate).

Mandated command form — `python3` is PREFERRED (see kernel-timeout caveat below). Use `python3` or `/bin/bash` explicitly (NOT `/bin/sh`, which is dash on Ubuntu 24.04 and does NOT support `/dev/tcp`):

**Primary form (python3 — preferred):**
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

**Fallback form (bash `/dev/tcp` — see kernel-timeout caveat):**
```bash
systemd-run --uid=9001 --gid=9001 --pipe --quiet --collect \
  --unit=osgania-egress-selfcheck \
  --property=RestrictAddressFamilies='AF_INET AF_INET6' \
  --property=Environment='' \
  /bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"' </dev/null
```

**Normative ordering requirement (python3 form):** The `except TimeoutError` clause MUST appear BEFORE `except OSError`. `TimeoutError` is a subclass of `OSError`; reversing the order would catch a timeout as `OSError` → exit 1 (REFUSE) instead of exit 124 (PROCEED), silently locking the gate to REFUSE forever.

**`TimeoutError` vs `socket.timeout`:** Active forms use `except TimeoutError` (non-deprecated name, Python ≥3.3). `socket.timeout` is a deprecated alias (Python 3.11+) on Ubuntu 24.04's Python 3.12 and risks a future `NameError`. Do NOT use `socket.timeout` in active code. (Historical RESOLVED notes quoting the old `socket.timeout` form are left as-is.)

**Bash-form kernel-timeout caveat:** The bash form's "exit 124 = timeout = PROCEED" contract assumes `net.ipv4.tcp_syn_retries` is at its default (≥6, ~127s) so the user-space 5s `timeout` fires before the kernel abandons the SYN. On a host with `tcp_syn_retries` tuned down, the kernel may abandon first → bash `timeout` sees the child exit non-124 → REFUSE (fail-closed, but a working wall would be wrongly refused). The python3 form is immune (pure user-space `settimeout(5)`, independent of kernel retransmit tuning). This is why python3 is the preferred/primary form.

**`restore()` canonical form:** The `systemd-run` invocation MUST use `--unit=osgania-egress-selfcheck` so the trap can deterministically stop an orphaned transient. The provisioner MUST set the trap before launching the transient:
```bash
restore() { systemctl stop osgania-egress-selfcheck.service 2>/dev/null || true; }
trap 'restore' EXIT INT TERM
```
A no-op `restore` does NOT satisfy this requirement.

**Root positive-control connect (before launching the uid-9001 `systemd-run`):** As uid 0 (no `systemd-run`), attempt the same TCP connect to the canary. Use the same python3 or bash form without `--uid`. If this fails (canary unreachable from root), REFUSE and report the canary as unusable.

**Exit-code semantics (uid-9001 self-check — fail-closed, unambiguous):**
- A **SUCCESSFUL** connection (bash exit 0 / python3 `connect` raises no exception → exit 0) means WALL ABSENT or MISCONFIGURED → **REFUSE** to write allow[]. Do NOT proceed.
- A **BLOCKED** result — the nft `drop` causes a TIMEOUT (bash `timeout` exits **124** / python3 catches `TimeoutError` → exits **124**) — means WALL PRESENT → **PROCEED**. This is the ONLY outcome that unlocks allow[] writing. Exit 124 and exit 124 alone.
- **ANY other/ambiguous outcome** (ECONNREFUSED → non-zero (typically exit 1) → REFUSE for bash; exit 1 for python3 via `sys.exit(1)`; non-124 non-0 bash exit; any non-0 non-124 python3 exit) → **REFUSE** (fail-closed). Note: for the bash `/dev/tcp` form, exit codes for a failed redirection are implementation-defined; only the python3 form guarantees exit 1 via explicit `sys.exit(1)`. The security behavior is unchanged — anything ≠ 124 = REFUSE. The provisioner MUST write allow[] ONLY when exit code is EXACTLY 124 AND the nft table is already confirmed loaded AND the root positive-control connect succeeded; every other outcome refuses.

For the bash form: the transient's exit code IS the connect result — `timeout` exits 124 on timeout; the inner `bash -c "exec 3<>/dev/tcp/..."` exits 0 on a successful connect. The outer `/bin/bash -c '...'` wrapper passes that exit code through unchanged. There is NO `; echo $?` suffix — adding `; echo $?` would always exit 0 (echo succeeds) and destroy the exit-code signal.

For the python3 form: exit 0 = `connect` succeeded (connected) = REFUSE; exit 124 = `TimeoutError` caught = wall PRESENT = PROCEED; exit 1 = `OSError` (including ECONNREFUSED) = REFUSE. The provisioner proceeds ONLY on exit 124.

**Provisioner gate logic (explicit — THREE conditions):** Write `allow[]` ONLY IF ALL THREE hold: (a) the nft table `inet osgania_egress` is loaded; (b) root positive-control connect SUCCEEDS (exit 0 — canary reachable from uid 0); (c) the uid-9001 self-check exits EXACTLY 124. Exit 0 on uid-9001 → REFUSE. Any non-124 non-0 on uid-9001 → REFUSE. Root positive-control failure → REFUSE. Exit 124 on uid-9001 is the single PROCEED signal; everything else is fail-closed REFUSE.

The nft rule uses `drop` (not `reject`) so the expected proceed-signal when the wall is present is a TIMEOUT — the `timeout 5` / `settimeout(5)` ensures the check does not hang indefinitely.

**Why `/bin/sh` is prohibited here:** `/bin/sh` on Ubuntu 24.04 is dash; dash does NOT implement `/dev/tcp`. A dash invocation of `/dev/tcp` always errors with "No such file or directory" — the connect never actually attempts, and the non-zero exit would be misread as "wall is blocking" on a box with NO wall (fail-OPEN). Always use `/bin/bash` explicitly or `python3`.

> Note: this self-check is run by the PROVISIONER as a uid-9001 transient to TEST the wall — it is NOT an agent command and is entirely unrelated to guardia's `/dev/tcp` agent denylist (which guards the agent from making outbound connections via bash builtins).

---

## 6 — The positive expected-set assertion (ADR-4)

Replaces the Slice-1 `allow == []` gate AND the 2a HA-05.x `allow == []` assertions — strengthened, never deleted.

**Current code (read on disk), `provision-agent.sh::_assert_r9_r12_invariant`:**
- Lines 452–459: asserts `permissions.allow | length == 0`. → REPLACED.
- Lines 461–468: asserts `permissions.defaultMode == "default"`. → KEPT verbatim (dontAsk is a CLI flag, so the managed field stays `"default"`; R9.8 / HA-09 oracle preserved).
- The 6 `deny[]` entries (lines 426–450), `disableBypassPermissionsMode` (470–477), `allowManagedHooksOnly` (479–486), hook structure (488–557), no-extra-top-level-keys (559–566): ALL KEPT verbatim.

**New assertion (replaces 452–459):** define a reviewed expected-set constant (the §4 output), then assert `allow[]` equals EXACTLY that set — same length AND same membership, in any order — and REJECT any unexpected entry. Shape:

```bash
# AGENT_EXPECTED_ALLOW — the reviewed broad allowlist (D2). Source of truth.
# (Exact entries are an OUTPUT of the §4 observe+review procedure, recorded in tasks.)
AGENT_EXPECTED_ALLOW='[ ... reviewed entries ... ]'   # sorted JSON array

# assertion: live allow[] must equal the expected set exactly (fail closed on drift)
live_allow="$(jq -cS '.permissions.allow' "$f")"
expected_allow="$(printf '%s' "$AGENT_EXPECTED_ALLOW" | jq -cS '.')"
if [[ "$live_allow" != "$expected_allow" ]]; then
    printf 'provision-agent.sh: INVARIANT FAILED: permissions.allow=%s, expected exactly %s\n' \
        "$live_allow" "$expected_allow" >&2
    return 1
fi
```

Properties: fails CLOSED on ANY entry not in the reviewed set (so an injected/extra allow rule aborts the provisioner); it is a TIGHTENING of the old `== []` check, not a loosening. The explore's retired "no forbidden glob" bats guard is replaced by this positive set + the egress wall.

**2a HA-05.x amendment (named, live-artifact pattern).** HA-05.3 ("managed-settings.json byte-identical / 2a never writes it"), HA-05.6 ("R9–R12 structurally unchanged"), and scenario HA-05-S3 (`.permissions.allow == []`) are SUPERSEDED for 2b: `managed-settings.json` now legitimately carries the reviewed `allow[]`, and the `allow == []` structural assert is replaced by the positive expected-set assertion above. Mirrors exactly how 2a extended the live `guardia.sh` (HA-15) without rewriting the archived `platform-security-core` text. Every OTHER R9–R12 key stays asserted unchanged.

---

## 7 — Delivery topology

Three chained units, ordered so the wall exists and is PROVEN before the door opens. Order is enforced in TWO places: (1) the chained-PR sequence, and (2) the fail-closed activation gate (§5) so the invariant lives in the ARTIFACT, not just human process.

```
U1 STEP 0  ──►  U2 nft egress wall (PROVEN)  ──►  U3 broad autonomy
restore run    root-installed IP-pin,            allow[] + dontAsk-CLI +
path + prompt  persisted + boot-loaded           amendments, behind the
(egress open,  (allowlist NOT enabled)           fail-closed activation gate
allowlist                                         (refuses unless U2 wall
NOT enabled)                                       loaded + hermetic-self-check
                                                   BLOCKED on same host)
```

| Unit | Hardware exit criterion | Maps to |
|------|-------------------------|---------|
| U1 | `systemctl start osgania-agent.service` runs `claude -p` against the policy and produces an audit record; box alive + instrumentable; gate-#11 reconciled (why was the wrapper missing). Egress open is SAFE here because guardia's CURRENT `defer` behavior means nothing executes during U1 (the defer-terminal property from gate #1 is the protection; the allowlist is not yet active). Gate #2 (dontAsk + pass-through posture) is the proof of U3 safety, not U1 safety. **guardia.sh stays the 2a defer-emitting version through U1 — pass-through MUST NOT ship in U1.** | ADR-6, gate #1, gate #11 |
| U2 | From uid 9001 only 443→Anthropic-range + loopback leave; all else DROP; root unaffected; DNS + `RestrictAddressFamilies` coexist; v6 not an open bypass; `claude -p` works end-to-end under the wall; box Docker-free. **guardia.sh stays the 2a defer-emitting version through U2 — the defer-terminal property remains the egress-open safety net until the wall is proven hermetic and U3 activates.** | D1, gates #4–#8/#10, memory #243 |
| U3 | Agent autonomously executes allowed commands; HA-09 probe reads VERIFIED; wall still holds with the agent capable; activation gate refuses `allow[]` if wall absent or self-check connects. **guardia.sh pass-through ships ONLY in U3, alongside the reviewed allow[].** | ADR-1, ADR-3, ADR-4, gate #1 |

**Review budget**: each unit is targeted under ~400 lines (U1 ~120, U2 ~150, U3 ~180). The egress collapse from two units (nft + Squid) to one PROVEN unit is what keeps U2 inside budget. **Chain strategy: `feature-branch-chain`** — PR #1 targets the tracker branch, U2 targets U1's branch, U3 targets U2's branch; only the tracker merges to main. This gives rollback control: a flawed U3 cannot reach main without the wall units, and the wall can be reverted as a unit if a hardware exit criterion regresses.

---

## 8 — Security model re-statement (ADR-3, honest)

**The broad allowlist DEMOTES guardia (Layer-2) from an exfil control to an anti-accident control.** ADR-7 already admits any interpreter reads its own environment and opens sockets. With interpreters (node/python) and git in the allowlist, guardia's env-dump and `/dev/tcp` rules stop being meaningful EXFIL controls — a one-liner sidesteps them. guardia remains valuable against ACCIDENTAL destructive actions (rm -rf, disk-wipe, sudo, secrets/platform paths) and as a denylist ceiling, but it is no longer the exfil boundary.

**Exfil containment now rests ENTIRELY on:**
- **D1 — the nft egress wall.** The only thing that makes a non-Anthropic destination genuinely unreachable from uid 9001.
- **ADR-6 — single-tenancy.** One untrusted principal per box; the residual is bounded by the no-self-exfil property of the one channel that must stay open.

This is EXACTLY why the delivery order is a security property and why the activation gate is fail-closed: the containment layer that replaces the interpreter-ban (the wall) must be present and proven before the allowlist that relies on it.

**Residual after IP-pin (ADR-5 as it now stands — COMPLETE list):**
1. **Exfil over the legitimate `api.anthropic.com:443` channel** — IRREDUCIBLE. No filter that must allow `api.anthropic.com` can stop data leaving through it. Bounded only by single-tenancy.
2. **Low-bandwidth DNS tunnel via the local stub** — bounded (~108-byte key fits in crafted subdomain queries to `127.0.0.53`; upstream resolution is done by `systemd-resolved`, a different uid). Bounded-but-nonzero given the deliberate choice to keep a resolver path.

**Holes that are now CLOSED (vs the superseded Squid design and vs the pre-2b open box):**
- The **HTTPS-to-any-host** hole is CLOSED (443 from uid 9001 only reaches Anthropic's range).
- The **apt-`:80`** and **NTP-`:123`** residuals are GONE (those uids are not 9001; the floor opens neither port).
- The **ECH / domain-fronting** weakness is GONE (no SNI dependency — IP-pinning to a dedicated published range; an attacker cannot own an IP in Anthropic's range).

---

## Checklist (what the spec/tasks phases must encode)

- [ ] guardia: ALL non-deny branches (benign Bash, non-Bash tools, malformed/empty-STDIN early-returns) → pass-through (exit 0, no STDOUT). `emit_defer` REMOVED from all non-deny branches. R2.7-2b amendment; DENY logic + R1.4 + R1.5 unchanged.
- [ ] bats: benign Bash (GD-19/20/21) asserts NO PreToolUse decision; non-Bash/malformed (GD-24/25) ALSO now assert pass-through (NOT defer) — because defer is terminal (gate #1).
- [ ] `table inet osgania_egress` shipped as `platform/nft/osgania-egress.nft` (canonical repo path), installed to `/etc/osgania/nft/osgania-egress.nft`, root-installed, persisted via nftables.service drop-in, boot-loaded with `After=nftables.service` in the agent unit, idempotent (delete-before-recreate); CIDRs from a single refreshable provisioner constant.
- [ ] Wrapper: canonical path `PROMPT_FILE="/opt/osgania/platform/prompts/agent-prompt.txt"` (repo: `platform/prompts/agent-prompt.txt`); canonical exec line `exec /usr/bin/claude --permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p "$(cat "$PROMPT_FILE")"` with `AGENT_SETTINGS_FILE="/opt/osgania/platform/agent-settings.json"`; flag order: dontAsk → --settings → --setting-sources → -p; `--setting-sources ""` excludes agent-writable sources (Amendment A5, HB-03.7); wrapper guard detects `-p` as a STANDALONE positional argument by iterating `"$@"` (NOT a `$*` substring match) and exits non-zero if absent; ExecStart byte-identical; `--bare` banned; auth/export block unchanged. Prompt file: `root:root 0644`.
- [ ] HA-09 probe: MUST NOT receive `--permission-mode dontAsk` (cross-ref HB-05.2) — probe uses only `--dangerously-skip-permissions`.
- [ ] Units: add `DISABLE_TELEMETRY=1` + `DISABLE_ERROR_REPORTING=1` to `osgania-agent.service`; BOTH `osgania-agent.service` AND `osgania-agent.timer` MUST each carry `After=nftables.service` + `Wants=nftables.service` (cross-ref HB-02.7a — omitting either unit is a specification violation); `RestrictAddressFamilies` untouched; `OnCalendar=daily` placeholder kept.
- [ ] `allow[]` DERIVED by the §4 observe+review procedure (entries are an apply-time output, NOT specified here).
- [ ] `provision-agent.sh`: replace lines 452–459 `allow==[]` with the positive expected-set assertion; keep 461–468 `defaultMode=="default"`; keep all other R9–R12 asserts.
- [ ] Fail-closed activation gate (THREE conditions): (a) assert wall loaded (structural); (b) root uid-0 positive-control connect to canary SUCCEEDS — proves canary reachable on network, not just uid-blocked (closes canary fail-open); (c) live uid-9001 hermetic self-check BLOCKED using the **preferred python3 form** (try/except: `TimeoutError` → exit 124, `OSError` → exit 1; `except TimeoutError` MUST precede `except OSError`) or the **bash fallback** `/bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/<canary>/443"'` with kernel-timeout caveat (see §5); NOT `/bin/sh`; NOT bare `timeout`; NOT `socket.create_connection`; NOT `connect_ex` one-liner; NOT `socket.timeout` (deprecated). Canary outside Anthropic ranges and loopback. `systemd-run` transient with FULL flag set `--uid=9001 --gid=9001 --pipe --quiet --collect --unit=osgania-egress-selfcheck --property=RestrictAddressFamilies='AF_INET AF_INET6' --property=Environment=''` and clean env (no ANTHROPIC_API_KEY), `</dev/null`, trap-protected (`restore() { systemctl stop osgania-egress-selfcheck.service 2>/dev/null || true; }` — no-op restore not sufficient). Root positive-control failure → REFUSE + canary unusable report. exit-0 on uid-9001 = wall absent = REFUSE; exit-124 on uid-9001 = wall present = PROCEED; any other exit on uid-9001 = REFUSE. Exit 124 on uid-9001 is the ONLY proceed signal (requires root positive-control + nft table ALSO passing).
- [ ] Named amendments: PSC R2.7 (guardia — all non-deny branches now pass-through, not just benign Bash tail), Slice-1 R9.8/R9.9, 2a HA-05.3/HA-05.6/HA-05-S3 — all flagged as 2b-owned (live-artifact pattern), not silent.
- [ ] Delivery: 3 units, feature-branch-chain, each with its hardware exit criterion; ordering invariant + fail-closed gate carried into the spec.

## Deferred review findings (Judgment Day Round 3) — ALL RESOLVED

> This design + the spec passed two adversarial review rounds (regressions and contradictions fixed). A third round surfaced a cluster of precision/completeness items. All JD-1…JD-6 findings and the minors are now RESOLVED in the contracts (spec.md + design.md + tasks.md). No outstanding deferred findings remain.
>
> **JD-1 — RESOLVED.** python3 self-check updated to try/except form: `socket.timeout` → exit 124, `OSError` → exit 1. §5 python3 block updated. Provisioner gate logic stated explicitly (exit 124 is the single PROCEED signal).
>
> **JD-2 — RESOLVED.** HB-06-S2b scenario updated to assert exit 124 specifically on the PROCEED branch; non-124 non-0 = REFUSE clarified.
>
> **JD-3 — RESOLVED.** This Checklist's fail-closed bullet updated to the canonical `/bin/bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/<canary>/443"'` form and the try/except python3 form. `socket.create_connection` and bare `timeout` removed.
>
> **JD-4 — RESOLVED.** HB-10.1 manifest completed with `platform/systemd/osgania-agent.service` and `osgania-agent.timer`; `guardia.sh` entry annotated "(Unit 3 ONLY — MUST NOT ship in U1/U2 PRs)".
>
> **JD-5 — RESOLVED.** §5 `systemd-run` invocation was already the authoritative full form here; spec HB-06.2b now includes the full flag set (`--uid=9001 --gid=9001 --pipe --quiet --collect --property=Environment=''`) and a reference to §5 as canonical.
>
> **JD-6 — RESOLVED in contracts (§3 above).** The 2b wrapper is a production launcher that hardcodes the claude invocation and discards `"$@"` (except the HB-01.8 `-p` guard). The HA-09 probe cannot go through this wrapper because: (a) the wrapper would discard the probe's `--output-format stream-json --verbose --dangerously-skip-permissions` args → no stream-json `init` event → HB-05.1 broken; (b) `--permission-mode dontAsk` would be injected into the probe path → HB-05.2 violated. Resolution: the probe invokes `/usr/bin/claude` directly, exports `ANTHROPIC_API_KEY` inline from `AGENT_SECRETS_KEY` (`/etc/osgania/secrets/anthropic-api-key` — `CREDENTIALS_DIRECTORY` is a systemd LoadCredential var unavailable outside service runtime; the provisioner uses the persistent on-disk path), and MUST NOT include `--permission-mode dontAsk`. See §3 above and spec HB-05.2/HB-05.4/HB-05-S1. Implementation task: tasks U1-T7.
>
> **Minors — RESOLVED.** HB-01.5 "produces an audit record" clarified (camara logs init/result events even without Bash tool execution); HB-02.7a tightened (BOTH service AND timer required); `restore` trap behavior defined (kill/stop orphaned uid-9001 transient); HB-02.10 row added to requirements-to-scenario map; HB-06-S2b bats run-timeout note added.

---

## WU0-T7 polish applied

Final precision fixes applied after JD Round 3 resolution:

| Fix | What changed |
|-----|-------------|
| RestrictAddressFamilies checklist | Checklist fail-closed-gate bullet now enumerates full `systemd-run` flag set: `--uid=9001 --gid=9001 --pipe --quiet --collect --unit=osgania-egress-selfcheck --property=RestrictAddressFamilies='AF_INET AF_INET6' --property=Environment=''` |
| Canary positive-control (fail-open closed) | §5 gate expanded to THREE conditions: (a) nft table loaded, (b) root uid-0 positive-control connect SUCCEEDS, (c) uid-9001 self-check BLOCKED (exit 124). Root-connect failure → REFUSE + canary unusable report. |
| `TimeoutError` + ordering | Active python3 forms updated from `except socket.timeout` to `except TimeoutError`; normative ordering note added (`except TimeoutError` MUST precede `except OSError`). Historical RESOLVED notes left as-is. |
| `tcp_syn_retries` / python3 preferred | Bash-form kernel-timeout caveat documented in §5; python3 declared PREFERRED/primary; bash form is an acceptable fallback with caveat. |
| `restore()` canonical form | `--unit=osgania-egress-selfcheck` mandated on `systemd-run`; `restore()` given concrete form `restore() { systemctl stop osgania-egress-selfcheck.service 2>/dev/null \|\| true; }`; no-op restore explicitly not sufficient. |
| Service AND timer | Checklist boot-ordering bullet now explicitly requires BOTH `osgania-agent.service` AND `osgania-agent.timer` carry `After=nftables.service` + `Wants=nftables.service`. |
| ECONNREFUSED wording | Bash form: "ECONNREFUSED → non-zero (typically exit 1) → REFUSE" (exit codes implementation-defined); python3 form: "exit 1 via `sys.exit(1)`" (guaranteed). Security behavior unchanged. |

---

## Amendment A4 — allow[] location: /opt/osgania/platform/agent-settings.json via --settings (Approach B)

Applied after hardware-proven finding (2026-06-19). Supersedes §6's managed-settings write approach for U3.

**Two hardware-proven findings that drove the change:**

1. **Claude Code 2.1.153 does NOT honor `permissions.allow[]` from the enterprise managed-settings file.** Only `deny`, `disableBypassPermissionsMode`, and `hooks` are read from that file when passed via `CLAUDE_CODE_ENTERPRISE_MANAGED_SETTINGS_FILE`. `allow` must come from user settings, project settings, or a `--settings`-flag file. Writing allow to managed-settings had ZERO effect on the agent.

2. **First fix (user settings + chattr +i on the file) had a dir-swap self-escalation hole.** The `.claude` directory and its parent `/var/lib/osgania-agent` are `aios`-owned. The agent can `mv ~/.claude ~/.claude.bak && mkdir ~/.claude` — the rename operates on the parent directory entry (not the immutable file inode), so `chattr +i` on the settings file does not block the swap. A malicious build script (running under the allow[]) could replace the settings with an expanded allow. `chattr +i` on the `.claude` directory would block the swap but breaks Claude Code (can't write its cache).

**Approach B solution (hardware-confirmed on VPS, 2026-06-19):**

- Write the reviewed allow to `/opt/osgania/platform/agent-settings.json` (root:root 0644).
- Load it via the wrapper's `--settings` flag plus `--setting-sources ""` (Amendment A5): `exec /usr/bin/claude --permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p "$(cat "$PROMPT_FILE")"`.
- `platform/` is the **operator layer**: root-owned, the agent does not own it or its parent `/opt/osgania`. The managed `deny[]` already blocks `Edit(/opt/osgania/platform/**)` and `Write(/opt/osgania/platform/**)`. Hardware: aios can READ the file, cannot WRITE or swap it.
- No `chattr` needed.

**Amendment A5 — self-escalation via additive allow[] (hardware-proven, same session):**

Claude Code merges `permissions.allow[]` ADDITIVELY across sources. The agent-writable sources — user settings (`/var/lib/osgania-agent/.claude/settings.json`), project settings (`/opt/osgania/client/.claude/settings.json`), local `.claude.json` — each independently extend the effective allow[]. A planted `Bash(cargo build)` in the user settings was honored on hardware even with the platform `--settings` file containing only the reviewed entries. `--setting-sources ""` passed to the wrapper excludes all three agent-writable sources; `--settings` (platform file) and managed-settings still load. Hardware result: make PERMITTED (from platform file), cargo build DENIED (user source excluded). See spec HB-03.7.

**Scope of change (what §4/§6/Checklist items change):**

| Element | Before A4/A5 | After A4/A5 |
|---------|-----------|---------|
| `unit3_write_allow()` target | `managed-settings.json` | `/opt/osgania/platform/agent-settings.json` |
| Ownership | root:aios + chattr +i on file | root:root 0644, no chattr |
| Assertion | `_assert_r9_r12_invariant(..., AGENT_EXPECTED_ALLOW)` | `_assert_agent_allow_settings()` (new) + `_assert_r9_r12_invariant()` with allow==[] |
| Managed allow | Written to AGENT_EXPECTED_ALLOW | Stays [] always |
| Wrapper exec line | `--permission-mode dontAsk -p ...` | `--permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p ...` |
| `_assert_wrapper_invariant` | Checks for exec line without `--settings` | Checks AGENT_SETTINGS_FILE assignment + `--settings` + `--setting-sources` in non-comment exec line |
| `_assert_r9_r12_invariant` second arg | Used as expected allow | Silently ignored; always checks managed allow==[] |
| Self-escalation via agent-writable settings | OPEN (additive allow[]) | CLOSED (`--setting-sources ""` excludes user/project/local) |

**Checklist delta (amends the Checklist section above):**

- Wrapper canonical exec line: `exec /usr/bin/claude --permission-mode dontAsk --settings "$AGENT_SETTINGS_FILE" --setting-sources "" -p "$(cat "$PROMPT_FILE")"` with `AGENT_SETTINGS_FILE="/opt/osgania/platform/agent-settings.json"`. Order: dontAsk → --settings → --setting-sources → -p.
- `_assert_wrapper_invariant` now checks: (1) AGENT_SETTINGS_FILE assignment to platform path (any line); (2) non-comment exec line contains `--permission-mode dontAsk --settings`; (3) non-comment exec line contains `--setting-sources`; (4) PROMPT_FILE referenced. Comment-line exclusion uses `grep -v '^[[:space:]]*#'` so a tampered wrapper that puts the correct string only in a comment cannot pass.
- `allow[]` WRITE target: `$AGENT_ALLOW_SETTINGS` = `/opt/osgania/platform/agent-settings.json`, owner root:root 0644, built via `jq -n --argjson allow ... '{permissions: {allow: $allow}}'` + `install -o root -g root -m 0644`. No managed-settings write.
- New `_assert_agent_allow_settings()`: (a) file exists; (b) jq-equality against `AGENT_EXPECTED_ALLOW`; (c) owner root:root via `stat -c '%U:%G'` (graceful skip on macOS). HOST-SAFE testable against a fixture.
- `_assert_r9_r12_invariant`: ignore second arg; always assert managed `permissions.allow == []`.
- New bats HB-01-S3: HOST-SAFE mutation coverage for `_assert_wrapper_invariant` — three tampered fixture cases (missing `--setting-sources`, missing `--settings`/AGENT_SETTINGS_FILE, exec only in comment) each return non-zero; correct fixture returns 0.

## Next step

Contracts are final. Proceed to `sdd-apply` with U1 → U2 → U3 implementation tasks. WU0 contract-finalization tasks (WU0-T1…WU0-T6) are marked Applied in tasks.md. Tasks must NOT invent `allow[]` entries — they carry the §4 derivation procedure and the assertion shape.
