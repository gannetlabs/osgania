# Spec: onboarding-intake-contract (P0 — Intake Contract + Offline Validator)

**Change**: `onboarding-intake-contract`
**Capability**: client onboarding — product slice P0 ("the input contract")
**Project**: osgania
**Artifact store**: openspec
**Established**: 2026-06-25
**Status**: spec
**Depends on**: `vps-provisioning-hardening-2b` (ARCHIVED — the proven platform foundation)
**Implements**: proposal.md

> P0 defines and validates the operator-authored `intake.yaml` input file. It adds **zero** system state to any VPS: no root, no filesystem mutation, no egress wall, no managed policy, no launch path, and the agent never reads `intake.yaml`. All artifacts are repo-only. This spec describes WHAT must be true; HOW is for `sdd-design`.

---

## Scope summary

P0 ships two artifacts and nothing else:

1. A versioned `intake.yaml` contract — the single source of truth for what a well-formed per-client onboarding input looks like.
2. An offline validator — a host-safe, read-only tool the operator runs before onboarding to obtain a VALID (exit 0) or INVALID (non-zero + reason) verdict.

Everything else (the generator, the apps, OD-001 runtime, secret delivery, MCP wiring) is out of scope and MUST NOT appear in this change.

---

## ADDED Requirements

### IC-01 — Four-part contract structure

The `intake.yaml` contract MUST model exactly four parts, each with defined validity rules:

| Part | What it carries | Validity rule (contract level) |
|------|-----------------|-------------------------------|
| Typed business core | Structured, machine-meaningful fields about the client | Required fields MUST be present and non-empty; values MUST match their declared types |
| Free-form context corpus | An opaque markdown blob authored by the operator | MUST be present and non-empty well-formed text; MUST NOT be parsed for meaning |
| App selection | A selection over the menu: `db`, `automation`, `landing`, `inbox` | Each selected value MUST be a member of that fixed menu; empty/none selection MUST be valid |
| Secret references | Pointers to secrets by key, resolving to `/etc/osgania/secrets/<key>` | Each entry MUST be a reference (a key pointer); an inlined literal value is a REJECTION (see IC-03) |

**IC-01.1** The contract MUST carry an explicit version declaration. The validator MUST reject any `intake.yaml` that omits the version field, or whose declared version is unknown to the validator, with a non-zero exit code and a reason identifying the missing/unknown version.

**IC-01.2** The four-part structure is forward-compatible: the contract MUST accept an `intake.yaml` that carries no app selection (empty or absent) as valid, because apps are built in later slices and the first client MAY run brain-only.

**IC-01.3** The contract MUST NOT contain any `allow[]`, permissions, capability-grant, or authority-delegation field. This is a categorical non-goal. The validator MUST reject any `intake.yaml` that contains such a field (see IC-04).

**Isolation boundary (IC-01):** The contract is a schema document in the repo. It is operator-held and operator-authored input data. The agent MUST NOT read `intake.yaml` directly; `intake.yaml` MUST NOT be stored under `/opt/osgania/client/` (the agent-readable workspace). The P1 generator will read it as root from an operator-controlled path and render derived, non-secret documents into `client/` — but the raw `intake.yaml` itself MUST NOT reside there.

---

#### Scenario IC-01-S1: complete intake is valid

- GIVEN an `intake.yaml` fixture that provides all required typed business core fields with correct types, a non-empty markdown corpus, at least one valid app-selection value from the menu, and all secrets represented as references
- WHEN the validator is run against the fixture
- THEN exit code is 0
- AND the validator writes nothing to the filesystem

#### Scenario IC-01-S2: missing required core field is invalid

- GIVEN an `intake.yaml` fixture that omits a required typed business core field
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output identifies the missing field by name

#### Scenario IC-01-S3: app-selection value outside the menu is invalid

- GIVEN an `intake.yaml` fixture whose app-selection contains a value not in `{db, automation, landing, inbox}` (e.g. `crm`)
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output identifies the invalid app-selection value

#### Scenario IC-01-S4: missing or empty corpus is invalid

- GIVEN an `intake.yaml` fixture whose free-form context corpus is absent or empty
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output identifies the corpus as missing or empty

#### Scenario IC-01-S5: missing version declaration is invalid

- GIVEN an `intake.yaml` fixture that omits the version field
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output identifies the missing version field

---

### IC-02 — Validator verdicts and determinism

**IC-02.1** The validator MUST implement exactly two verdicts:

| Verdict | Exit code | Writes anything | Reason output |
|---------|-----------|-----------------|---------------|
| VALID | 0 | Nothing | None required |
| INVALID | Non-zero (>0) | Nothing | MUST produce a clear, field- or line-oriented reason |

**IC-02.2** The validator MUST be deterministic: the same `intake.yaml` input MUST always produce the same verdict (VALID or INVALID) across repeated invocations. There MUST be no randomness, timestamp sensitivity, or external-state dependency in the verdict.

**IC-02.3** The validator MUST be read-only: it MUST NOT write to the filesystem, create or modify any file, touch any system state, or make network calls. It reads the input file and exits.

**IC-02.4** The validator MUST NOT require root. It MUST run as an unprivileged operator account on the host machine (macOS or Linux).

**IC-02.5** The INVALID verdict MUST identify the problem at the field or line level — the reason MUST be specific enough for the operator to locate and fix the offending entry without reading the validator source code.

**Isolation boundary (IC-02):** The validator is a host-safe, operator-side tool. It has no VPS surface: no root, no egress wall, no managed policy, no systemd, no agent. It is the sole gatekeeper before the (root-run) generator receives its input. Its determinism guarantee enables re-validation after any edit without special procedures.

---

#### Scenario IC-02-S1: valid intake exits 0 and writes nothing

- GIVEN a well-formed `intake.yaml` fixture satisfying all contract rules
- WHEN the validator is run against the fixture
- THEN exit code is 0
- AND no file on the filesystem is created, modified, or deleted

#### Scenario IC-02-S2: invalid intake exits non-zero with a field-level reason

- GIVEN an `intake.yaml` fixture with exactly one validity violation (e.g. a missing required field)
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output contains a reason that names the offending field or line

#### Scenario IC-02-S3: same input produces same verdict on repeated runs

- GIVEN any `intake.yaml` fixture (valid or invalid)
- WHEN the validator is run twice consecutively against the same fixture without any change to the file
- THEN both invocations produce the same exit code
- AND both invocations produce the same reason text (if invalid)

---

### IC-03 — Inlined secret rejection (load-bearing)

**IC-03.1** The validator MUST reject any `intake.yaml` in which a secret value is inlined — that is, where a secret-bearing field contains what appears to be a literal credential value rather than a reference into `/etc/osgania/secrets/<key>`. This is a hard, non-negotiable rejection enforcing Principle 4 ("secrets never in versioned files, repo, or conversation").

**IC-03.2** The secret-reference model is: a secret field MUST contain a reference/pointer to a key in `/etc/osgania/secrets/`, never the secret value itself. The concrete detection rule — what distinguishes a reference from an inlined value — is a design decision (IC-03 specifies the OBSERVABLE verdict, not the algorithm).

**IC-03.3** When the validator detects an inlined secret, it MUST exit non-zero and produce a reason that explicitly names the inlined-secret problem, identifies the offending field, and does NOT echo back the suspected secret value.

**IC-03.4** The validator MUST NOT accept an inlined secret value under any fallback, warning-only, or soft-rejection mode. Inlined secrets are always hard INVALID.

**Isolation boundary (IC-03):** IC-03 is the validator's primary load-bearing rule. It prevents Principle 4 violations at the earliest possible point — before any root process (the generator) touches the file. The validator does not resolve, read, or verify the referenced secrets; it only checks that the reference format is used instead of a literal value.

---

#### Scenario IC-03-S1: inlined secret value causes rejection

- GIVEN an `intake.yaml` fixture in which a secret-bearing field contains a literal credential value (e.g. a token-shaped string) instead of a reference
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output reason explicitly identifies the inlined-secret problem
- AND the output does NOT echo the suspected secret value

#### Scenario IC-03-S2: secret reference is valid

- GIVEN an `intake.yaml` fixture in which all secret-bearing fields contain references (pointers into `/etc/osgania/secrets/<key>`)
- WHEN the validator is run against the fixture
- THEN exit code is 0 (the secret reference format is valid; the referenced secret is not read or verified)

---

### IC-04 — No allow[]/permissions field (load-bearing non-goal guard)

**IC-04.1** The `intake.yaml` contract schema MUST NOT define, accept, or model any field whose purpose is to grant, extend, configure, or delegate agent authority — including but not limited to any field named or shaped like `allow`, `permissions`, `capability`, or `policy`. This is a categorical hard non-goal: putting such a field in a client-supplied input would re-open the self-escalation surface that `vps-provisioning-hardening-2b` closed (HB-03.7, the `--setting-sources ""` fail-closed gate).

**IC-04.2** The validator MUST reject any `intake.yaml` that contains such a field, even if the field's value is empty or benign-looking. The rejection MUST be non-zero with a reason identifying the forbidden field.

**IC-04.3** The agent's authority is defined exclusively in the root-owned `/opt/osgania/platform/agent-settings.json` behind the 2b fail-closed gate. Nothing in `intake.yaml` can widen, narrow, or influence that authority.

**Isolation boundary (IC-04):** IC-04 is a structural guard on the schema itself. It prevents authority creep at the contract definition level — not just at validation time. The contract schema MUST NOT contain the field; the validator MUST also actively reject it if somehow present in an input. Both layers are required.

---

#### Scenario IC-04-S1: intake with allow[] field is rejected

- GIVEN an `intake.yaml` fixture that contains a field named `allow` with any value (including an empty list)
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output reason identifies the forbidden `allow` field

#### Scenario IC-04-S2: intake with permissions field is rejected

- GIVEN an `intake.yaml` fixture that contains a field named `permissions` with any value
- WHEN the validator is run against the fixture
- THEN exit code is non-zero
- AND the output reason identifies the forbidden `permissions` field

#### Scenario IC-04-S3: the contract schema itself contains no authority field

- GIVEN the published `intake.yaml` contract schema document
- WHEN it is inspected for fields named `allow`, `permissions`, `capability`, or any authority-delegation field
- THEN no such field exists anywhere in the schema definition

---

### IC-05 — Brain-only intake is valid (forward compatibility)

**IC-05.1** An `intake.yaml` with an empty or absent app-selection MUST be valid. The apps (`db`, `automation`, `landing`, `inbox`) are built in later slices (P5/P6); a client MUST be representable in the contract today with no app selected.

**IC-05.2** A brain-only intake that satisfies all other contract requirements (typed core present, corpus present, no inlined secrets, no forbidden fields) MUST exit 0.

**Isolation boundary (IC-05):** Forward-compatibility is a contract-level invariant. Requiring at least one app selection would make the contract invalid for the first real client before P5/P6 ship, and would require a schema breaking-change. The validator MUST NOT treat empty/absent app-selection as an error.

---

#### Scenario IC-05-S1: brain-only intake (no app selection) is valid

- GIVEN an `intake.yaml` fixture that contains all required typed business core fields and a non-empty corpus, with the app-selection field absent or explicitly set to empty
- WHEN the validator is run against the fixture
- THEN exit code is 0

---

### IC-06 — Re-runnable and idempotent validation

**IC-06.1** The validator MUST be safe to re-run against the same or an evolved `intake.yaml` without any reset or cleanup procedure. Re-validation MUST be the normal update path — an operator who adds an app or changes context fields edits `intake.yaml` and re-runs the validator.

**IC-06.2** An evolved `intake.yaml` (e.g. one that previously had no app selection and now declares one, or one with updated corpus text) MUST be accepted as valid as long as all contract rules are satisfied.

**IC-06.3** Re-running the validator against a previously validated file MUST produce the same verdict (determinism, IC-02.2). Re-running against an unchanged invalid file MUST also produce the same verdict.

**Isolation boundary (IC-06):** The validator writes nothing, so re-runs have no cumulative side-effects. The idempotency guarantee mirrors `provision.sh` R11 and is the reason the validator can be part of a pre-onboarding checklist that the operator runs as many times as needed.

---

#### Scenario IC-06-S1: evolved intake (new app + changed corpus) is valid

- GIVEN an `intake.yaml` fixture that was previously valid (version A: brain-only)
- AND the fixture has been updated to add an app-selection value and change the corpus text (version B)
- WHEN the validator is run against version B of the fixture
- THEN exit code is 0
- AND the validator writes nothing

#### Scenario IC-06-S2: re-validating an unchanged valid fixture produces same verdict

- GIVEN a valid `intake.yaml` fixture
- WHEN the validator is run twice against the same unchanged file
- THEN both runs exit 0 with no output (or identical output)

---

### IC-07 — Host-safe isolation boundary (P0 scope enforcement)

**IC-07.1** The validator MUST be runnable entirely on the operator's host machine (macOS or Linux) without root, without VPS access, without the egress firewall, without the managed policy, and without any systemd unit.

**IC-07.2** The validator and its test suite MUST NOT require a live VPS, a running agent, network access, or elevated privileges. All TIER1 bats tests MUST run host-side with `bats tests/` and `shellcheck scripts/**/*.sh` only.

**IC-07.3** P0 MUST NOT create or modify any file outside the repository: no VPS state, no managed policy, no `allow[]`, no secret, no systemd unit, and no `/opt/osgania/client/` content.

**IC-07.4** Any bash glue around the validator MUST pass `shellcheck -s bash` with no warnings.

**Isolation boundary (IC-07):** P0 has zero security surface. There is nothing to lock out, escalate from, or roll back on any VPS. Rollback is simply reverting the repo change.

---

#### Scenario IC-07-S1: validator runs host-side without root

- GIVEN the repository validator artifact and a fixture file
- WHEN the validator is invoked by an unprivileged user on macOS or Linux without root
- THEN the validator runs to completion and exits with the appropriate code
- AND no file outside the repository is created or modified

#### Scenario IC-07-S2: bash glue passes shellcheck

- GIVEN all bash scripts added by P0 (invocation glue, fixture loops, exit-code plumbing)
- WHEN `shellcheck -s bash` is run on each script
- THEN shellcheck exits 0 with no warnings and no errors

---

### IC-08 — File structure

**IC-08.1** The following artifacts MUST exist in the repository after P0 is applied:

```
schemas/
  intake/
    intake-schema.<ext>       — the versioned intake.yaml contract (format decided in design)
scripts/
  validate-intake.sh          — invocation wrapper / driver (shellcheck-clean)
tests/
  intake/
    valid/
      complete.yaml           — complete intake fixture (all four parts, one app selected)
      brain-only.yaml         — brain-only fixture (no app selection)
      evolved-update.yaml     — evolved fixture (new app + changed corpus vs a prior valid one)
    invalid/
      inlined-secret.yaml     — fixture with an inlined secret value (load-bearing)
      missing-core-field.yaml — fixture missing a required typed business core field
      bad-app-selection.yaml  — fixture with an app value outside the menu
      missing-corpus.yaml     — fixture with absent/empty corpus
      allow-field.yaml        — fixture containing an `allow[]` field (hard non-goal guard)
    intake.bats               — bats test suite covering all IC- scenarios
```

**IC-08.2** `scripts/validate-intake.sh` and any other bash artifact MUST pass `shellcheck -s bash` with no warnings.

**IC-08.3** The contract schema document MUST carry an explicit version string. The initial version MUST be declared; design decides the versioning scheme.

**Isolation boundary (IC-08):** All P0 artifacts are repo-only. No artifact lands on any VPS, no operator machine path outside the repo is modified, and `intake.yaml` itself is operator-held (not committed to the repo).

---

#### Scenario IC-08-S1: all fixture scenarios pass under bats

- GIVEN the complete fixture set (`valid/` and `invalid/`) and the bats test suite
- WHEN `bats tests/intake/intake.bats` is run on the host (no root, no VPS)
- THEN all tests pass (exit 0)
- AND each valid fixture causes exit 0 from the validator
- AND each invalid fixture causes non-zero exit from the validator with a reason

---

## Fixture matrix (normative — all required for IC-08)

| Fixture | Expected verdict | Load-bearing requirement |
|---------|-----------------|--------------------------|
| `valid/complete.yaml` | VALID (exit 0) | IC-01, IC-02 |
| `valid/brain-only.yaml` | VALID (exit 0) | IC-05 |
| `valid/evolved-update.yaml` | VALID (exit 0) | IC-06 |
| `invalid/inlined-secret.yaml` | INVALID (non-zero, names inlined-secret) | IC-03 — load-bearing |
| `invalid/missing-core-field.yaml` | INVALID (non-zero, names field) | IC-01 |
| `invalid/bad-app-selection.yaml` | INVALID (non-zero, names value) | IC-01 |
| `invalid/missing-corpus.yaml` | INVALID (non-zero, names corpus) | IC-01 |
| `invalid/allow-field.yaml` | INVALID (non-zero, names forbidden field) | IC-04 — load-bearing |

---

## Scenario-to-requirement map

| Scenario | Requirement(s) |
|----------|---------------|
| IC-01-S1 | IC-01 |
| IC-01-S2 | IC-01 |
| IC-01-S3 | IC-01 |
| IC-01-S4 | IC-01 |
| IC-01-S5 | IC-01.1 |
| IC-02-S1 | IC-02.1, IC-02.3 |
| IC-02-S2 | IC-02.1, IC-02.5 |
| IC-02-S3 | IC-02.2 |
| IC-03-S1 | IC-03.1, IC-03.3 |
| IC-03-S2 | IC-03.2 |
| IC-04-S1 | IC-04.1, IC-04.2 |
| IC-04-S2 | IC-04.1, IC-04.2 |
| IC-04-S3 | IC-04.1, IC-04.3 |
| IC-05-S1 | IC-05.1, IC-05.2 |
| IC-06-S1 | IC-06.1, IC-06.2 |
| IC-06-S2 | IC-06.3 |
| IC-07-S1 | IC-07.1, IC-07.3 |
| IC-07-S2 | IC-07.4 |
| IC-08-S1 | IC-08.1, IC-08.2 |

Total requirements: **8** (IC-01 through IC-08)
Total scenarios: **19** (IC-01-S1 through IC-08-S1)
Load-bearing requirements: **IC-03** (inlined secret rejection), **IC-04** (no allow[]/permissions)

---

## Non-goals (reiterated for contract clarity)

- The onboarding generator (P1) — out of scope
- The apps (db, automation, landing, inbox) — out of scope
- `allow[]` / permissions / capability grants — categorically excluded from the schema
- Anything touching root, the egress wall, managed policy, or the launch path
- Secret delivery mechanism — out of scope (P0 models the reference; design resolves the detection rule)
- Per-app token storage/injection (P4) or MCP wiring (P3/P6)
- OD-001 runtime decision (Python vs Node) — deferred to design
