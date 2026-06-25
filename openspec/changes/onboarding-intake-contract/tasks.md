# Tasks: onboarding-intake-contract ("The input contract")

**Change**: `onboarding-intake-contract` (product slice P0)
**Spec**: `openspec/changes/onboarding-intake-contract/spec.md` (8 requirements IC-01..IC-08, 19 scenarios)
**Design**: `openspec/changes/onboarding-intake-contract/design.md` (ADR-1..ADR-6 + SI-1/SI-2/SI-3)
**TDD mode**: STRICT — every implementation cluster follows RED → GREEN → shellcheck
**Platform**: macOS dev box, host-safe only (no VPS, no root, no live key — P0 has zero security surface)

---

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 280–360 (schema ~120 LOC, wrapper ~60 LOC, 9 fixture files ~80 LOC, bats suite ~80–100 LOC) |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR (P0 is complexity S — schema + wrapper + fixtures + bats) |
| Delivery strategy | ask-on-risk |
| Chain strategy | N/A — single PR |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: Low

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| WU0 | Tooling gate + install doc | PR 1 | `check-jsonschema` install; confirm bats + shellcheck |
| WU1 | `schema/intake.schema.json` | PR 1 | JSON Schema Draft 2020-12; all ADRs encoded |
| WU2 | `scripts/validate-intake.sh` wrapper | PR 1 | Bash driver; shellcheck-clean; writes nothing |
| WU3 | Fixture matrix | PR 1 | 3 valid + 6 invalid YAML files under `tests/` |
| WU4 | `tests/intake/intake.bats` test suite | PR 1 | Drives validator as subprocess; 19 scenarios |

All five work units ship as a single PR. Commit per work unit for reviewability.

---

## Install Prerequisite (run before first sdd-apply)

```bash
# bats-core and shellcheck (if not yet present from earlier slices):
brew install bats-core shellcheck

# canonical JSON Schema validator (python3 3.9.6 is already on the host):
pip install check-jsonschema
# OR: pipx install check-jsonschema
```

These three tools MUST be available before any GREEN task executes.

---

## Phase 1: Tooling Gate + Schema Document (WU0 + WU1)

_Covers: IC-08.1 (file structure), IC-08.3 (version string), IC-01.3 (no authority fields via SI-1), ADR-1..ADR-6_

- [ ] 1.1 **[WU0 — Tooling gate]** Verify `bats --version` (>=1.13.0), `shellcheck --version` (>=0.11.0), and `check-jsonschema --version` all exit 0. Document the install one-liner above in `tests/intake/README.md` (single paragraph: how to add a fixture, the valid/invalid contract, and the tool install line). This task gates all subsequent RED/GREEN tasks.

- [ ] 1.2 **[WU1 — RED: schema fixture test]** Create `tests/intake/intake.bats` with file header, `setup()`, and a single failing test:
  `@test "schema file is valid JSON parseable by jq"` — `run jq . schema/intake.schema.json`; assert `$status -eq 0`. Confirm it FAILS (file does not exist yet).

- [ ] 1.3 **[WU1 — GREEN: create `schema/intake.schema.json`]** Write the JSON Schema Draft 2020-12 document encoding:
  - `"$schema": "https://json-schema.org/draft/2020-12/schema"`
  - `"additionalProperties": false` at top level (SI-1 — any `allow`/`permissions`/unknown key is a structural rejection)
  - `"required": ["contract_version", "client", "business", "context_corpus"]`
  - `contract_version`: `{"type": "string", "const": "1"}` (ADR-6)
  - `client` object: `additionalProperties: false`; required `slug` (`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`), `display_name` (1–80 chars) (ADR-3)
  - `business` object: `additionalProperties: false`; required `sector` (1–60 chars), `locale` (`^[a-z]{2}(-[A-Z]{2})?$`); optional `products`, `goals`, `tone` (enum `["formal","neutral","friendly","playful"]`) (ADR-3)
  - `context_corpus`: `{"type": "string", "minLength": 1, "maxLength": 65536}` (ADR-5)
  - `apps` (optional): object with `additionalProperties: false`, properties keyed `database`/`automation`/`landing`/`inbox`, each a `$ref` to `#/$defs/appEntry`; `$defs/appEntry`: `{type:object, additionalProperties:false, required:["enabled"], properties:{enabled:{type:boolean}}}` (ADR-4)
  - `secrets` (optional): object, `additionalProperties: false`; values are `secret_ref` — `{"type":"string","pattern":"^secret://[A-Za-z0-9_.-]+$"}` (ADR-2/SI-2)
  Confirm the 1.2 test is now GREEN.

---

## Phase 2: Bash Wrapper (WU2)

_Covers: IC-07.4 (shellcheck-clean bash), IC-02.1..IC-02.5 (read-only, verdicts, determinism, no root), IC-08.2_

- [ ] 2.1 **[WU2 — RED: wrapper test]** In `tests/intake/intake.bats`, add failing tests:
  - `@test "IC-07-S2 validate-intake.sh passes shellcheck"` — `run shellcheck -s bash scripts/validate-intake.sh`; assert `$status -eq 0`. Confirm FAIL (file does not exist yet).
  - `@test "IC-02-S1 wrapper exits non-zero when called with no argument"` — `run bash scripts/validate-intake.sh`; assert `$status -ne 0`. Confirm FAIL.

- [ ] 2.2 **[WU2 — GREEN: create `scripts/validate-intake.sh`]** Write the bash wrapper:
  - `#!/usr/bin/env bash` + `set -euo pipefail`
  - Accept exactly one positional argument (the candidate YAML path); exit non-zero with `"usage: validate-intake.sh <path>"` if absent or more than one arg
  - Check the file exists and is readable; exit 2 + `"cannot read <path>"` if not (IC-02 flow step 1)
  - Invoke `check-jsonschema --schemafile "$(dirname "$0")/../schema/intake.schema.json" --traceback-mode plain "$1"` capturing stdout+stderr
  - On exit 0: print nothing (or `"VALID"`) and exit 0 (IC-02.1 verdict VALID)
  - On non-zero exit: emit a field-oriented reason from `check-jsonschema` output; NEVER echo back a value that could be a secret (only field path + rule name); exit 1 (IC-02.1 verdict INVALID, IC-02.5, IC-03.3 / S4 surface review)
  - Write NOTHING to the filesystem (IC-02.3, SI-3); NO `set -x` around candidate content
  - Requires no root (IC-02.4)
  Confirm 2.1 tests are now GREEN.

- [ ] 2.3 **[WU2 — SHELLCHECK]** `shellcheck -s bash scripts/validate-intake.sh` MUST exit 0 with no warnings. Satisfies IC-07-S2, IC-08.2. (Paired shellcheck task per config `rules.tasks`.)

---

## Phase 3: Fixture Matrix (WU3)

_Covers: IC-08.1 (file structure), all valid/invalid fixture scenarios_

- [ ] 3.1 **[WU3 — Create valid fixtures]** Write three YAML fixtures under `tests/intake/valid/`:
  - `complete.yaml` — `contract_version: "1"`, all five required core fields (`client.slug`, `client.display_name`, `business.sector`, `business.locale`, `context_corpus` non-empty), one app enabled (`apps.database.enabled: true`), one `secrets` entry using `secret://` reference. Expected: exit 0 (IC-01-S1, IC-02-S1/S2/S3).
  - `brain-only.yaml` — same required core fields + corpus, `apps` key entirely absent (or all `enabled: false`), no `secrets`. Expected: exit 0 (IC-05-S1, IC-01.2).
  - `evolved-update.yaml` — was `brain-only`; now has `apps.inbox.enabled: true` + updated corpus text. Expected: exit 0 (IC-06-S1/S2).

- [ ] 3.2 **[WU3 — Create invalid fixtures — load-bearing IC-03]** Write `tests/intake/invalid/inlined-secret.yaml`: all required core fields valid, but `secrets.api_token` contains a literal credential string (e.g. `sk-ant-api03-FAKE`) instead of a `secret://` reference. Expected: exit non-zero, reason names inlined-secret problem NOT echoing the value (IC-03-S1 — **LOAD-BEARING**).

- [ ] 3.3 **[WU3 — Create invalid fixtures — load-bearing IC-04]** Write `tests/intake/invalid/allow-field.yaml`: all required core fields valid, but adds a top-level `allow: []` key. Expected: exit non-zero, reason identifies the forbidden `allow` field (IC-04-S1 — **LOAD-BEARING**). Also write `tests/intake/invalid/permissions-field.yaml`: same but with a `permissions: {}` key (IC-04-S2).

- [ ] 3.4 **[WU3 — Create remaining invalid fixtures]** Write under `tests/intake/invalid/`:
  - `missing-core-field.yaml` — omits `business.sector`. Expected: exit non-zero, names the missing field (IC-01-S2).
  - `bad-app-selection.yaml` — adds `apps.crm.enabled: true` (value not in menu). Expected: exit non-zero, names invalid value (IC-01-S3).
  - `missing-corpus.yaml` — `context_corpus` absent or empty string. Expected: exit non-zero, names corpus (IC-01-S4).
  - `missing-version.yaml` — `contract_version` field absent. Expected: exit non-zero, names missing version (IC-01-S5).
  - `unknown-version.yaml` — `contract_version: "2"`. Expected: exit non-zero, names unknown/invalid version (IC-01.1).

---

## Phase 4: bats Test Suite (WU4)

_Covers: all 19 IC scenarios + determinism + structural schema assertion_

- [ ] 4.1 **[WU4 — RED: valid-fixture tests]** In `tests/intake/intake.bats`, add failing tests for every valid fixture (run wrapper as subprocess, assert exit 0, assert no file on disk created):
  - `@test "IC-01-S1 / IC-02-S1 complete valid intake exits 0"` — `run bash scripts/validate-intake.sh tests/intake/valid/complete.yaml`; assert `$status -eq 0`
  - `@test "IC-05-S1 brain-only intake exits 0"` — same pattern, brain-only fixture
  - `@test "IC-06-S1 evolved-update intake exits 0"` — same, evolved fixture
  - `@test "IC-02-S3 / IC-06-S2 determinism: same valid file run twice gives same exit 0"` — run twice, both `$status -eq 0`
  - `@test "IC-07-S1 validator runs without root and writes no file"` — run wrapper; assert exit 0; assert no new file in `$BATS_TMPDIR` post-run
  - `@test "IC-08-S1 schema file is valid JSON"` — `run jq . schema/intake.schema.json`; assert `$status -eq 0`
  Confirm tests FAIL before GREEN phase.

- [ ] 4.2 **[WU4 — RED: invalid-fixture tests]** In `tests/intake/intake.bats`, add failing tests for each invalid fixture:
  - `@test "IC-03-S1 inlined-secret causes non-zero exit and names field not value"` — run against `invalid/inlined-secret.yaml`; assert `$status -ne 0`; assert output contains `secrets` or `inlined-secret` or `secret_ref` (field-level reason); assert output does NOT contain the literal fake credential string (**IC-03 LOAD-BEARING**)
  - `@test "IC-04-S1 allow-field causes non-zero exit and names allow"` — run against `invalid/allow-field.yaml`; assert `$status -ne 0`; assert output contains `allow` (**IC-04 LOAD-BEARING**)
  - `@test "IC-04-S2 permissions-field causes non-zero exit and names permissions"` — run against `invalid/permissions-field.yaml`; assert `$status -ne 0`; assert output contains `permissions`
  - `@test "IC-01-S2 missing-core-field causes non-zero exit and names field"` — assert `$status -ne 0`; assert output names the missing field
  - `@test "IC-01-S3 bad-app-selection causes non-zero exit"` — assert `$status -ne 0`
  - `@test "IC-01-S4 missing-corpus causes non-zero exit"` — assert `$status -ne 0`; assert output mentions `context_corpus`
  - `@test "IC-01-S5 missing-version causes non-zero exit"` — assert `$status -ne 0`; assert output mentions `contract_version`
  - `@test "IC-01.1 unknown-version causes non-zero exit"` — assert `$status -ne 0`; assert output mentions version
  - `@test "IC-02-S3 determinism: same invalid file run twice gives same non-zero exit"` — run twice, both `$status -ne 0`, both `$output` identical
  Confirm tests FAIL before GREEN phase.

- [ ] 4.3 **[WU4 — RED: structural schema assertion]** In `tests/intake/intake.bats`, add:
  - `@test "IC-04-S3 schema has additionalProperties false at top level"` — `run jq '.additionalProperties' schema/intake.schema.json`; assert output is `false`
  - `@test "IC-03-S2 valid secret-ref intake exits 0"` — run against `valid/complete.yaml` (which has `secret://` references); assert `$status -eq 0`
  Confirm FAIL before GREEN phase.

- [ ] 4.4 **[WU4 — GREEN: run full bats suite]** With schema + wrapper + all fixtures in place, run `bats tests/intake/intake.bats`. ALL tests MUST be green (0 failures). No VPS, no root, no network. Satisfies IC-08-S1.

- [ ] 4.5 **[WU4 — SHELLCHECK re-verify]** `shellcheck -s bash scripts/validate-intake.sh` MUST exit 0. Re-run after any wrapper edits surfaced by the bats run.

---

## Phase 5: Full Green Gate + File Structure Verification

_Covers: IC-08.1 (file structure), IC-08.2 (shellcheck), IC-07-S1/S2_

- [ ] 5.1 **Full bats green gate**: `bats tests/intake/intake.bats` — all tests PASS, 0 failures. Record test count here after run: `__ ok / 0 failed`.

- [ ] 5.2 **Shellcheck clean gate**: `shellcheck -s bash scripts/validate-intake.sh` — exit 0, zero warnings. Satisfies IC-07-S2, IC-08.2.

- [ ] 5.3 **File structure verification**: Confirm all IC-08.1 artifacts exist:
  ```
  schema/intake.schema.json                     ✓
  scripts/validate-intake.sh                    ✓
  tests/intake/valid/complete.yaml              ✓
  tests/intake/valid/brain-only.yaml            ✓
  tests/intake/valid/evolved-update.yaml        ✓
  tests/intake/invalid/inlined-secret.yaml      ✓  (load-bearing IC-03)
  tests/intake/invalid/allow-field.yaml         ✓  (load-bearing IC-04)
  tests/intake/invalid/permissions-field.yaml   ✓  (IC-04-S2)
  tests/intake/invalid/missing-core-field.yaml  ✓
  tests/intake/invalid/bad-app-selection.yaml   ✓
  tests/intake/invalid/missing-corpus.yaml      ✓
  tests/intake/invalid/missing-version.yaml     ✓
  tests/intake/invalid/unknown-version.yaml     ✓
  tests/intake/intake.bats                      ✓
  tests/intake/README.md                        ✓
  ```
  No file lands outside the repository. No VPS state created (IC-07.3, IC-08.1 isolation boundary).

---

## Scenario Coverage Table (all 19 scenarios — zero orphans)

| Scenario | Requirement(s) | Fixture | Task |
|----------|---------------|---------|------|
| IC-01-S1 | IC-01 | `valid/complete.yaml` | 4.1 |
| IC-01-S2 | IC-01 | `invalid/missing-core-field.yaml` | 4.2 |
| IC-01-S3 | IC-01 | `invalid/bad-app-selection.yaml` | 4.2 |
| IC-01-S4 | IC-01 | `invalid/missing-corpus.yaml` | 4.2 |
| IC-01-S5 | IC-01.1 | `invalid/missing-version.yaml` | 4.2 |
| IC-02-S1 | IC-02.1, IC-02.3 | `valid/complete.yaml` | 4.1 |
| IC-02-S2 | IC-02.1, IC-02.5 | any invalid fixture | 4.2 |
| IC-02-S3 | IC-02.2 | any fixture | 4.1 / 4.2 |
| IC-03-S1 | IC-03.1, IC-03.3 | `invalid/inlined-secret.yaml` | 3.2 / 4.2 |
| IC-03-S2 | IC-03.2 | `valid/complete.yaml` | 4.3 |
| IC-04-S1 | IC-04.1, IC-04.2 | `invalid/allow-field.yaml` | 3.3 / 4.2 |
| IC-04-S2 | IC-04.1, IC-04.2 | `invalid/permissions-field.yaml` | 3.3 / 4.2 |
| IC-04-S3 | IC-04.1, IC-04.3 | `schema/intake.schema.json` | 4.3 |
| IC-05-S1 | IC-05.1, IC-05.2 | `valid/brain-only.yaml` | 3.1 / 4.1 |
| IC-06-S1 | IC-06.1, IC-06.2 | `valid/evolved-update.yaml` | 3.1 / 4.1 |
| IC-06-S2 | IC-06.3 | any valid fixture | 4.1 |
| IC-07-S1 | IC-07.1, IC-07.3 | `valid/complete.yaml` | 4.1 |
| IC-07-S2 | IC-07.4 | `scripts/validate-intake.sh` | 2.3 / 4.5 |
| IC-08-S1 | IC-08.1, IC-08.2 | all fixtures + bats | 5.1 / 5.2 / 5.3 |

**Total: 19 scenarios | Zero orphans confirmed.**

---

## Parallelism Notes

- Phase 1 and Phase 2 are independent: schema (WU1) and wrapper (WU2) can be drafted in parallel, but the wrapper's GREEN task needs the schema at the correct path to run `check-jsonschema` against it.
- Phase 3 (fixtures) depends on Phase 1 GREEN (schema must exist so the valid fixture content is known correct).
- Phase 4 (bats suite) depends on Phases 1, 2, and 3 all complete.
- Phase 5 (gate) depends on Phase 4 GREEN.
- Phase 1.1 (tooling gate) must be first: blocking dependency.

---

## Rough Size Estimate

| File | Estimated LOC |
|------|--------------|
| `schema/intake.schema.json` | 100–130 LOC |
| `scripts/validate-intake.sh` | 50–70 LOC |
| `tests/intake/valid/*.yaml` (3 files) | ~40 LOC |
| `tests/intake/invalid/*.yaml` (8 files) | ~60 LOC |
| `tests/intake/intake.bats` | 80–110 LOC |
| `tests/intake/README.md` | 15–20 LOC |
| **Total** | **345–430 LOC** |

> Estimate is at the upper edge of Low risk. All host-safe; no Linux-root or live-key tier. Single PR is appropriate.
