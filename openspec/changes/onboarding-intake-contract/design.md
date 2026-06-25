# Design: onboarding-intake-contract ("The input contract")

**Change**: `onboarding-intake-contract` (product slice P0 — "the input contract")
**Project**: osgania
**Artifact store**: openspec
**Date**: 2026-06-25
**Status**: design
**Depends on**: `proposal.md` (APPROVED, 6 open questions — this design RESOLVES them), the proven foundation (`platform-security-core`, `vps-provisioning-base`, `vps-provisioning-hardening-2a`, `vps-provisioning-hardening-2b` — ARCHIVED + verified). Reads engram `sdd/onboarding-intake-contract/proposal` (#282), `sdd-init/osgania` (#135), `sdd/product-roadmap/derisk-spikes` (#281).

> P0 defines **two repo artifacts and nothing else**: a versioned `intake.yaml` **contract** (a JSON Schema document applied to the parsed YAML) and an offline **validator** the operator runs BEFORE onboarding. It mutates **no system state**: no root, no filesystem mutation, no egress wall, no managed policy, no launch path. The decided literals below are AUTHORITATIVE — the spec MUST copy them verbatim (drift gate); if a value looks wrong, fix it HERE first.

---

## Quick path (the 6 resolved questions, one decision each)

| # | Open question | Decision (concrete) |
|---|---------------|---------------------|
| **ADR-1** | Schema mechanism (the main fork) | **Option A — language-agnostic JSON Schema (Draft 2020-12)** applied to the parsed YAML, enforced by `check-jsonschema` (Python, PyPI — already-present `python3` host) as the canonical validator, driven as a subprocess from bats. The schema `.json` is the single source of truth and is **runtime-neutral**; it does NOT commit OD-001. See **OD-001 coupling note**. |
| **ADR-2** | Inlined-secret detection rule | **Structural — designated `secret_ref` fields accept ONLY a reference shape (`secret://<key>`), a literal is invalid.** Enforced by JSON Schema `pattern` + a closed object shape. NOT entropy heuristics, NOT a forbidden-key denylist. Lowest false-positive, deterministic, encodable in the schema itself. |
| **ADR-3** | Typed core field set | `contract_version`, `client.slug`, `client.display_name`, `business.sector`, `business.locale` **required**; `business.products`, `business.goals`, `business.tone` **optional but typed**. Exact types below. |
| **ADR-4** | App-selection representation | **Map of per-app objects keyed by the fixed app menu** (`database`, `automation`, `landing`, `inbox`), each `{ enabled: bool }` today. Brain-only = all `enabled:false` (or omitted) and is VALID. The per-app object is the extension point so P4/P5 add keys WITHOUT a reshape. |
| **ADR-5** | Corpus validation depth | **Opaque blob: present + non-empty (after trim) + valid UTF-8 + size-bounded (1–64 KiB).** NOT parsed for markdown semantics. The corpus is a string field in `intake.yaml` (inline) — well-formed *text*, not well-formed *markdown*. |
| **ADR-6** | Versioning scheme | **`contract_version` is a required top-level integer-major string `"1"`.** The validator **rejects** an unknown/future major (fail-closed, exit non-zero with a clear reason). `const: "1"` in the schema today; bumping it is a deliberate contract revision. |

**Hard security invariants (categorical, restated as design law):**

- **SI-1 — No `allow[]` / permissions / capability field — EVER.** The schema uses `additionalProperties: false` at the top level and on every object, so an `allow`, `permissions`, `deny`, `capabilities`, `setting-sources`, or any unknown grant key is a **structural rejection**. Authority stays solely in root-owned `/opt/osgania/platform/agent-settings.json` behind 2b's `--setting-sources ""` fail-closed gate. Nothing in intake can widen it. (Proposal hard non-goal; risk row "allow[] creeps in" = Critical.)
- **SI-2 — No inlined secret values — fail closed.** Only `secret://<key>` references are valid in `secret_ref` fields; a literal token/password/key is a structural rejection (ADR-2). This is the validator's load-bearing rule.
- **SI-3 — HOST-SAFE.** The validator is read-only, runs no privileged code, writes nothing, opens no socket, touches no VPS state. It reads one file and exits 0/non-zero.

---

## Technical Approach

P0 adds, to the **repo only**, three things:

1. **`schema/intake.schema.json`** — a JSON Schema (Draft 2020-12) document. The single, runtime-neutral source of truth for a well-formed `intake.yaml`. It encodes the typed core (ADR-3), the app map (ADR-4), the corpus bounds (ADR-5), the version `const` (ADR-6), the `secret://` reference pattern (ADR-2), and `additionalProperties:false` everywhere (SI-1).
2. **`scripts/validate-intake.sh`** — a thin bash wrapper (the operator's entrypoint) that (a) confirms the candidate file exists and is readable, (b) parses YAML → JSON and re-emits it, (c) invokes the canonical JSON Schema validator against `intake.schema.json`, (d) maps the validator's exit code to a clear, field-oriented operator message, and exits 0 (valid) or non-zero (invalid). It **writes nothing** to disk.
3. **`tests/validate-intake.bats` + `tests/fixtures/intake/{valid,invalid}/`** — the host-safe bats matrix (the valid/invalid fixture sets from the proposal's testing strategy and the spec's Given/When/Then).

The wrapper is the sanctioned validator entrypoint exactly as `provision.sh` is the sanctioned OS mutator — except here the "mutation" is nil. The JSON Schema document is deliberately separated from any runtime so the OD-001 decision (P1) cannot drift the contract.

### Why a wrapper at all (not "just run the validator")

The operator runs ONE command (`scripts/validate-intake.sh ./client-acme.intake.yaml`). The wrapper hides three concerns from the operator: the YAML→JSON normalization step, the exact validator binary/flags, and the translation of a raw schema error into a readable, field-named reason. This keeps the operator UX stable even if the canonical validator is swapped (the schema, not the binary, is the contract).

---

## Architecture Decisions

### ADR-1 — Schema mechanism: language-agnostic JSON Schema (Option A), enforced by `check-jsonschema`

**Choice.** The contract is a **JSON Schema (Draft 2020-12)** document, `schema/intake.schema.json`, applied to the parsed `intake.yaml`. The **canonical validator** is [`check-jsonschema`](https://pypi.org/project/check-jsonschema/) — a maintained Python CLI (built on the reference [`jsonschema`](https://pypi.org/project/jsonschema/) library) that natively parses YAML and validates it against a `--schemafile`. The host already has `python3 3.9.6` (`sdd-init/osgania` #135), so no new runtime is introduced. The validator is driven as a **subprocess from bats** (assert exit code + reason), matching the foundation's TIER1 `bats`+`shellcheck` pattern.

**Concrete invocation (illustrative — spec fixes the literal):**

```bash
# scripts/validate-intake.sh (core, condensed — host-safe, read-only)
check-jsonschema --schemafile "$SCHEMA" --traceback-mode plain "$CANDIDATE"
```

**Why Option A over Option B (language-native).** Option B binds the validator to the P1 generator's runtime (Python or Node) and therefore **forces OD-001 before P1 decides it** (proposal risk "Binding P0 to OD-001 prematurely" = High). Option A keeps the contract — the schema `.json` — a runtime-neutral artifact: P1 can pick Python or Node and still load the SAME schema (every mainstream language has a conformant validator), so the contract never becomes a migration. Option A is also the cleanest to drive from bats (subprocess + exit code, no in-process test harness) and lets the inlined-secret and no-`allow[]` rules live IN the schema as data, where a structural test can assert their presence.

**Tools verified (search-first — real, maintained, cited; NOT guessed):**

| Tool | Runtime | What it does | Source (confirmed) | Verdict |
|------|---------|--------------|--------------------|---------|
| **`check-jsonschema`** | Python (host has `python3`) | CLI: validates a YAML/JSON instance against `--schemafile`; native YAML parsing; exit 0/1 | https://pypi.org/project/check-jsonschema/ · docs https://check-jsonschema.readthedocs.io | **CANONICAL — Adopt.** Single CLI, no glue to parse YAML, exit-code driven, fits bats. |
| `jsonschema` (lib) | Python | Reference Draft 2020-12 implementation `check-jsonschema` is built on | https://pypi.org/project/jsonschema/ | Transitive dependency of the canonical choice; the engine of record. |
| `ajv` / `ajv-cli` | Node (host has `node 26`) | Most-used JS validator; `ajv-cli validate -s schema.json -d data.yaml` | https://www.npmjs.com/package/ajv · https://www.npmjs.com/package/ajv-cli | **Fallback / OD-001=Node path.** Same schema, Node runtime. Needs a YAML→JSON step (e.g. `yq`) since ajv-cli reads JSON/YAML via a data-format flag. |
| `yq` (Mike Farah) | Go | YAML→JSON normalizer if a validator needs JSON input | https://github.com/mikefarah/yq | Optional — only the ajv path needs it; `check-jsonschema` reads YAML directly. |

**Recommendation:** adopt **`check-jsonschema`** as the canonical P0 validator (zero new runtime, native YAML, single CLI, exit-code clean). The schema document is the contract; the binary is replaceable. Spec MUST pin the validator name + version-floor and document `brew`/`pip` install (mirrors the `bats-core`/`shellcheck` install note in `sdd-init`).

**Alternatives considered.** (a) Option B language-native validation sharing the generator's models — rejected: binds P0 to OD-001 (High risk) and duplicates the contract in code instead of a declarative, portable schema. (b) Hand-rolled bash/`jq` validation — **rejected hard** (search-first): reinventing a YAML/JSON-Schema validator is exactly the anti-pattern; `jq` cannot express recursive schema constraints (`additionalProperties:false`, `pattern`, conditional shapes) without a fragile, untestable mini-engine. (c) A custom Python script using `jsonschema` directly instead of the `check-jsonschema` CLI — rejected as the DEFAULT: it would add ~30 lines of custom YAML-load + error-format glue (more to test, more to drift) when the CLI already does exactly that; kept only as the escape hatch if the CLI is unavailable in an operator environment.

### OD-001 coupling note (flag the dependency — do NOT resolve it)

OD-001 (Python vs Node onboarding-generator runtime) is **resolved in P1, not here** (`sdd-init/osgania` #135; roadmap lean = provisional Python). ADR-1 **minimizes** coupling to it:

- **The contract is OD-001-neutral.** `schema/intake.schema.json` is a Draft 2020-12 document. Both candidate P1 runtimes have first-class conformant validators (`check-jsonschema`/`jsonschema` for Python; `ajv` for Node), so the schema is loadable whichever way OD-001 lands. The contract does NOT migrate when P1 chooses.
- **Only the thin validator binary touches a runtime.** P0 picks `check-jsonschema` (Python) for the offline validator because Python is already on the host and the proposal's lean is Python — but this is a P0 *tooling* choice, NOT the OD-001 decision. If P1 picks Node, P1 can re-enforce the SAME schema with `ajv` at no contract cost; the P0 validator can stay as the operator's offline gate or be re-pointed. Either way the schema is the stable seam.
- **No reverse pressure.** Choosing `check-jsonschema` in P0 does NOT pre-decide OD-001 toward Python — it is reversible and contract-neutral. Spec MUST state this explicitly so a future reader does not mistake the P0 validator tooling for the generator runtime decision.

### ADR-2 — Inlined-secret detection: structural `secret://<key>` reference, never a literal

**Choice.** Designated secret-bearing fields are `secret_ref` typed: a **string matching `^secret://[A-Za-z0-9_.-]+$`** (a pointer that the P1 generator later resolves to `/etc/osgania/secrets/<key>`). The schema enforces this with `pattern`; ANYTHING that is not this exact reference shape — a raw token, a password, an API key, a base64 blob, an empty string — **fails the pattern** and the validator exits non-zero. Secret fields live ONLY where the contract designates them; a secret-shaped value anywhere a `secret_ref` is expected is a structural rejection.

```jsonc
"secret_ref": {
  "type": "string",
  "pattern": "^secret://[A-Za-z0-9_.-]+$",
  "description": "Pointer into /etc/osgania/secrets/<key>. A literal secret value is INVALID."
}
```

**Why structural over the alternatives (the crux — lowest false-positive).**
- **Structural (CHOSEN):** "this field is ONLY ever a `secret://` reference; a literal is invalid." Deterministic, **zero false-positives by construction** (a real reference always passes, a real secret never matches the reference shape), encodable as pure schema data, and trivially testable (an invalid fixture with a raw token in a `secret_ref` field → non-zero exit, clear reason). It also closes the inverse hole: an operator CANNOT smuggle a secret in by making it "look like" non-secret prose, because secret material only belongs in `secret_ref` fields, which reject literals.
- **Entropy heuristics (REJECTED):** "flag high-entropy strings." High false-positive (a long slug, a UUID, a base64 logo, a hashed id, a locale list all read as 'high entropy'); high false-negative (a low-entropy weak password slips through); non-deterministic across tunings — violates the "same input → same verdict" requirement. Not encodable in JSON Schema without a custom keyword.
- **Forbidden-key-shapes denylist (REJECTED):** "reject keys named `token`/`password`/`api_key`." Brittle (misses `pwd`, `secret2`, `auth`), order-dependent, and an arms race; the structural rule subsumes it (the secret fields are designated positively, so there is no "loose" key to denylist).

**Normative rule (spec MUST encode as a TDD guard, not a comment):** a `secret_ref` field MUST match `^secret://[A-Za-z0-9_.-]+$`; a literal value in such a field is a validation FAILURE with reason naming the inlined-secret problem (proposal success-criterion 4, load-bearing). The `secret://` scheme is a contract token, NOT a filesystem path — the validator does NOT resolve it, read `/etc/osgania/secrets/`, or touch any secret (SI-3 host-safe).

### ADR-3 — Typed core field set

**Choice.** The typed business core under `client.*` and `business.*`:

| Field | Type | Req? | Constraint |
|-------|------|------|-----------|
| `contract_version` | string | **MUST** | `const: "1"` (ADR-6) |
| `client.slug` | string | **MUST** | `^[a-z][a-z0-9-]{1,38}[a-z0-9]$` (DNS/dir-safe; one client = one slug) |
| `client.display_name` | string | **MUST** | 1–80 chars, non-empty after trim |
| `business.sector` | string | **MUST** | 1–60 chars, non-empty (free text — generator branches on it) |
| `business.locale` | string | **MUST** | BCP-47-ish `^[a-z]{2}(-[A-Z]{2})?$` (e.g. `es-AR`, `en`) |
| `business.products` | array of string | MAY | each 1–120 chars; products/services offered |
| `business.goals` | array of string | MAY | each 1–200 chars; what the client wants the agent to achieve |
| `business.tone` | string (enum) | MAY | `["formal","neutral","friendly","playful"]` (bounded so the generator renders predictably) |
| `context_corpus` | string | **MUST** | opaque blob, ADR-5 bounds |
| `apps` | object | MAY | the app map, ADR-4 (omitted ⇒ brain-only, valid) |
| `secrets` | object | MAY | map of name → `secret_ref` (ADR-2); omitted ⇒ no secrets referenced |

**Rationale.** The five MUSTs are the minimum the P1 generator needs to render a coherent per-client context: WHO (`slug`, `display_name`), WHAT-domain (`sector`), HOW-to-speak-defaults (`locale`), and the rich prose (`context_corpus`). Everything generator-branching-but-not-essential (`products`, `goals`, `tone`) is optional-but-typed so a sparse first intake validates while a rich one stays machine-meaningful. `tone` is an enum (not free text) precisely because the generator must render it predictably (proposal "typed so the generator can render predictably"). `slug` is the strict regex because it is the per-client identity that later names directories/workspaces — one VPS, one slug (isolation principle).

**Alternatives considered.** Making `products`/`goals`/`tone` required — rejected: forces ceremony on a brain-only first client and the corpus already carries that prose; typed-optional is the hybrid-model sweet spot. Free-text `tone` — rejected: unpredictable generator output; the bounded enum is the contract.

### ADR-4 — App selection: a map of per-app objects keyed by the fixed menu

**Choice.** `apps` is an **object** with the four fixed menu keys, each a small object:

```jsonc
"apps": {
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "database":   { "$ref": "#/$defs/appEntry" },
    "automation": { "$ref": "#/$defs/appEntry" },
    "landing":    { "$ref": "#/$defs/appEntry" },
    "inbox":      { "$ref": "#/$defs/appEntry" }
  }
},
"$defs": {
  "appEntry": {
    "type": "object",
    "additionalProperties": false,
    "properties": { "enabled": { "type": "boolean" } },
    "required": ["enabled"]
  }
}
```

**Brain-only is valid** two ways: omit `apps` entirely, OR set every entry `enabled:false`. A menu key outside `{database,automation,landing,inbox}` is a structural rejection (`additionalProperties:false`) — that is proposal success-criterion's "malformed app selection (value outside the menu)".

**Why per-app object over a flat enum list (forward-compat — the load-bearing reason).** A `["database","inbox"]` enum-list models *which* apps but has NO room for *per-app config* (the connection details, scopes, and `secret_ref`s that P4/P5 add) without a **reshape** from `array<enum>` to `array<object>` — turning every earlier client's `intake.yaml` into a migration (proposal risk "too-narrow schema" = Medium). The per-app object starts minimal (`{enabled}`) and P4/P5 ADDITIVELY add keys (e.g. `database.connection_ref: secret://...`, `automation.scopes: [...]`) under `additionalProperties:false` relaxed-per-app — a pure schema extension, NO reshape, NO migration. P0 ships the SHAPE; later slices fill it.

**Alternatives considered.** `array` of enum strings — rejected (reshape on first per-app config, above). `array` of `{name, enabled, ...}` objects — rejected: a list allows duplicate/ordered/missing names; the keyed map gives uniqueness + presence-by-key for free and reads cleaner. A single `enabled_apps: [...]` plus a parallel `app_config: {...}` — rejected: two structures to keep in sync invites drift; one keyed map is the single source.

### ADR-5 — Corpus validation depth: opaque well-formed *text*, not parsed markdown

**Choice.** `context_corpus` is a **string** validated as:
- **present** (required field),
- **non-empty after trim** (`minLength` on the trimmed value — a whitespace-only corpus is invalid),
- **valid UTF-8** (guaranteed by YAML parse + JSON Schema `type:string`; the wrapper's YAML→JSON step rejects invalid encoding),
- **size-bounded: 1–65536 bytes (64 KiB)** (`maxLength`), to bound the generator's later render and reject a pasted-binary/runaway file.

It is **NOT parsed for markdown semantics** — no heading/link/list checks, no rendering, no meaning extraction. "Well-formed markdown text" means well-formed *text that the operator authored as markdown prose*; the generator (P1) renders it verbatim into `client/` context docs. Treating it as opaque keeps P0 from coupling to any markdown library and avoids rejecting benign-but-unusual prose (proposal risk "corpus mis-validated" = Low).

**Note on inline vs path.** The corpus is an **inline string field** in `intake.yaml`, not a path to a separate file — this keeps the validator a single-file read (HOST-SAFE, SI-3) and keeps "one client = one intake file" intact. (If a future slice wants an external corpus file, that is an additive `corpus_ref` extension, not a P0 concern.)

**Alternatives considered.** Parse + lint the markdown (e.g. require valid CommonMark) — rejected: pulls in a markdown parser, raises false-positives on benign content, and the generator renders verbatim anyway. No size bound — rejected: an unbounded blob is a DoS-shaped foot-gun for the P1 render; 64 KiB is generous for prose. Allowing empty corpus — rejected: an empty business description defeats the "knows the client's business" purpose; non-empty-after-trim is the floor.

### ADR-6 — Versioning: required `contract_version: "1"`, reject unknown/future major (fail-closed)

**Choice.** `contract_version` is a **required top-level string**, today `const: "1"`. The validator REJECTS any other value (including a higher/future major like `"2"`) with a clear reason. Bumping the contract is a deliberate, reviewed schema revision (new `const`, new fixtures); the validator never silently accepts a version it does not understand.

```jsonc
"contract_version": { "type": "string", "const": "1" }
```

**Why reject (not warn) an unknown version.** P0's whole reason to exist is to be the **safe gate before the root-run P1 generator**. A `warn`-and-continue on an unknown version would let a file written against a *different* contract reach P1 — exactly the "discover the problem after root started mutating" failure the slice prevents. Fail-closed (reject) is consistent with 2b's `--setting-sources ""` philosophy and the proposal's "deterministic verdict." A future contract revision is handled by the operator updating the schema + re-validating (the re-runnable/idempotent path, proposal R11-mirror), NOT by the validator guessing.

**Why a string-major (`"1"`) not semver.** The contract needs ONE axis the validator branches on: "is this the contract shape I enforce?" A single integer-major string answers that crisply (`const` check). Minor/patch wiggle is unnecessary for a hand-authored input — every shape change is a reviewed bump. (Spec MAY note a future `"1.x"` convention if minor additive fields ever need to validate against multiple minors; not needed for P0.)

**Alternatives considered.** Optional version (default to "1" if absent) — rejected: an absent version is ambiguous between "old file" and "operator forgot"; required is unambiguous and forces intent. `warn` on future version — rejected (fail-closed reasoning above). Full semver `pattern` — rejected: over-engineered for a single-shape contract; `const` is the testable, drift-proof minimum.

---

## The `intake.yaml` shape (the contract, end-state)

A complete, valid example the spec's `valid/` fixtures mirror:

```yaml
contract_version: "1"

client:
  slug: acme-cafe
  display_name: "Acme Café"

business:
  sector: "specialty coffee retail"
  locale: es-AR
  products:
    - "single-origin beans"
    - "barista courses"
  goals:
    - "answer FAQs about opening hours and the menu"
    - "take catering inquiries"
  tone: friendly

context_corpus: |
  # Acme Café
  Family-run specialty coffee shop in Palermo, Buenos Aires...
  (rich operator-authored prose — rendered verbatim by P1, NOT parsed here)

# apps omitted ⇒ brain-only ⇒ VALID today.
# When apps land (P5/P6), this becomes e.g.:
# apps:
#   inbox:    { enabled: true }
#   database: { enabled: false }

# secrets omitted ⇒ no references. When present, ONLY references:
# secrets:
#   inbox_smtp: secret://acme-inbox-smtp   # a literal here ⇒ REJECTED (ADR-2/SI-2)
```

What makes a file INVALID (each is a fixture + a Given/When/Then in the spec):
- a literal value in any `secret_ref` field (SI-2, load-bearing) → non-zero;
- any `allow`/`permissions`/`deny`/`capabilities`/`setting-sources`/unknown key (SI-1) → non-zero;
- a missing MUST field (`contract_version`, `client.slug`, `client.display_name`, `business.sector`, `business.locale`, `context_corpus`) → non-zero;
- an app key outside `{database,automation,landing,inbox}`, or `enabled` not boolean → non-zero;
- a missing/empty/oversized `context_corpus` → non-zero;
- `contract_version` ≠ `"1"` → non-zero.

---

## Validator flow (the only "sequence" P0 has — read-only, no agent, no app)

P0 has NO agent-to-app communication flow (the config `rules.design` sequence-diagram rule targets agent-to-app flows; P0 introduces none — it is an offline operator tool). For completeness, the validator's single read-and-judge path:

```
operator runs: scripts/validate-intake.sh ./acme.intake.yaml
   │
   ▼
[1] file exists + readable?            no → exit 2, "cannot read <path>"
   │ yes
   ▼
[2] parse YAML → JSON (in memory)      parse error / bad UTF-8 → exit 1, "not well-formed YAML"
   │ ok
   ▼
[3] check-jsonschema --schemafile intake.schema.json  (the contract, ADR-1)
   │      enforces: version const (ADR-6), required core (ADR-3),
   │      app map (ADR-4), corpus bounds (ADR-5),
   │      secret:// pattern (ADR-2/SI-2), additionalProperties:false (SI-1)
   ├─ valid   → exit 0   (writes NOTHING — SI-3)
   └─ invalid → exit 1, field-oriented reason (e.g. "secrets.inbox_smtp: inlined
                          secret value — only secret://<key> references allowed")
```

Deterministic: same input → same verdict (proposal success-criterion 8). No network, no socket, no privileged call, no write (SI-3). This is NOT an agent run — there is no `claude`, no managed-settings, no hook, no key. The wrapper is a pure judge.

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `schema/intake.schema.json` | Create | The contract: JSON Schema Draft 2020-12. Encodes ADR-2..ADR-6 + SI-1. The single, runtime-neutral source of truth. |
| `scripts/validate-intake.sh` | Create | Operator entrypoint. Read-only wrapper: existence check → YAML→JSON → `check-jsonschema` → exit-code + reason. `shellcheck -s bash` clean. Writes nothing. |
| `tests/validate-intake.bats` | Create | Host-safe bats matrix driving the validator as a subprocess against fixtures (exit-code + reason assertions). |
| `tests/fixtures/intake/valid/*.intake.yaml` | Create | `complete`, `brain-only` (apps omitted), `client-update` (evolved: a new app enabled + changed context). All → exit 0. |
| `tests/fixtures/intake/invalid/*.intake.yaml` | Create | `inlined-secret` (load-bearing), `has-allow` (SI-1 structural guard), `missing-core`, `bad-app`, `bad-corpus`, `bad-version`. All → non-zero + reason. |
| `tests/fixtures/intake/README.md` | Create (optional) | One-paragraph note: how to add a fixture; the valid/invalid contract. |

NO VPS file, NO `managed-settings.json`, NO `agent-settings.json`, NO systemd unit, NO secret, NO `allow[]` is created or modified by P0 (proposal success-criterion 10). Repo-only, additive.

---

## Secret-leak surface review (config rule: flag every leak point)

| # | Surface | Risk | Mitigation |
|---|---------|------|------------|
| **S-1** | **Inlined secret in a `secret_ref` field** (the central one) | Operator pastes a real token "to make it work" → a secret lands in an operator/versioned file (Principle 4 violation) | **ADR-2 / SI-2 structural rule:** `secret_ref` matches ONLY `^secret://<key>$`; a literal → non-zero exit + clear reason. Dedicated `invalid/inlined-secret` fixture is the load-bearing TDD guard (success-criterion 4). |
| **S-2** | A secret pasted into a *non-secret* field (e.g. into `context_corpus` or `business.sector`) | A token hidden in prose evades the `secret_ref` check | Bounded, NOT fully eliminated: secret material *belongs* only in designated `secret_ref` fields; the corpus is opaque text (ADR-5) and the validator does not entropy-scan it (ADR-2 rejects entropy heuristics as high-false-positive). Residual = operator discipline; flagged here. (A future optional `--paranoid` entropy pass on free-text fields is a candidate hardening, NOT P0 — it would re-introduce the false-positive cost ADR-2 deliberately avoids.) |
| **S-3** | The validator reading/resolving `secret://<key>` | If the validator dereferenced the pointer it would read `/etc/osgania/secrets/<key>` → a secret in tool memory/output | **It does NOT.** `secret://` is a contract TOKEN; the validator only pattern-matches the string, never resolves it, never touches the secrets path (SI-3 host-safe). Resolution is P1's root-run job, out of scope. |
| **S-4** | Validator stdout / a `set -x` trace | Tracing the wrapper could echo the candidate file's content (incl. a mistakenly-inlined secret) into the operator terminal/CI log | The wrapper MUST NOT `set -x` around the candidate content; it prints only the field-oriented *reason* (a field path + rule name), NEVER the offending value. The reason for `inlined-secret` names the FIELD, not the secret. Spec encodes "reason names the field, not the value." |
| **S-5** | `intake.yaml` placement under agent-readable `client/` | If stored under `/opt/osgania/client/` (aios:aios 0700) the agent could read raw operator input incl. `secret://` keys | Contract STATES `intake.yaml` is operator-held, never committed, never under `client/` (proposal). P0 does not require the file to live anywhere agent-readable; *enforcing* placement is P1's root-run job. Flagged; not P0-enforced. |
| **S-6** | `additionalProperties:false` gap (an undesigned grant key slips in) | A future schema edit relaxes `additionalProperties` and an `allow`/`permissions` key creeps in → re-opens 2b's self-escalation surface (SI-1, Critical) | A **structural test** asserts the schema has `additionalProperties:false` at the top level and rejects an `has-allow` fixture (success-criterion 5). Any PR relaxing it on the top object MUST be caught by that test. SI-1 is design law. |

**Note on security surface**: P0 touches **no firewall, no SSH, no managed policy, no launch path, no root, no key, no socket**. None of the foundation's lockout/escalation risks apply (proposal). The ONLY security-relevant logic is the input-hygiene rules above (SI-1/SI-2) — declarative, in the schema, host-safe.

---

## Testing Strategy

| Layer | What to test | Approach |
|-------|-------------|----------|
| Host-safe (macOS now, bats) | Valid fixtures (`complete`, `brain-only`, `client-update`) → exit 0, no file written. Invalid fixtures (`inlined-secret` [load-bearing], `has-allow` [SI-1], `missing-core`, `bad-app`, `bad-corpus`, `bad-version`) → non-zero + reason names the field/rule. Determinism (run twice, same verdict). Structural assertion that the schema sets `additionalProperties:false` at top level. | `check-jsonschema` driven as a subprocess from bats; assert exit code + reason substring. No root, no systemd, no VPS, no key. |
| Lint | `scripts/validate-intake.sh` passes `shellcheck -s bash` with no warnings (every bash file gets a paired shellcheck task — config `rules.tasks`). | `shellcheck` on the wrapper. |
| Schema sanity | `intake.schema.json` is itself valid JSON Schema (the validator/`jq .` parses it). | `jq .` (host has `jq 1.7.1`) + the validator's own schema-load. |

**No Linux-deferred tier.** P0 has nothing needing a disposable VPS, root, or a real key — entirely host-safe (proposal). A `--check`-style dry run is the validator's WHOLE purpose; there is no separate dry-run mode to add.

**Install note (mirror `sdd-init`):** before first `sdd-apply`, the dev host needs `bats-core`, `shellcheck`, AND the canonical validator: `brew install bats-core shellcheck` + `pipx install check-jsonschema` (or `pip install check-jsonschema`). Spec MUST carry this install line.

---

## Migration / Rollout

No data migration. Rollout = the operator authors an `intake.yaml` and runs `scripts/validate-intake.sh` before onboarding; re-validating an evolved file (new app, changed context) is the normal re-run path (proposal R11-mirror). **Rollback is trivial and repo-only** (proposal): revert the schema + wrapper + tests. No box is touched; no `intake.yaml` on any operator machine is affected (operator-held data). No managed policy, no `allow[]`, no secret, no audit arming, no systemd unit to preserve — P0 created none. Forward-fix (a contract bug) is an additive schema edit + re-run of the host-safe tests; full revert is the escape hatch.

## Open Questions

None blocking. The 6 proposal questions are resolved (ADR-1..ADR-6). Two dependencies are FLAGGED, not resolved (correctly out of P0 scope):
- **OD-001** (Python vs Node generator runtime) — resolved in P1; ADR-1 + the OD-001 coupling note keep the contract neutral so P0 does not pre-decide it.
- **Secret-delivery channel** (how a token actually lands in `/etc/osgania/secrets/<key>`) — a separate roadmap gap; P0 only models the `secret://` reference and rejects inlined values.

## Next step

Run `sdd-tasks` (now that spec + design are ready): break this into a host-safe TDD task list — schema document, the `shellcheck`-clean wrapper, the bats fixtures (valid + invalid, with the load-bearing `inlined-secret` and `has-allow` guards), and the install note — grouped by phase with a paired shellcheck task for the bash wrapper (config `rules.tasks`). No Linux-deferred tasks; zero security surface to stage.
