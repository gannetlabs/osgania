# Proposal: onboarding-intake-contract

**Change id**: `onboarding-intake-contract`
**Capability**: client onboarding — **product slice P0 ("the input contract")**
**Project**: osgania
**Artifact store**: openspec
**Date**: 2026-06-25
**Status**: proposal (awaiting review → spec + design)
**Builds on**: the proven platform foundation (`platform-security-core`, `vps-provisioning-base`, `vps-provisioning-hardening-2a`, `vps-provisioning-hardening-2b` — all ARCHIVED + verified). Reads the product roadmap (engram `sdd/product-roadmap/explore`) and the de-risk spikes (engram `sdd/product-roadmap/derisk-spikes`).
**First product slice**: P0 is the first client-facing slice on top of the done foundation. It depends on nothing and unblocks P1 (the generator).

---

## Why (the problem)

The foundation runs a hardened, homeless `aios` agent on a per-client VPS, behind the three locks (managed deny rules + guardia/camara hooks + the `--setting-sources ""` fail-closed `allow[]` gate). But **the agent does not yet know anything about the client's business**. Today the per-client workspace `/opt/osgania/client/` exists (2a HA-04) and the prompt file `/opt/osgania/platform/prompts/agent-prompt.txt` exists (2b HB-01.4) — but both are placeholders. There is **no defined, validated way for the operator to describe a client** so the platform can be populated for that client.

OSGANIA is "one VPS per client, each running a dedicated Claude Code CLI agent that knows the client's business." The piece that carries "knows the client's business" from the operator's head into the box is **a per-client input file**. That file does not exist yet, and — more importantly — there is **no contract** for it:

- **No agreed shape.** The roadmap names `intake.yaml` as the onboarding input (engram `sdd-init/osgania`), but nothing defines what fields it carries, what is required, or what is well-formed. The P1 generator cannot be built against an undefined input.
- **No safety gate before onboarding.** The future generator (P1) runs as **root** and writes into `client/` and the prompt file. Feeding it a malformed, ambiguous, or dangerous input file is the worst possible moment to discover a problem — root has already started mutating the box. There is no offline check the operator can run BEFORE that.
- **No enforced secret hygiene at the input layer.** Principle 4 ("secrets never in versioned files, repo, or conversation") is enforced today only at the OS and policy layers for the *running key*. The *onboarding input* is a brand-new file the operator authors by hand — exactly the kind of file where a token gets pasted inline "just to make it work." Nothing stops that today because the file does not exist yet; the moment it does, it needs a guard.
- **No forward-compatible structure.** App selection (DB / automation / landing / inbox), business context, and per-client wiring all eventually flow through this input. If P0 ships a narrow file and P5/P6 have to rework its shape, every earlier client's `intake.yaml` becomes a migration. The contract should be defined once, forward-looking, so later slices extend it rather than reshape it.

**Why now**: P0 is the **smallest, safest, first** product slice. It is pure **input-contract validation** — a versioned schema plus an offline validator the operator runs before onboarding. It touches **no system state**: no root, no filesystem mutation, no egress wall, no managed policy, no launch path. It is the one slice that can be built and fully tested host-side (bats + shellcheck) with **zero security surface**, and it is the hard dependency of the generator (P1). Defining the contract first means P1 is built against a *validated, stable* input instead of an improvised one — and it lets the secret-hygiene and forward-compatibility decisions land at the cheapest possible point, before any code consumes the file.

---

## What changes (capability description)

This slice delivers two artifacts and nothing else:

1. **A versioned `intake.yaml` input contract (a schema).** A documented, versioned description of the per-client onboarding input. The operator authors one `intake.yaml` per client to describe that client's business and chosen apps. The contract is the single source of truth for what a well-formed intake looks like; the P1 generator will consume exactly this shape.

2. **An offline `intake.yaml` validator.** A host-safe tool the operator runs against a candidate `intake.yaml` BEFORE onboarding. It answers one question: *"is this input well-formed, complete, and safe to feed to the (root-run) generator?"* It reads the file, validates it against the contract, and exits 0 (valid) or non-zero (invalid) with a clear, line-or-field-oriented reason. It **never writes anything** — pure read-and-judge.

### The `intake.yaml` shape (requirements-level — the WHAT, not the full field list)

The contract models four parts. (Exact field names, types, and the schema mechanism are for `sdd-spec` / `sdd-design`; this proposal fixes the *shape and rules*.)

| Part | What it carries | Decision baked in |
|------|-----------------|-------------------|
| **Typed business core** | Structured, machine-meaningful fields about the client (e.g. sector, products/services, goals, tone). A small, validated set the generator can branch on. | **HYBRID model, part 1.** Typed so the contract can enforce presence/format and the generator can render predictably. |
| **Free-form context corpus** | An **opaque markdown blob** the operator authors — the rich, prose description of the business that does not fit typed fields. | **HYBRID model, part 2.** Validated as *present and well-formed text*, NOT parsed for meaning. The generator (P1) renders both core + corpus into `client/` context docs. |
| **App selection** | A selection over the app menu — **DB / automation / landing / inbox** — declaring which apps this client gets. | **Forward-looking, in the schema NOW.** The apps are built later (P5/P6) and the first client may run brain-only (empty/none selection MUST be valid), but the menu lives in the contract today so it is not reworked when apps land. |
| **Secret references** | Pointers to secrets by key (resolving to `/etc/osgania/secrets/<key>`), **never the secret values themselves.** | **Hard security rule (below).** The contract models a *reference*; an inlined value is a validation FAILURE. |

### Hard rules the contract and validator MUST encode

- **No inlined secrets — fail closed.** The validator MUST **reject** any `intake.yaml` that inlines a secret value (a token, password, API key, etc.). Secrets appear ONLY as references/pointers into `/etc/osgania/secrets/<key>` — never as literal values in the versioned file. This is non-negotiable (Principle 4) and is the validator's most important rejection.
- **No `allow[]` / permissions field — ever.** The reviewed `allow[]` is **100% operator-controlled** and lives in the root-owned `/opt/osgania/platform/agent-settings.json` behind 2b's `--setting-sources ""` fail-closed gate (HB-03.7). The `intake.yaml` contract **MUST NOT contain any `allow[]`, permissions, or capability-grant field.** This is a **hard non-goal**: putting permissions in a client-supplied, operator-authored input would re-open the exact self-escalation surface that 2b closed. The agent's authority stays defined exclusively in the root-owned platform file, never derivable from intake.
- **Re-runnable + idempotent input.** `intake.yaml` is a **re-usable** input validated on **every** (re-)run, not a one-shot. The contract MUST support client updates — adding an app, changing context — so re-validating an evolved file is the normal path (mirrors `provision.sh` R11 idempotency). The validator is deterministic: same input → same verdict.
- **The file is operator-held, never agent-readable.** `intake.yaml` is held by the operator. The contract MUST state that it is **never committed to the repo** and **never stored under `/opt/osgania/client/`** (which is agent-readable, aios:aios 0700). It is an operator-side input, not part of the box's running state. (P1 will read it as root from an operator-controlled path and render *derived, non-secret* docs into `client/` — but the raw `intake.yaml` itself does not live there.)

### Where this plugs into the proven seam

The platform already reserves the injection points P0 feeds: `/opt/osgania/client/` (the agent's writable workspace, 2a HA-04) is where P1 will render the *derived* context docs; `/opt/osgania/platform/prompts/agent-prompt.txt` (root-owned, 2b HB-01.4) is where P1 will render the *derived* prompt; the reviewed `allow[]` stays in `/opt/osgania/platform/agent-settings.json` (root-owned, 2b). **P0 produces none of these** — it defines and validates the *input* the P1 generator will later turn into them. The foundation is DONE and is NOT re-proposed here.

---

## Out of scope (explicit non-goals)

P0 is deliberately the thinnest possible slice. The following are NOT in this change:

- **The onboarding generator (P1).** Reading a validated `intake.yaml`, rendering `client/` context docs, rendering the per-client prompt, populating connections — ALL deferred to P1. P0 defines and validates the *input*; it does not consume it to produce anything.
- **The apps (P5 / P6).** Building DB / automation / landing / inbox, deploying via Coolify, wiring MCP servers — deferred. P0 only models the *selection menu* in the schema; it builds no app and wires no token.
- **`allow[]` / permissions / capability grants — categorically excluded from the schema (hard non-goal).** These remain 100% operator-controlled in the root-owned platform file behind 2b's fail-closed gate. Never in `intake.yaml`, never derived from it.
- **Anything touching root, the egress wall, managed policy, or the launch path.** P0 runs no privileged code, mutates no filesystem, touches no nftables ruleset, edits no `managed-settings.json` / `agent-settings.json`, and changes no systemd unit or wrapper. **Zero security surface; HOST-SAFE.**
- **Secret delivery mechanism.** *How* a token actually lands in `/etc/osgania/secrets/<key>` (the out-of-band channel, integrity, who) is a separate roadmap gap (engram explore: missing slice "secrets-delivery"). P0 only models the *reference* and rejects inlined values; it does not move or resolve secrets.
- **Per-app token storage / injection (P4) and MCP wiring (P3 / P6).** The schema names which apps a client gets; it does not store, inject, or scope any token.
- **The OD-001 runtime decision (Python vs Node).** P0 does not resolve it. The validator's runtime is tied to it (see Risks / Open questions) but P0 frames the dependency without deciding it.

---

## Non-negotiable principles referenced (config.yaml)

| Principle | How P0 honors it |
|-----------|------------------|
| Secrets never in versioned files, repo, or conversation | The contract models secrets ONLY as references into `/etc/osgania/secrets/<key>`; the validator's primary rejection is an inlined secret value. The contract states `intake.yaml` is never committed and never stored under agent-readable `client/`. |
| Client-facing agent has NO root and is read-only by default | P0 runs no privileged code and produces nothing the agent reads. The validator is an operator-side, host-safe, read-only tool. The agent never sees `intake.yaml`. |
| Operator policy cannot be overridden by the client/agent | The contract categorically **excludes** `allow[]` / permissions. The agent's authority stays defined only in the root-owned `agent-settings.json` behind 2b's `--setting-sources ""` gate; nothing in intake can widen it. |
| Per-client isolation (one VPS, one key, one workspace per client) | One `intake.yaml` describes one client; the schema is per-client by construction. Secret references resolve to that box's `/etc/osgania/secrets/`. |
| Verify product facts against official docs; never guess | The schema-mechanism choice (JSON Schema vs language-native) is framed for design, not guessed; the secret-reference / `client/`-placement facts are grounded in the verified 2a/2b seam. |
| Re-runnable, idempotent provisioning | `intake.yaml` is validated on every (re-)run and supports client updates (new app, changed context); the validator is deterministic (same input → same verdict), mirroring `provision.sh` R11. |

Brain-vs-apps separation / MCP least-privilege is **named** by the app-selection menu but **not exercised** by P0 (no wiring), and not regressed.

---

## Schema-mechanism framing — DESIGN QUESTION (do NOT decide here)

The contract needs a concrete validation mechanism, and there is a real fork with a downstream dependency. This proposal **frames** it; `sdd-design` decides it.

- **Option A — language-agnostic schema (e.g. JSON Schema for YAML).** The contract is expressed as a standalone schema document, validatable by any conforming validator and **drivable directly from bats** (validate the fixture as a subprocess, assert exit code). Decouples the *contract* from the P1 generator's runtime: the schema is the source of truth, and either a Python or a Node validator can enforce it. Plays well with the TIER1 bats+shellcheck strategy.
- **Option B — language-native validation.** The contract lives as validation code in the same runtime the P1 generator will use (Python or Node), sharing types/models with the generator. Tighter coupling, less duplication later — but it **binds P0 to OD-001 before OD-001 is resolved**.

**The dependency to flag, not resolve:** OD-001 (Python vs Node onboarding-generator runtime) is **resolved in P1, not here** (engram `sdd-init/osgania`; roadmap lean = provisional Python). The validator's runtime is tied to that choice. Option A *minimizes* the coupling (the schema is language-agnostic; only the thin bats glue / validator binary touches a runtime); Option B *maximizes* it. **Design MUST choose** the mechanism and state explicitly how it relates to OD-001 — ideally keeping P0 enforceable without prematurely committing the generator's language. The proposal *leans* Option A precisely because it keeps the contract stable across the OD-001 decision and is cleanest to drive from bats, but does not decide it.

---

## Rollback plan (trivial — additive, no system state)

P0 mutates **no** system state. It adds a schema document, an offline validator, and tests to the **repo only**. There is nothing on any VPS to undo.

- **To roll back**: revert the repo change (remove the schema, validator, and tests). No box is touched; no `intake.yaml` on any operator machine is affected (it is operator-held data the operator owns).
- **MUST NOT during rollback**: nothing privileged is involved — there is no managed policy, no `allow[]`, no secret, no audit arming, and no systemd unit to preserve, because P0 created none of them.
- **Forward-fix path (preferred)**: because the validator is pure and deterministic, fixing a contract bug is a normal additive repo edit + re-run of the host-safe tests. Full revert is the escape hatch; an additive fix is the day-to-day path.

This is the cheapest rollback profile in the whole roadmap, by design: P0 has no security surface to unwind.

---

## Risks and mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Inlined secret slips past the validator** → a token lands in a versioned/operator file (Principle 4 violation) | **Critical** | The no-inlined-secret rejection is the validator's primary, load-bearing rule, exercised by a dedicated invalid fixture (a secret-looking value where only a reference is allowed) asserting a non-zero exit + clear reason. Spec MUST encode it as a normative requirement and a TDD guard, not a comment. |
| **An `allow[]` / permissions field creeps into the schema** (now or in a later extension) → re-opens 2b's self-escalation surface | **Critical** | The contract categorically forbids any permissions/capability field (hard non-goal). A structural test asserts the schema has no such field; design carries an explicit "intake MUST NOT grant authority" guard. The agent's authority stays solely in the root-owned `agent-settings.json`. |
| **Binding P0 to OD-001 prematurely** → the validator's runtime forces the generator's language before P1 decides it | High | Frame the schema-mechanism fork for design (Option A leans language-agnostic to minimize coupling); do NOT resolve OD-001 in P0. The schema stays the source of truth regardless of which runtime P1 picks. |
| **A too-narrow schema** → P5/P6 must reshape it, turning every earlier client's `intake.yaml` into a migration | Medium | App-selection menu (DB/automation/landing/inbox) is in the schema NOW, forward-looking; the hybrid model (typed core + opaque corpus) absorbs business detail without per-field churn. Empty/brain-only selection is valid. |
| **Schema too rigid for client updates** → re-validating an evolved file (new app, changed context) fails the normal re-run path | Medium | Contract is explicitly re-runnable/idempotent; validator is deterministic; spec includes a "client update" fixture (a valid evolved intake) to prove re-validation. |
| **Operator stores `intake.yaml` under `client/`** → the agent can read the raw operator input | Medium | Contract states `intake.yaml` is operator-held, never committed, never placed under agent-readable `client/`. (Enforcement of *placement* is P1's root-run job; P0 states the constraint and the validator does not require the file to live anywhere agent-readable.) |
| **Markdown corpus mis-validated** (parsed for meaning, or rejected for benign content) | Low | The corpus is validated as *present + well-formed text*, treated as an opaque blob — NOT parsed for semantics. Fixtures cover a rich-but-valid corpus and a missing/empty one. |
| **bash glue around the validator has a shell bug** | Low | `shellcheck` on all bash glue (canonical lint per `sdd-init`); host-safe and pure, no root path to get wrong. |

**Note on lockout / security surface**: P0 touches **no firewall, no SSH, no managed policy, no launch path, no root**. None of the foundation's lockout or escalation risks apply — there is no privileged operation in this slice. This is the explicit design intent: a zero-security-surface first slice.

---

## Testing strategy

Pure host-safe TDD on macOS, now — no Linux, no root, no systemd, no VPS. (`sdd-init` canonical: `bats tests/`, `shellcheck scripts/**/*.sh`. Reminder: `brew install bats-core shellcheck` before first `sdd-apply`.)

- **Validator behavior — bats against fixtures, host-side.** A `valid/` fixture set (a complete intake; a brain-only/empty-app-selection intake; an evolved "client update" intake with a new app + changed context) asserts exit 0. An `invalid/` fixture set asserts non-zero exit + a clear reason, covering at minimum: **the secret-inlining rejection** (load-bearing), a missing required core field, a malformed app selection (value outside the DB/automation/landing/inbox menu), a malformed/missing corpus, and — as a structural guard — **a fixture containing an `allow[]`/permissions field, asserting the schema rejects it** (the hard non-goal made testable).
- **Schema-driven, runtime-light.** If design picks Option A (language-agnostic schema), bats drives the validator as a subprocess and asserts exit codes — keeping the test harness independent of the eventual OD-001 runtime. If Option B, the validator is still driven as a subprocess from bats (same TIER1 pattern the foundation uses for the provisioner).
- **Bash glue — `shellcheck`-clean.** Any bash wrapper around the validator (invocation, fixture loops, exit-code plumbing) MUST pass `shellcheck -s bash` with no warnings.
- **No Linux-deferred tier.** Unlike 2a/2b, P0 has **nothing** that needs a disposable VPS, root, or a real key — it is entirely host-safe. This is a feature of the slice, not a gap.

A `--check`-style dry run is the validator's *whole purpose*; there is no separate dry-run mode to add.

---

## Success criteria (testable)

1. A versioned `intake.yaml` contract document exists in the repo, defining the four parts: typed business core, opaque markdown corpus, app-selection menu (DB/automation/landing/inbox), and secret references — and is explicitly versioned.
2. The contract document contains **no** `allow[]`, permissions, or capability field, and states that explicitly as a non-goal.
3. An offline validator exists that, given a valid `intake.yaml` fixture, exits 0 and writes nothing.
4. Given an `intake.yaml` that **inlines a secret value**, the validator exits non-zero with a reason naming the inlined-secret problem. *(Load-bearing.)*
5. Given an `intake.yaml` that contains an `allow[]`/permissions field, the validator exits non-zero. *(Hard non-goal, made testable.)*
6. Given a brain-only intake (empty/none app selection), the validator exits 0 (forward-compatible: apps not built yet).
7. Given an evolved "client update" intake (new app + changed context vs a prior valid one), the validator exits 0 (re-runnable / idempotent input).
8. The validator is deterministic: the same input yields the same verdict across runs.
9. All bash glue passes `shellcheck -s bash` with no warnings; the validator + fixtures run green under `bats tests/` host-side with no root, no systemd, no VPS.
10. The change adds repo artifacts only — no VPS state, no managed policy, no `allow[]`, no secret, no systemd unit is created or modified by P0.

---

## Open questions for design

1. **Schema mechanism (the main fork)** — JSON Schema / language-agnostic (Option A, leaned) vs language-native (Option B). Design MUST choose and state how the choice relates to OD-001, ideally keeping P0 enforceable without committing the generator's language.
2. **"Inlined secret" detection rule** — define the concrete, testable rule that distinguishes a *secret reference* (a pointer into `/etc/osgania/secrets/<key>`) from an *inlined value*. What patterns count as "a secret value" (entropy heuristics? a forbidden-key-shape allowlist? structural — "this field must be a reference, never a literal"?). The structural approach (designated fields accept ONLY references) is likely cleanest and lowest false-positive; design ratifies it.
3. **Typed core field set** — the exact required vs optional core fields (sector, products/services, goals, tone, …), their types, and which are mandatory for a valid intake. (Proposal fixes the *categories*; design fixes the *fields*.)
4. **App-selection representation** — how the DB/automation/landing/inbox menu is modeled (list of enums? per-app object?) so it cleanly supports brain-only today and per-app config later (P4/P5) without a reshape.
5. **Corpus validation depth** — exactly what "well-formed markdown text" means for the opaque corpus (present + non-empty + valid UTF-8? a size bound?) without parsing it for meaning.
6. **Versioning scheme** — how the contract version is declared in `intake.yaml` and how the validator handles an unknown/future version (reject? warn?), so client updates across contract revisions are predictable.

---

## Next step

Run `sdd-spec` (encode the contract end-state and the validator's verdicts as Given/When/Then with RFC-2119 keywords, including the load-bearing inlined-secret and no-`allow[]` rejections and the valid/invalid fixture matrix) and `sdd-design` (resolve the 6 open questions above — chiefly the schema mechanism and the inlined-secret detection rule — with ADRs and the OD-001 dependency note). These two can run in parallel from this proposal.
