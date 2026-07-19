# agent-action-guard — Implementation Plan (v0.1)

This document is descriptive. The single normative contract is
[ADR-0001](adr/0001-scope-and-decision-semantics.md). If any wording here
disagrees with ADR-0001, ADR-0001 wins. This plan introduces no semantics of
its own and creates no source files at this stage.

## 1. Module map and dependency direction

One Python package, five modules, standard library only. Dependencies point
strictly downward; no module imports `cli`, and `model` imports nothing:

```
cli ──▶ loader ─────▶ model
cli ──▶ engine ─────▶ model
cli ──▶ serializer ─▶ model
```

- **`model`** — frozen dataclasses `Action`, `Rule`, `Policy`, `Decision`.
  No I/O, no JSON.
- **`loader`** — bytes → validated model objects or a typed validation
  error. Sole home of JSON parsing and all strictness rules N5–N16,
  including UTF-8/BOM rejection (N5), duplicate-member rejection via a
  pair-hook parse rather than parser defaults (N6), unknown-field rejection
  (N7), and unpaired-surrogate rejection (N3).
- **`engine`** — one pure function `evaluate(action, policy) -> Decision`
  implementing N17–N26 and N39. No I/O, no JSON, no clock, no randomness;
  this purity is what makes order independence (N26) and byte determinism
  (N33) provable.
- **`serializer`** — `Decision` → canonical bytes implementing N27–N32:
  compact UTF-8, no BOM, fixed member order, sorted rule-ID groups, exactly
  one trailing LF.
- **`cli`** (`__main__`) — argument parsing, file reading, wiring,
  exit-code mapping N34–N38, stderr diagnostics. The only module with side
  effects; on any failure it writes nothing to stdout (N37).

## 2. Milestones

1. `model` dataclasses.
2. `loader` validation with the full rejection matrix (N3, N5–N16).
3. Pure `engine` (N17–N26, N39).
4. Canonical `serializer` (N27–N32).
5. `cli` wiring and exit codes (N34–N38).
6. Golden-byte and shuffle-invariance tests (N26, N33).

Each milestone lands with its tests; no milestone may weaken a normative
rule to simplify a later one.

## 3. Minimum future test categories

Categories only — no test implementations at this stage. Each cites the
rules it proves.

1. **Validation rejection matrix** — every invalid class in N3, N5–N15 exits
   3 with stdout exactly empty: missing/extra/unknown fields, empty strings,
   wrong types, bad `effect` values, duplicate `rule_id`, duplicate JSON
   member names, unpaired surrogates, non-UTF-8 bytes, malformed JSON, and a
   leading UTF-8 BOM on the action file or the policy file (including a
   BOM-plus-otherwise-valid-JSON file, which many decoders silently accept).
2. **Matching semantics** — exact case-sensitive equality with no trimming,
   folding, or normalization; omitted fields unconstrained; empty match
   object matches everything; `null`-present vs omitted `side_effect`
   (N17–N19).
3. **Conflict-resolution precedence** — DENY over REQUIRE_APPROVAL over
   ALLOW; multiple matches per effect; each matched reason code observed
   with `default_deny_used: false` (N21–N23, N39).
4. **Side-effect invariant grid** — action `side_effect` ∈ {true, false,
   null} × ALLOW match {explicit same value, explicit different value,
   omitted}; asserts `default_deny_allow_ineligible` vs
   `matched_eligible_allow` per N24–N25.
5. **Order-independence property** — shuffled `rules` arrays produce
   byte-identical output (N26).
6. **Golden-byte determinism** — checked-in expected output bytes, including
   a non-ASCII rule ID and reordered/re-whitespaced input variants
   (N27–N33); verifies compact form, fixed member order, sorted groups, no
   BOM (stream starts with `{`), exactly one trailing LF, coverage of both
   `default_deny_used` values, and the reason-code ↔ `default_deny_used`
   bijection (N39).
7. **CLI contract** — exit codes 0/1/2/3 per N35–N36; usage errors exit 2;
   file failures including BOM-bearing files exit 3; stdout exactly empty on
   all non-zero exits (N37).
8. **Default-deny paths** — empty rules array, no field match, and
   ineligible-ALLOW-only; each with the correct default-deny reason code and
   `default_deny_used: true` (N10, N24, N39).

## 4. Tooling constraints

- Python standard library only; no runtime dependencies.
- No policy-engine imports (e.g., OPA).
- No network access at build, test, or run time.
- Implementation must not rely on parser defaults where ADR-0001 forbids
  them (duplicate members, coercion, BOM tolerance).

## 5. Out-of-plan items

Everything listed under "What it is explicitly not" in the
[problem statement](problem-statement.md) §4 is out of plan. Known future
pressures — pattern matching on `resource`, `schema_version`, per-decision
exit codes, stdin input, batch evaluation, policy composition — are recorded
in ADR-0001 §8 as rejected for v0.1 and may enter only through a superseding
ADR. Nothing in this plan may expand v0.1.
