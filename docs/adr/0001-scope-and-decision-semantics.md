# ADR-0001: Scope and Decision Semantics for agent-action-guard v0.1

## 1. Status and context

**Status:** Accepted.

agent-action-guard is a deterministic local policy gate for proposed AI-agent
actions. It answers: "What is this agent allowed to do, and what evidence
supports that decision?" It evaluates proposals only. It never executes an
action.

This ADR is the **sole normative authority** for v0.1. If any other document,
comment, or code in this repository disagrees with this ADR, this ADR wins.

The design commits to exact-match semantics, effect-priority conflict
resolution, and fail-closed defaults because a policy gate must be auditable,
order-independent, and byte-reproducible. Every rule below is numbered
(N1–N39) so tests and reviews can cite it precisely.

## 2. String semantics

- **N1.** All string comparison is case-sensitive, with no trimming, no case
  folding, and no Unicode normalization.
- **N2.** String equality is equality of the parsed Unicode code-point
  sequence.
- **N3.** Any input string containing an unpaired surrogate code point makes
  the input invalid (exit 3).
- **N4.** Duplicate `rule_id` detection uses the same exact equality as N2.

## 3. Input schemas

### 3.1 General validity

- **N5.** Both input files must decode as UTF-8 and must not begin with a
  UTF-8 BOM (bytes `EF BB BF`). Undecodable bytes, or a BOM at the start of
  either the action file or the policy file, make the input invalid
  (exit 3, stdout exactly empty per N37).
- **N6.** Duplicate member names within any JSON object make the input
  invalid (exit 3); parser-default last-wins behavior is forbidden.
- **N7.** Unknown or extra fields in the action object, policy object, any
  rule object, or any match object make the input invalid (exit 3).

### 3.2 Action proposal

- **N8.** The action object must contain exactly: `action_id`, `actor`,
  `tool`, `operation`, `resource` (each a non-empty string) and `side_effect`
  (exactly JSON `true`, `false`, or `null`). No coercion of any kind.

### 3.3 Policy document

- **N9.** The policy object must contain exactly `policy_id` (non-empty
  string) and `rules` (JSON array).
- **N10.** An empty `rules` array is valid; every evaluation against it
  defaults to DENY.
- **N11.** Every rule must contain exactly `rule_id` (non-empty string),
  `effect` (exactly `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`), and `match`
  (JSON object).
- **N12.** Duplicate `rule_id` values (per N4) make the policy invalid
  (exit 3).
- **N13.** A match object may contain any subset of: `actor`, `tool`,
  `operation`, `resource`, `side_effect` — and nothing else (per N7).
- **N14.** Match values for `actor`, `tool`, `operation`, `resource` must be
  non-empty strings; empty strings and wrong JSON types are invalid (exit 3).
- **N15.** A match `side_effect` value must be exactly JSON `true`, `false`,
  or `null`.
- **N16.** An empty match object `{}` is valid and field-matches every action.

## 4. Matching semantics

- **N17.** A rule field-matches an action when every member present in its
  match object equals the corresponding action field exactly (N1–N2 for
  strings; identity for `true`/`false`/`null`).
- **N18.** Members omitted from a match object are unconstrained.
- **N19.** `"side_effect": null` present in a match object is a constraint
  matching only actions whose `side_effect` is `null`; it is distinct from
  omitting the member.
- **N20.** There is no regex, glob, expression language, executable policy,
  or implicit coercion.

## 5. Decision procedure

- **N21.** If any field-matching rule has effect DENY, the decision is DENY
  (`matched_deny`).
- **N22.** Otherwise, if any field-matching rule has effect REQUIRE_APPROVAL,
  the decision is REQUIRE_APPROVAL (`matched_require_approval`).
- **N23.** Otherwise, if any field-matching ALLOW rule is *eligible*, the
  decision is ALLOW (`matched_eligible_allow`).
- **N24.** Otherwise the decision is DENY with `default_deny_used` true —
  reason `default_deny_allow_ineligible` if at least one ALLOW rule
  field-matched but none was eligible, else `default_deny_no_match`.
- **N25.** Eligibility applies only to ALLOW rules: when the action's
  `side_effect` is `true` or `null`, an ALLOW rule is eligible only if its
  match object explicitly contains `side_effect` equal to that same value.
  When the action's `side_effect` is `false`, every field-matching ALLOW rule
  is eligible. An ALLOW rule explicitly matching `side_effect: null` may
  authorize an action whose `side_effect` is `null`. A broad ALLOW rule that
  omits `side_effect` must not silently authorize a side-effecting or
  unknown-side-effect action.
- **N26.** The order of the `rules` array has no effect on the decision or on
  the output bytes.

Cross-reference: `default_deny_used` is exactly true when the procedure
reaches N24; see N39.

## 6. Decision record

- **N27.** Exactly one decision record is written to stdout, as one compact
  UTF-8 JSON object: no BOM, no insignificant whitespace, separators exactly
  `,` and `:`, non-ASCII characters emitted directly (not ASCII-escaped),
  followed by exactly one trailing LF byte.
- **N28.** Member order is fixed and never derived from generic map ordering:
  `action_id`, `policy_id`, `decision`, `matched_rule_ids`,
  `decisive_reason`, `default_deny_used`.
- **N29.** `matched_rule_ids` contains exactly the members `DENY`,
  `REQUIRE_APPROVAL`, `ALLOW`, in that order, each always present, each an
  array (possibly empty) of the rule IDs that field-matched with that effect.
- **N30.** The ALLOW group includes ALLOW rules that field-matched but were
  ineligible under N25; eligibility affects only `decision` and
  `decisive_reason`, never group membership.
- **N31.** Rule IDs within each group are sorted lexicographically by Unicode
  code point.
- **N32.** `decisive_reason` is exactly one of: `matched_deny`,
  `matched_require_approval`, `matched_eligible_allow`,
  `default_deny_no_match`, `default_deny_allow_ineligible`.
- **N33.** Parsed-value-identical inputs produce byte-identical output; input
  member order, whitespace, and equivalent JSON escape choices must not
  affect output bytes.
- **N39.** `default_deny_used` is `true` if and only if the decision
  procedure reaches N24 — that is, exactly when `decisive_reason` is
  `default_deny_no_match` or `default_deny_allow_ineligible`. It is `false`
  for `matched_deny`, `matched_require_approval`, and
  `matched_eligible_allow`. Equivalently, `default_deny_used` is fully
  determined by `decisive_reason`, and any record violating this bijection
  is a defect.

The structural shape of the record (formatted here only for documentation;
the serialized form is compact on one line per N27):

```json
{
  "action_id": "<string>",
  "policy_id": "<string>",
  "decision": "<ALLOW|DENY|REQUIRE_APPROVAL>",
  "matched_rule_ids": {
    "DENY": ["<sorted rule IDs>"],
    "REQUIRE_APPROVAL": ["<sorted rule IDs>"],
    "ALLOW": ["<sorted rule IDs>"]
  },
  "decisive_reason": "<reason code>",
  "default_deny_used": false
}
```

## 7. CLI and exit-code contract

- **N34.** Invocation:
  `python -m agent_action_guard evaluate --action <action.json> --policy <policy.json>`.
- **N35.** Exit 0 means a valid decision record was produced, regardless of
  ALLOW/DENY/REQUIRE_APPROVAL. **Exit 0 does not mean permission was
  granted**; the `decision` field is the only authority.
- **N36.** Exit 1: unexpected internal error. Exit 2: CLI argument or usage
  error only. Exit 3: file access, decoding, JSON syntax, or semantic input
  validation error — including missing, unreadable, non-UTF-8,
  BOM-prefixed, and syntactically invalid files.
- **N37.** On every non-zero exit, stdout is exactly empty; no partial
  decision record is ever emitted; diagnostics go to stderr and are outside
  the determinism contract.
- **N38.** The tool never executes, retries, persists, or transmits anything;
  its only outputs are the stdout record, stderr diagnostics, and the exit
  code.

## 8. Consequences and rejected alternatives

- **First-match rule ordering** — rejected: order-dependent semantics make
  policies fragile under refactoring and defeat shuffle-invariance testing.
- **Regex, glob, or expression-language matching** — rejected for v0.1: it
  reintroduces ambiguity and an execution surface into the policy itself.
- **Per-decision exit codes** — rejected: exit codes signal evaluation
  success, not permission; conflating them invites `guard && act` misuse.
  The docs must state loudly that exit 0 conveys no permission (N35).
- **`schema_version` field in inputs or outputs** — rejected for v0.1: this
  ADR is the version authority (see §9).
- **Lenient parsing (duplicate keys, unknown fields, coercion, BOM
  tolerance)** — rejected: a policy gate must fail closed and loudly; silent
  last-wins or silent field-dropping can invert a security decision.
- **Importing a policy engine such as OPA** — rejected: v0.1 must be small
  enough to audit line by line, with stdlib-only behavior.

Consequences accepted: policies are verbose (no wildcards beyond field
omission); authors must explicitly write `"side_effect": true` or
`"side_effect": null` in ALLOW rules to authorize such actions; unmatched
actions are denied by default.

## 9. Version authority

There is no `schema_version` field in v0.1 inputs or outputs. This ADR is the
version authority for v0.1. Any semantic change requires a new ADR that
supersedes this one.
