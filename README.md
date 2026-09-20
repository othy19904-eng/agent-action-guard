# agent-action-guard

agent-action-guard is a deterministic local policy gate for proposed
AI-agent actions: it evaluates one action proposal against one policy
document and emits one canonical JSON decision record.

> **It evaluates proposals only. It never executes actions.**
>
> **Exit code 0 means a decision record was produced — not that
> permission was granted.** The JSON `decision` field is the only
> authority. Never write `agent-action-guard && do-the-thing`.

## The problem

Systems that let AI agents act need an auditable answer to the question
"what is this agent allowed to do, and what evidence supports that
decision?" before anything happens. That answer must be boring: the same
inputs must produce the same bytes, no matter how the policy file is
ordered, whitespaced, or escaped, and anything malformed must fail
closed rather than fail open.

v0.1 is deliberately small: a single offline evaluation of one action
JSON file against one policy JSON file, producing one decision record on
stdout. The complete semantics are fixed by
[ADR-0001](docs/adr/0001-scope-and-decision-semantics.md), the sole
normative authority for this version (rules N1–N39). If anything in this
README appears to disagree with ADR-0001, ADR-0001 wins.

## Core guarantees

- **Strict fail-closed validation** — unknown fields, duplicate JSON
  members, duplicate rule IDs, wrong types, empty strings, non-UTF-8
  bytes, a UTF-8 BOM, and unpaired surrogates all reject the input
  (exit 3) instead of being silently tolerated.
- **Exact code-point matching** — case-sensitive, no trimming, no case
  folding, no Unicode normalization, no regex, no globs, no coercion.
  Omitted match members are unconstrained; `"side_effect": null` present
  in a match is distinct from omitting it.
- **Effect precedence** — DENY > REQUIRE_APPROVAL > eligible ALLOW, then
  default DENY. No first-match ordering exists.
- **Side-effect eligibility safeguard** — an ALLOW rule that omits
  `side_effect` can never authorize an action whose `side_effect` is
  `true` or `null`; authors must write the value explicitly to authorize
  side-effecting or unknown-side-effect actions.
- **Rule-order independence** — reordering the policy's `rules` array
  changes neither the decision nor a single output byte.
- **Canonical byte-reproducible JSON** — compact separators, fixed member
  order, code-point-sorted rule-ID groups, direct UTF-8 (no ASCII
  escaping of non-ASCII), no BOM, exactly one trailing LF.
- **No network, no database, no LLM, no persistence, no execution** — the
  only outputs are the stdout record, stderr diagnostics, and the exit
  code.

Runs on the Python 3.10+ standard library. No dependencies.

## Quick start

From the repository root:

```sh
python3 -m agent_action_guard evaluate --action action.json --policy policy.json
```

### action.json

```json
{
  "action_id": "act-2026-001",
  "actor": "agent-1",
  "tool": "fs",
  "operation": "read",
  "resource": "/data/report.txt",
  "side_effect": false
}
```

All six fields are required; `side_effect` must be exactly `true`,
`false`, or `null`.

### policy.json

```json
{
  "policy_id": "policy-baseline",
  "rules": [
    {
      "rule_id": "allow-fs-read",
      "effect": "ALLOW",
      "match": {
        "tool": "fs",
        "operation": "read",
        "side_effect": false
      }
    }
  ]
}
```

A `match` object may constrain any subset of `actor`, `tool`,
`operation`, `resource`, and `side_effect`; an empty `match` object
field-matches every action.

### Output

One compact line on stdout, terminated by a single LF (shown wrapped
here for readability only — the real output has no inner whitespace or
line breaks):

```json
{"action_id":"act-2026-001","policy_id":"policy-baseline","decision":"ALLOW","matched_rule_ids":{"DENY":[],"REQUIRE_APPROVAL":[],"ALLOW":["allow-fs-read"]},"decisive_reason":"matched_eligible_allow","default_deny_used":false}
```

## Decision values

| `decision` | Meaning |
|---|---|
| `ALLOW` | An eligible ALLOW rule field-matched and nothing stronger did. |
| `DENY` | A DENY rule field-matched, or the default deny applied. |
| `REQUIRE_APPROVAL` | A REQUIRE_APPROVAL rule field-matched and no DENY did. |

## Decisive reason codes

| `decisive_reason` | `default_deny_used` | Meaning |
|---|---|---|
| `matched_deny` | `false` | At least one DENY rule field-matched. |
| `matched_require_approval` | `false` | No DENY matched; a REQUIRE_APPROVAL rule did. |
| `matched_eligible_allow` | `false` | No DENY or REQUIRE_APPROVAL matched; an eligible ALLOW did. |
| `default_deny_no_match` | `true` | No rule field-matched at all. |
| `default_deny_allow_ineligible` | `true` | Only ALLOW rules field-matched, and none was eligible. |

`default_deny_used` is fully determined by `decisive_reason`: it is
`true` exactly for the two `default_deny_*` codes.

`matched_rule_ids` always contains all three groups (`DENY`,
`REQUIRE_APPROVAL`, `ALLOW`), each a possibly-empty array of every rule
ID that field-matched with that effect, sorted by Unicode code point.
Ineligible ALLOW rules stay listed in the `ALLOW` group; eligibility
affects only `decision` and `decisive_reason`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | A complete decision record was written to stdout — for ALLOW, DENY, and REQUIRE_APPROVAL alike. **Not permission.** |
| 1 | Unexpected internal error. |
| 2 | CLI argument or usage error only. |
| 3 | File access, decoding, JSON syntax, or input validation error — missing, unreadable, non-UTF-8, BOM-prefixed, malformed, or schema-invalid files. |

On every non-zero exit, stdout is exactly empty; diagnostics go to
stderr and their wording is not a stable contract.

## Experimental consequence-path scanner

This branch also contains the first usable MVP of the
**Consequence Boundary Completeness** work.

It answers a narrower question than the policy evaluator above:

> From this repository entrypoint, can the current model trace a path to this
> GitHub workflow consequence?

Run it from the repository root:

```sh
python -m retest_lab scan --repo . --root main --target deploy.yml
```

The `function:` and `workflow:` prefixes are optional. The equivalent
explicit form is:

```sh
python -m retest_lab scan \
  --repo . \
  --root function:main \
  --target workflow:deploy.yml
```

Example output:

```text
PROVEN
root:   function:main
target: workflow:deploy.yml
path:
  function:main
  -> effect:shell.exec  [invokes; certain; app.py:42]
  -> workflow:deploy.yml  [gh_workflow_dispatch; certain; app.py:42]
```

Machine-readable output is available with `--json`:

```sh
python -m retest_lab scan \
  --repo . \
  --root main \
  --target deploy.yml \
  --json
```

The scanner returns one of three statuses:

| Status | Meaning |
|---|---|
| `PROVEN` | A modeled path from the requested root to target exists and every edge on that path is supported as certain by the bounded extractor. |
| `POSSIBLE` | A modeled path exists, but at least one edge depends on unresolved runtime state or incomplete static information. |
| `UNKNOWN` | The current model did not find a path. This does **not** mean the path is impossible. |

**Important:** `PROVEN` is a statement about the returned modeled path, not a
claim that the repository has been analyzed completely. `POSSIBLE` must never
be promoted to a proven bypass, and `UNKNOWN` must never be interpreted as a
safety guarantee.

The current pinned real-world acceptance corpus contains 25 cases:
15 known-positive paths and 10 negative controls. The current gate requires
zero missed positives and zero certain or possible false positives before CI
passes.

## Development

Run the full test suite from the repository root:

```sh
python3 -m unittest discover -s tests -t . -v
```

The suite currently contains 113 tests covering the model, the strict
loader, the pure decision engine, the canonical serializer, and the CLI
contract — including golden-byte and shuffle-invariance checks.

## Documentation

- [ADR-0001: Scope and decision semantics](docs/adr/0001-scope-and-decision-semantics.md) — the sole normative authority (N1–N39).
- [Problem statement](docs/problem-statement.md)
- [Implementation plan](docs/implementation-plan.md)

## Non-goals in v0.1

- No execution, retrying, persistence, or transmission of any action.
- No regex, glob, or expression-language matching.
- No policy composition, batch evaluation, or stdin input.
- No `schema_version` field — ADR-0001 is the version authority; any
  semantic change requires a superseding ADR.
- No per-decision exit codes: exit status signals evaluation success
  only, never the verdict.
- No packaging, external integrations, or services of any kind.
