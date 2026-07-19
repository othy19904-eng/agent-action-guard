# agent-action-guard — Problem Statement (v0.1)

This document is descriptive. The single normative contract is
[ADR-0001](adr/0001-scope-and-decision-semantics.md). If any wording here
disagrees with ADR-0001, ADR-0001 wins.

## 1. Problem

AI agents propose actions — tool calls, file operations, API invocations —
faster than humans can review them, and the components that execute those
actions rarely ask whether they should. Teams need a gate that sits between
"the agent proposed this" and "something executed this": a check that is
local, deterministic, and auditable, whose answer can be reproduced
byte-for-byte after the fact and attributed to specific policy rules.

Existing policy engines are powerful but bring expression languages, network
services, or nondeterministic evaluation surfaces that are themselves hard to
audit. The gap is a minimal gate whose entire behavior fits in one document.

## 2. What agent-action-guard is

agent-action-guard is a deterministic local policy gate for proposed AI-agent
actions. It evaluates exactly one local JSON action proposal against exactly
one local JSON policy document and emits one canonical JSON decision record.

The tool evaluates proposals only. **It never executes an action.**

## 3. What it answers

> "What is this agent allowed to do, and what evidence supports that
> decision?"

Every decision record identifies the action, the policy, the final decision,
every rule that matched (grouped by effect), the decisive reason, and whether
the fail-closed default was used.

## 4. What it is explicitly not (v0.1 non-goals)

- no action execution
- no automatic retry
- no human-approval workflow execution
- no network calls
- no database or persistence
- no LLM calls
- no web UI or service
- no authentication system
- no cryptographic signing
- no policy language beyond exact field matching
- no importing policy engines such as OPA
- no idempotency registry yet
- no mutable state

None of these may enter v0.1 through implementation convenience.

## 5. v0.1 boundary summary

Each item below is normative only in the form given in ADR-0001 (rule numbers
in parentheses).

- **Inputs:** one action proposal file and one policy file, strict UTF-8
  without BOM, strictly validated — unknown fields, duplicate JSON member
  names, and unpaired surrogates are rejected (N5–N16).
- **Matching:** exact code-point equality only; omitted match fields are
  unconstrained; `"side_effect": null` present is distinct from omitted
  (N17–N20).
- **Decision vocabulary:** exactly `ALLOW`, `DENY`, `REQUIRE_APPROVAL`.
- **Conflict resolution:** DENY over REQUIRE_APPROVAL over eligible ALLOW,
  otherwise default DENY; rule order never matters (N21–N26).
- **Side-effect safety invariant:** a broad ALLOW rule that omits
  `side_effect` never authorizes an action whose `side_effect` is `true` or
  `null` (N25).
- **Output:** one compact, canonical, byte-reproducible JSON decision record
  on stdout with fixed member order and exactly one trailing LF (N27–N33,
  N39).
- **CLI:**
  `python -m agent_action_guard evaluate --action <action.json> --policy <policy.json>`
  (N34).
- **Exit codes:** 0 = a decision record was produced (**not** permission);
  1 = internal error; 2 = usage error; 3 = invalid input. Stdout is exactly
  empty on every non-zero exit (N35–N38).

## 6. Definition of done for v0.1

Three testable claims, all provable from ADR-0001:

1. **Determinism:** parsed-value-identical inputs produce byte-identical
   output (N33).
2. **Order independence:** shuffling the `rules` array changes neither the
   decision nor a single output byte (N26).
3. **Fail-closed:** any action not explicitly and eligibly allowed is denied,
   with the default-deny path and its reason visible in the record (N24,
   N25, N39).
