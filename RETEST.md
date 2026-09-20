# Consequence Boundary Completeness — RETEST lab

This is deliberately **not** a new authorization engine. It tests one narrower hypothesis:

> Can repository analysis discover an alternate execution path that reaches the same protected real-world consequence without crossing the expected enforcement boundary?

## Property under test

`production_deploy` must cross `approval:P`.

The fixture contains several paths to the same consequence:

1. MCP workflow dispatch after `approval:P` (guarded)
2. REST workflow dispatch (bypass)
3. `subprocess -> gh workflow run` (bypass)
4. `git push -> push-triggered workflow` (bypass)
5. local helper -> shell -> `gh workflow run` (multi-step bypass)

The analyzer builds a small effect graph across Python and GitHub Actions and then searches for a path to `consequence:production_deploy` that does not include `boundary:approval:P`.

Outcomes are intentionally limited to:

- `COUNTEREXAMPLE_FOUND`
- `COVERED_WITHIN_MODEL`
- `UNKNOWN`

`COVERED_WITHIN_MODEL` is **not** a claim of completeness.

## Run

```bash
python -m retest_lab.analyzer fixtures
```

A counterexample exits with code `1`, suitable for CI.

Run tests:

```bash
python -m unittest tests.test_retest_lab -v
```

## RETEST gate

Continue only if the prototype can reliably:

- connect different mechanisms to the same consequence;
- find multi-step bypass paths, not only suspicious lines;
- identify the missing expected boundary;
- fail CI when a PR introduces a new bypass path;
- keep false positives low enough to remain enabled.

If it degrades into generic shell/HTTP/MCP scanning, KILL the idea.
