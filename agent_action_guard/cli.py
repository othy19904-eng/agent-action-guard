"""Command-line interface for agent-action-guard v0.1.

Sole home of ADR-0001 N34-N38: argument parsing, file reading, module
wiring, exit-code mapping, and the stdout/stderr contract.

Exit 0 means only that a complete decision record was produced; it
never means permission. The record's "decision" field is the only
authority (N35). Exit 1: unexpected internal error. Exit 2: CLI usage
error only. Exit 3: file-access or input-validation error.

On every failure detected before the single stdout write, stdout is
exactly empty (N37). Honest limitation: the record is emitted as one
buffered write plus one flush; if the operating system accepts a
partial write and then fails, the already-emitted bytes cannot be
retracted. Such a write or flush failure exits 1. Stderr diagnostics
are one line and their wording is not a stable contract.
"""

import argparse
import sys

from agent_action_guard.engine import evaluate
from agent_action_guard.loader import (
    InputValidationError,
    load_action,
    load_policy,
)
from agent_action_guard.serializer import serialize


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    # Argparse must never terminate the process or touch stdout: every
    # parse failure funnels through error(), which raises instead of
    # calling self.exit() (no SystemExit can leak).
    def error(self, message):
        raise _UsageError(message)


class _SingleUseAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"argument {option_string}: repeated")
        setattr(namespace, self.dest, values)


def _build_parser() -> _Parser:
    parser = _Parser(prog="agent-action-guard", add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = subparsers.add_parser("evaluate", add_help=False)
    evaluate_parser.add_argument(
        "--action", required=True, action=_SingleUseAction
    )
    evaluate_parser.add_argument(
        "--policy", required=True, action=_SingleUseAction
    )
    return parser


def _read_file(path: str) -> bytes:
    with open(path, "rb") as stream:
        return stream.read()


def _internal_error(exc: Exception) -> int:
    print(
        f"agent-action-guard: internal error:"
        f" {type(exc).__name__}: {exc}",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build_parser().parse_args(argv)
    except _UsageError as exc:
        print(f"agent-action-guard: usage error: {exc}", file=sys.stderr)
        return 2

    try:
        action_data = _read_file(args.action)
        policy_data = _read_file(args.policy)
        action = load_action(action_data)
        policy = load_policy(policy_data)
    except (OSError, InputValidationError) as exc:
        print(f"agent-action-guard: input error: {exc}", file=sys.stderr)
        return 3

    try:
        record = serialize(evaluate(action, policy))
    except Exception as exc:
        return _internal_error(exc)

    try:
        sys.stdout.buffer.write(record)
        sys.stdout.buffer.flush()
    except Exception as exc:
        return _internal_error(exc)
    return 0
