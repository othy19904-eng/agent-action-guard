from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_ALLOWED_KINDS = {"root", "effect", "tool", "workflow", "boundary", "consequence", "attestation"}
_ALLOWED_FIELDS = {"seq", "kind", "name", "parent_seq", "evidence"}


class TraceError(ValueError):
    """Raised when runtime evidence is malformed or structurally ambiguous."""


@dataclass(frozen=True)
class TraceEvent:
    seq: int
    kind: str
    name: str
    parent_seq: int | None = None
    evidence: str | None = None

    @property
    def node(self) -> str:
        return f"{self.kind}:{self.name}"

    def to_dict(self) -> dict:
        out = {
            "seq": self.seq,
            "kind": self.kind,
            "name": self.name,
        }
        if self.parent_seq is not None:
            out["parent_seq"] = self.parent_seq
        if self.evidence is not None:
            out["evidence"] = self.evidence
        return out


@dataclass(frozen=True)
class WitnessResult:
    status: str
    consequence: str
    expected_boundary: str
    reason: str
    consequence_seq: int | None = None
    path_seq: tuple[int, ...] = ()
    path: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "consequence": self.consequence,
            "expected_boundary": self.expected_boundary,
            "reason": self.reason,
            "consequence_seq": self.consequence_seq,
            "path_seq": list(self.path_seq),
            "path": list(self.path),
            "evidence": list(self.evidence),
            "note": (
                "Absence of OBSERVED_BYPASS is not a proof of safety. "
                "UNRESOLVED_TRACE means the evidence is incomplete or ambiguous."
            ),
        }


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_event(raw: object, *, line_no: int) -> TraceEvent:
    if not isinstance(raw, dict):
        raise TraceError(f"line {line_no}: event must be a JSON object")

    unknown = set(raw) - _ALLOWED_FIELDS
    if unknown:
        names = ", ".join(sorted(unknown))
        raise TraceError(f"line {line_no}: unknown field(s): {names}")

    missing = {"seq", "kind", "name"} - set(raw)
    if missing:
        names = ", ".join(sorted(missing))
        raise TraceError(f"line {line_no}: missing field(s): {names}")

    seq = raw["seq"]
    kind = raw["kind"]
    name = raw["name"]
    parent_seq = raw.get("parent_seq")
    evidence = raw.get("evidence")

    if not _is_int(seq) or seq <= 0:
        raise TraceError(f"line {line_no}: seq must be a positive integer")
    if not isinstance(kind, str) or kind not in _ALLOWED_KINDS:
        raise TraceError(
            f"line {line_no}: kind must be one of {sorted(_ALLOWED_KINDS)}"
        )
    if not isinstance(name, str) or not name:
        raise TraceError(f"line {line_no}: name must be a non-empty string")
    if parent_seq is not None and (not _is_int(parent_seq) or parent_seq <= 0):
        raise TraceError(
            f"line {line_no}: parent_seq must be null or a positive integer"
        )
    if evidence is not None and (
        not isinstance(evidence, str) or not evidence
    ):
        raise TraceError(
            f"line {line_no}: evidence must be omitted or a non-empty string"
        )

    return TraceEvent(
        seq=seq,
        kind=kind,
        name=name,
        parent_seq=parent_seq,
        evidence=evidence,
    )


def load_jsonl_text(text: str) -> tuple[TraceEvent, ...]:
    if not text:
        raise TraceError("trace is empty")

    events: list[TraceEvent] = []
    seen: set[int] = set()
    previous_seq: int | None = None

    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise TraceError(f"line {line_no}: blank lines are not allowed")
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceError(f"line {line_no}: invalid JSON") from exc

        event = _parse_event(raw, line_no=line_no)

        if event.seq in seen:
            raise TraceError(f"line {line_no}: duplicate seq {event.seq}")
        if previous_seq is not None and event.seq <= previous_seq:
            raise TraceError(
                f"line {line_no}: seq values must be strictly increasing"
            )

        # Keep the issue #5 linear JSONL contract ergonomic: if a non-root
        # event omits parent_seq, it is attached to the immediately preceding
        # event. Explicit parent_seq is required to represent branching.
        parent_seq = event.parent_seq
        if event.kind == "root":
            if parent_seq is not None:
                raise TraceError(f"line {line_no}: root cannot have parent_seq")
        elif parent_seq is None:
            if previous_seq is None:
                raise TraceError(
                    f"line {line_no}: non-root event has no preceding parent"
                )
            event = TraceEvent(
                seq=event.seq,
                kind=event.kind,
                name=event.name,
                parent_seq=previous_seq,
                evidence=event.evidence,
            )
        elif parent_seq not in seen:
            raise TraceError(
                f"line {line_no}: parent_seq must reference an earlier event"
            )

        seen.add(event.seq)
        previous_seq = event.seq
        events.append(event)

    if not events:
        raise TraceError("trace is empty")
    return tuple(events)


def load_jsonl(path: str | Path) -> tuple[TraceEvent, ...]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TraceError(f"cannot read UTF-8 trace: {exc}") from exc
    return load_jsonl_text(text)


def _reconstruct_path(
    events_by_seq: dict[int, TraceEvent],
    consequence_event: TraceEvent,
) -> tuple[TraceEvent, ...]:
    chain: list[TraceEvent] = []
    seen: set[int] = set()
    current = consequence_event

    while True:
        if current.seq in seen:
            raise TraceError("cycle detected in parent chain")
        seen.add(current.seq)
        chain.append(current)

        if current.kind == "root":
            if current.parent_seq is not None:
                raise TraceError("root unexpectedly has a parent")
            break

        if current.parent_seq is None:
            raise TraceError("path terminates before reaching a root")

        parent = events_by_seq.get(current.parent_seq)
        if parent is None:
            raise TraceError("parent event is missing from trace")
        current = parent

    chain.reverse()
    return tuple(chain)


def _result_from_error(
    consequence: str,
    expected_boundary: str,
    reason: str,
) -> WitnessResult:
    return WitnessResult(
        status="UNRESOLVED_TRACE",
        consequence=consequence,
        expected_boundary=expected_boundary,
        reason=reason,
    )


def verify_events(
    events: Iterable[TraceEvent],
    *,
    consequence: str,
    expected_boundary: str,
) -> WitnessResult:
    if not consequence:
        return _result_from_error(
            consequence, expected_boundary, "consequence must be non-empty"
        )
    if not expected_boundary:
        return _result_from_error(
            consequence, expected_boundary, "expected boundary must be non-empty"
        )

    items = tuple(events)
    if not items:
        return _result_from_error(consequence, expected_boundary, "trace is empty")

    events_by_seq: dict[int, TraceEvent] = {}
    for event in items:
        if event.seq in events_by_seq:
            return _result_from_error(
                consequence, expected_boundary, f"duplicate seq {event.seq}"
            )
        events_by_seq[event.seq] = event

    matches = [
        event
        for event in items
        if event.kind == "consequence" and event.name == consequence
    ]

    if not matches:
        return _result_from_error(
            consequence,
            expected_boundary,
            "protected consequence was not observed",
        )

    # v0 intentionally supports one protected consequence occurrence per
    # witness. Multiple occurrences require run/attempt identity before they
    # can be attributed safely.
    if len(matches) != 1:
        return _result_from_error(
            consequence,
            expected_boundary,
            "multiple matching consequence events are ambiguous in v0",
        )

    target = matches[0]

    completions = [
        event
        for event in items
        if event.kind == "attestation" and event.name == "trace_complete"
    ]
    if len(completions) != 1:
        return _result_from_error(
            consequence,
            expected_boundary,
            "exactly one trace_complete attestation is required",
        )

    completion = completions[0]
    if completion.seq != max(event.seq for event in items):
        return _result_from_error(
            consequence,
            expected_boundary,
            "trace_complete attestation must be the final event",
        )
    if completion.parent_seq != target.seq:
        return _result_from_error(
            consequence,
            expected_boundary,
            "trace_complete attestation must reference the protected consequence",
        )

    try:
        path_events = _reconstruct_path(events_by_seq, target)
    except TraceError as exc:
        return _result_from_error(consequence, expected_boundary, str(exc))

    roots = [event for event in path_events if event.kind == "root"]
    if len(roots) != 1 or path_events[0].kind != "root":
        return _result_from_error(
            consequence,
            expected_boundary,
            "consequence path does not resolve to exactly one root",
        )

    boundary_present = any(
        event.kind == "boundary" and event.name == expected_boundary
        for event in path_events
    )

    evidence = tuple(
        event.evidence for event in path_events if event.evidence is not None
    )
    path_seq = tuple(event.seq for event in path_events)
    path = tuple(event.node for event in path_events)

    if boundary_present:
        return WitnessResult(
            status="BOUNDARY_OBSERVED",
            consequence=consequence,
            expected_boundary=expected_boundary,
            reason="expected boundary is on the observed consequence path",
            consequence_seq=target.seq,
            path_seq=path_seq,
            path=path,
            evidence=evidence,
        )

    return WitnessResult(
        status="OBSERVED_BYPASS",
        consequence=consequence,
        expected_boundary=expected_boundary,
        reason="observed consequence path does not contain expected boundary",
        consequence_seq=target.seq,
        path_seq=path_seq,
        path=path,
        evidence=evidence,
    )


def verify_jsonl_text(
    text: str,
    *,
    consequence: str,
    expected_boundary: str,
) -> WitnessResult:
    try:
        events = load_jsonl_text(text)
    except TraceError as exc:
        return _result_from_error(consequence, expected_boundary, str(exc))
    return verify_events(
        events,
        consequence=consequence,
        expected_boundary=expected_boundary,
    )


def verify_jsonl_file(
    path: str | Path,
    *,
    consequence: str,
    expected_boundary: str,
) -> WitnessResult:
    try:
        events = load_jsonl(path)
    except TraceError as exc:
        return _result_from_error(consequence, expected_boundary, str(exc))
    return verify_events(
        events,
        consequence=consequence,
        expected_boundary=expected_boundary,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runtime-witness",
        description=(
            "Verify whether an observed JSONL trace reached a protected "
            "consequence with or without the expected boundary."
        ),
    )
    parser.add_argument("trace", help="path to JSONL runtime trace")
    parser.add_argument("--consequence", required=True)
    parser.add_argument("--boundary", required=True)
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON (default output is concise text)",
    )
    return parser


def render_text(result: WitnessResult) -> str:
    lines = [
        result.status,
        f"consequence: {result.consequence}",
        f"expected_boundary: {result.expected_boundary}",
        f"reason: {result.reason}",
    ]
    if result.path:
        lines.append("path:")
        for node in result.path:
            lines.append(f"  {node}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = verify_jsonl_file(
        args.trace,
        consequence=args.consequence,
        expected_boundary=args.boundary,
    )

    if args.json:
        print(json.dumps(result.to_dict(), sort_keys=True))
    else:
        print(render_text(result))

    if result.status == "BOUNDARY_OBSERVED":
        return 0
    if result.status == "OBSERVED_BYPASS":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
