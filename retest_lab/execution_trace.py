from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Sequence


class ExecutionTraceRecorder:
    """Record observed local tool execution as Runtime Witness JSONL.

    The recorder is deliberately small and provider-agnostic. It does not
    infer intent and it does not execute an agent. Callers wrap the tool
    boundary they already control, then verify the emitted trace separately.

    A consequence should only be recorded after the caller has independently
    observed that the consequence happened.
    """

    def __init__(self, path: str | Path, *, root_name: str = "agent") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._next_seq = 1
        self._last_seq: int | None = None
        self._completed = False
        self.path.write_text("", encoding="utf-8")
        self._emit("root", root_name, parent_seq=None)

    @property
    def last_seq(self) -> int:
        assert self._last_seq is not None
        return self._last_seq

    def _emit(
        self,
        kind: str,
        name: str,
        *,
        evidence: str | None = None,
        parent_seq: int | None | object = ...,
    ) -> int:
        if self._completed:
            raise RuntimeError("trace is already complete")
        if not name:
            raise ValueError("event name must be non-empty")

        seq = self._next_seq
        self._next_seq += 1

        if parent_seq is ...:
            parent_seq = self._last_seq

        event: dict[str, object] = {
            "seq": seq,
            "kind": kind,
            "name": name,
        }
        if parent_seq is not None:
            event["parent_seq"] = parent_seq
        if evidence is not None:
            if not evidence:
                raise ValueError("evidence must be non-empty when provided")
            event["evidence"] = evidence

        encoded = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        self._last_seq = seq
        return seq

    def boundary(self, name: str, *, evidence: str | None = None) -> int:
        return self._emit("boundary", name, evidence=evidence)

    def tool(self, name: str, *, evidence: str | None = None) -> int:
        return self._emit("tool", name, evidence=evidence)

    def run_subprocess(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None = None,
        evidence: str | None = None,
        check: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a real subprocess and record it only after it returns.

        The recorder intentionally does not persist argv/stdout/stderr by
        default because those may contain credentials or proprietary data.
        Callers may provide a non-sensitive evidence label.
        """
        if not argv:
            raise ValueError("argv must not be empty")

        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        self._emit(
            "effect",
            "subprocess.exec",
            evidence=evidence,
        )

        if check and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                list(argv),
                output=completed.stdout,
                stderr=completed.stderr,
            )

        return completed

    def consequence(self, name: str, *, evidence: str | None = None) -> int:
        return self._emit("consequence", name, evidence=evidence)

    def complete(self, consequence_seq: int) -> int:
        if self._completed:
            raise RuntimeError("trace is already complete")
        if consequence_seq <= 0 or consequence_seq >= self._next_seq:
            raise ValueError("consequence_seq must reference an emitted event")

        seq = self._emit(
            "attestation",
            "trace_complete",
            parent_seq=consequence_seq,
        )
        self._completed = True
        return seq
