from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from retest_lab.execution_trace import ExecutionTraceRecorder
from retest_lab.runtime_witness import verify_jsonl_file


class LiveToolTraceIntegrationTests(unittest.TestCase):
    def _write_marker(
        self,
        recorder: ExecutionTraceRecorder,
        marker: Path,
    ) -> None:
        recorder.run_subprocess(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('done', encoding='utf-8')",
                str(marker),
            ],
            evidence="python subprocess wrote temporary marker",
        )
        self.assertEqual(marker.read_text(encoding="utf-8"), "done")

    def test_real_subprocess_guarded_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            marker = root / "guarded.txt"

            recorder = ExecutionTraceRecorder(trace)
            recorder.boundary("approval:P", evidence="test approval granted")
            self._write_marker(recorder, marker)
            consequence_seq = recorder.consequence(
                "local_file_write",
                evidence="guarded marker exists",
            )
            recorder.complete(consequence_seq)

            result = verify_jsonl_file(
                trace,
                consequence="local_file_write",
                expected_boundary="approval:P",
            )

            self.assertEqual(result.status, "BOUNDARY_OBSERVED")
            self.assertIn("effect:subprocess.exec", result.path)
            self.assertIn("boundary:approval:P", result.path)

    def test_real_subprocess_bypass_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            marker = root / "bypass.txt"

            recorder = ExecutionTraceRecorder(trace)
            self._write_marker(recorder, marker)
            consequence_seq = recorder.consequence(
                "local_file_write",
                evidence="bypass marker exists",
            )
            recorder.complete(consequence_seq)

            result = verify_jsonl_file(
                trace,
                consequence="local_file_write",
                expected_boundary="approval:P",
            )

            self.assertEqual(result.status, "OBSERVED_BYPASS")
            self.assertIn("effect:subprocess.exec", result.path)
            self.assertNotIn("boundary:approval:P", result.path)

    def test_truncated_real_execution_trace_is_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            marker = root / "truncated.txt"

            recorder = ExecutionTraceRecorder(trace)
            self._write_marker(recorder, marker)
            recorder.consequence(
                "local_file_write",
                evidence="marker exists but trace was not attested complete",
            )

            result = verify_jsonl_file(
                trace,
                consequence="local_file_write",
                expected_boundary="approval:P",
            )

            self.assertEqual(result.status, "UNRESOLVED_TRACE")
            self.assertIn("trace_complete", result.reason)

    def test_failed_tool_execution_does_not_create_consequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            recorder = ExecutionTraceRecorder(trace)

            with self.assertRaises(subprocess.CalledProcessError):
                recorder.run_subprocess(
                    [sys.executable, "-c", "raise SystemExit(7)"],
                    evidence="intentional failing subprocess",
                )

            result = verify_jsonl_file(
                trace,
                consequence="local_file_write",
                expected_boundary="approval:P",
            )
            self.assertEqual(result.status, "UNRESOLVED_TRACE")
            self.assertIn("not observed", result.reason)
