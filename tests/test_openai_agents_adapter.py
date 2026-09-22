from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agents import Agent, RunConfig, Runner
from agents.decorators import tool
from agents.testing import ScriptedModel, assistant_message, function_call

from retest_lab.adapters.openai_agents import OpenAIAgentsWitnessHooks
from retest_lab.runtime_witness import verify_jsonl_file


class OpenAIAgentsAdapterIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def _run_case(self, *, guarded: bool):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            marker = root / "marker.txt"

            @tool
            def write_marker(path: str) -> str:
                """Write a deterministic marker file.

                Args:
                    path: Destination path for the marker.
                """
                Path(path).write_text("done", encoding="utf-8")
                return "done"

            model = ScriptedModel(
                [
                    [
                        function_call(
                            "write_marker",
                            {"path": str(marker)},
                            call_id="call_write_1",
                        )
                    ],
                    [assistant_message("Marker written.")],
                ]
            )
            agent = Agent(
                name="Runtime Witness integration agent",
                model=model,
                tools=[write_marker],
            )
            hooks = OpenAIAgentsWitnessHooks(
                trace,
                tool_consequences={"write_marker": "local_file_write"},
            )

            if guarded:
                hooks.boundary(
                    "approval:P",
                    evidence="application approval observed before agent run",
                )

            result = await Runner.run(
                agent,
                "Write the marker file.",
                hooks=hooks,
                run_config=RunConfig(tracing_disabled=True),
            )
            hooks.finalize()
            model.assert_complete()

            self.assertEqual(result.final_output, "Marker written.")
            self.assertEqual(marker.read_text(encoding="utf-8"), "done")

            trace_text = trace.read_text(encoding="utf-8")
            self.assertNotIn(str(marker), trace_text)
            self.assertIn("call_write_1", trace_text)

            verdict = verify_jsonl_file(
                trace,
                consequence="local_file_write",
                expected_boundary="approval:P",
            )
            return verdict

    async def test_guarded_real_sdk_tool_pipeline(self) -> None:
        verdict = await self._run_case(guarded=True)

        self.assertEqual(verdict.status, "BOUNDARY_OBSERVED")
        self.assertIn("boundary:approval:P", verdict.path)
        self.assertIn("tool:openai_agents:write_marker", verdict.path)
        self.assertIn(
            "effect:openai_agents:write_marker:completed",
            verdict.path,
        )

    async def test_bypass_real_sdk_tool_pipeline(self) -> None:
        verdict = await self._run_case(guarded=False)

        self.assertEqual(verdict.status, "OBSERVED_BYPASS")
        self.assertNotIn("boundary:approval:P", verdict.path)
        self.assertIn("tool:openai_agents:write_marker", verdict.path)
        self.assertIn(
            "effect:openai_agents:write_marker:completed",
            verdict.path,
        )

    async def test_no_tool_call_cannot_be_finalized_as_safe_or_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.jsonl"
            model = ScriptedModel([[assistant_message("No action needed.")]])
            agent = Agent(name="No-op agent", model=model)
            hooks = OpenAIAgentsWitnessHooks(
                trace,
                tool_consequences={"write_marker": "local_file_write"},
            )

            result = await Runner.run(
                agent,
                "Do nothing.",
                hooks=hooks,
                run_config=RunConfig(tracing_disabled=True),
            )
            model.assert_complete()
            self.assertEqual(result.final_output, "No action needed.")

            with self.assertRaises(RuntimeError):
                hooks.finalize()

            verdict = verify_jsonl_file(
                trace,
                consequence="local_file_write",
                expected_boundary="approval:P",
            )
            self.assertEqual(verdict.status, "UNRESOLVED_TRACE")
