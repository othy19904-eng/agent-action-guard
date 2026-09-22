from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path

from agents import Agent, RunConfig, Runner
from agents.decorators import tool
from agents.testing import ScriptedModel, assistant_message, function_call

from retest_lab.adapters.openai_agents import OpenAIAgentsWitnessHooks
from retest_lab.runtime_witness import verify_jsonl_file


async def run_demo(mode: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace = root / "trace.jsonl"
        marker = root / "marker.txt"

        @tool
        def write_marker(path: str) -> str:
            """Write a marker file.

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
                        call_id="demo_write_1",
                    )
                ],
                [assistant_message("Marker written.")],
            ]
        )

        agent = Agent(
            name="Runtime Witness demo",
            model=model,
            tools=[write_marker],
        )

        hooks = OpenAIAgentsWitnessHooks(
            trace,
            tool_consequences={"write_marker": "local_file_write"},
        )

        if mode == "guarded":
            hooks.boundary(
                "approval:P",
                evidence="demo approval observed before agent run",
            )

        await Runner.run(
            agent,
            "Write the marker file.",
            hooks=hooks,
            run_config=RunConfig(tracing_disabled=True),
        )
        hooks.finalize()
        model.assert_complete()

        if marker.read_text(encoding="utf-8") != "done":
            raise RuntimeError("demo consequence did not occur")

        verdict = verify_jsonl_file(
            trace,
            consequence="local_file_write",
            expected_boundary="approval:P",
        )

        print(json.dumps(verdict.to_dict(), indent=2, sort_keys=True))

        expected = (
            "BOUNDARY_OBSERVED" if mode == "guarded" else "OBSERVED_BYPASS"
        )
        return 0 if verdict.status == expected else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a deterministic OpenAI Agents Runtime Witness demo."
    )
    parser.add_argument(
        "--mode",
        choices=("guarded", "bypass"),
        default="bypass",
    )
    args = parser.parse_args()
    return asyncio.run(run_demo(args.mode))


if __name__ == "__main__":
    raise SystemExit(main())
