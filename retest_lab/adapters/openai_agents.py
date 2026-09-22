from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from agents import RunHooks

from retest_lab.execution_trace import ExecutionTraceRecorder


class OpenAIAgentsWitnessHooks(RunHooks):
    """Bridge OpenAI Agents SDK local-tool hooks into Runtime Witness evidence.

    The adapter records only lifecycle metadata by default: tool name and
    tool_call_id. It deliberately does not persist tool arguments, stdout,
    stderr, model prompts, or model outputs.

    A tool can be mapped to a protected consequence. The consequence is
    emitted only from on_tool_end, after the SDK reports that the local tool
    invocation completed.

    Call boundary(...) when the application observes the expected
    approval/policy boundary, and call finalize() only after Runner.run(...)
    has returned successfully.
    """

    def __init__(
        self,
        trace_path: str | Path,
        *,
        tool_consequences: Mapping[str, str],
        root_name: str = "openai_agents_run",
    ) -> None:
        super().__init__()
        self.recorder = ExecutionTraceRecorder(trace_path, root_name=root_name)
        self._tool_consequences = dict(tool_consequences)
        self._consequence_seqs: list[int] = []
        self._finalized = False

        for tool_name, consequence in self._tool_consequences.items():
            if not tool_name or not consequence:
                raise ValueError(
                    "tool_consequences keys and values must be non-empty strings"
                )

    def boundary(self, name: str, *, evidence: str | None = None) -> int:
        """Record an application-observed approval/policy boundary."""
        return self.recorder.boundary(name, evidence=evidence)

    @staticmethod
    def _tool_name(tool: object) -> str:
        name = getattr(tool, "name", None)
        if isinstance(name, str) and name:
            return name
        return type(tool).__name__

    @staticmethod
    def _call_id(context: object) -> str | None:
        call_id = getattr(context, "tool_call_id", None)
        return call_id if isinstance(call_id, str) and call_id else None

    @classmethod
    def _evidence(cls, context: object, tool: object, phase: str) -> str:
        tool_name = cls._tool_name(tool)
        call_id = cls._call_id(context)
        if call_id is None:
            return f"openai-agents {phase} tool={tool_name}"
        return f"openai-agents {phase} tool={tool_name} call_id={call_id}"

    async def on_tool_start(self, context, agent, tool) -> None:
        """Record that the SDK began one local tool invocation."""
        self.recorder.tool(
            f"openai_agents:{self._tool_name(tool)}",
            evidence=self._evidence(context, tool, "tool_start"),
        )

    async def on_tool_end(self, context, agent, tool, result) -> None:
        """Record successful local-tool completion and any mapped consequence."""
        tool_name = self._tool_name(tool)
        self.recorder.effect(
            f"openai_agents:{tool_name}:completed",
            evidence=self._evidence(context, tool, "tool_end"),
        )

        consequence = self._tool_consequences.get(tool_name)
        if consequence is not None:
            seq = self.recorder.consequence(
                consequence,
                evidence=f"mapped from completed OpenAI Agents tool {tool_name}",
            )
            self._consequence_seqs.append(seq)

    def finalize(self) -> int:
        """Attest one unambiguous observed consequence after Runner completion."""
        if self._finalized:
            raise RuntimeError("OpenAI Agents witness trace is already finalized")
        if len(self._consequence_seqs) != 1:
            raise RuntimeError(
                "exactly one mapped consequence must complete before finalize"
            )

        self._finalized = True
        return self.recorder.complete(self._consequence_seqs[0])
