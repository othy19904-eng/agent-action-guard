from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

BOUNDARY_CALLS = {"require_approval", "approval"}
WORKFLOW_RUN_RE = re.compile(r"gh\s+workflow\s+run\s+([^\s]+)")
GIT_PUSH_RE = re.compile(r"\bgit\s+push\b")
REST_DISPATCH_RE = re.compile(r"/actions/workflows/([^/\"']+)/dispatches")


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str
    evidence: str


@dataclass
class Graph:
    edges: list[Edge] = field(default_factory=list)
    roots: set[str] = field(default_factory=set)
    boundaries: set[str] = field(default_factory=set)
    consequences: set[str] = field(default_factory=set)

    def add(self, src: str, dst: str, kind: str, evidence: str) -> None:
        edge = Edge(src, dst, kind, evidence)
        if edge not in self.edges:
            self.edges.append(edge)

    def outgoing(self, node: str) -> list[Edge]:
        return [e for e in self.edges if e.src == node]


@dataclass(frozen=True)
class Finding:
    status: str
    property_name: str
    consequence: str
    expected_boundary: str
    path: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "property": self.property_name,
            "consequence": self.consequence,
            "expected_boundary": self.expected_boundary,
            "path": list(self.path),
            "evidence": list(self.evidence),
        }


def _call_name(call: ast.Call) -> str | None:
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = fn
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
    return None


def _literal_text(node: ast.AST) -> str | None:
    try:
        value = ast.literal_eval(node)
    except Exception:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
        return " ".join(value)
    return None


def _iter_calls_in_order(func: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterable[ast.Call]:
    calls: list[tuple[int, int, ast.Call]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            calls.append((getattr(node, "lineno", 0), getattr(node, "col_offset", 0), node))
    for _, _, call in sorted(calls, key=lambda x: (x[0], x[1])):
        yield call


def _workflow_triggers_and_prod(path: Path) -> tuple[set[str], bool]:
    text = path.read_text(encoding="utf-8")
    triggers: set[str] = set()
    if re.search(r"(?m)^\s*workflow_dispatch\s*:", text) or "workflow_dispatch:" in text:
        triggers.add("workflow_dispatch")
    if re.search(r"(?m)^\s*push\s*:", text) or re.search(r"(?m)^on:\s*\[?push", text):
        triggers.add("push")
    prod = bool(
        re.search(r"(?im)^\s*environment\s*:\s*production\s*$", text)
        or re.search(r"(?i)deploy[-_ ]?prod(?:uction)?", text)
        or re.search(r"(?i)production_deploy", text)
    )
    return triggers, prod


def build_graph(repo: str | Path) -> Graph:
    repo = Path(repo)
    graph = Graph()

    workflows: dict[str, tuple[set[str], bool, Path]] = {}
    workflow_dir = repo / ".github" / "workflows"
    if workflow_dir.exists():
        for wf in sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml"))):
            triggers, prod = _workflow_triggers_and_prod(wf)
            workflows[wf.name] = (triggers, prod, wf)
            node = f"workflow:{wf.name}"
            if prod:
                graph.add(node, "consequence:production_deploy", "reaches_consequence", str(wf.relative_to(repo)))
                graph.consequences.add("consequence:production_deploy")

    function_names: set[str] = set()
    parsed: list[tuple[Path, ast.Module]] = []
    for py in sorted(repo.rglob("*.py")):
        if ".git" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except (SyntaxError, UnicodeDecodeError):
            continue
        parsed.append((py, tree))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_names.add(node.name)

    for py, tree in parsed:
        rel = py.relative_to(repo)
        for func in tree.body:
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fn_node = f"function:{func.name}"
            if func.name.startswith("agent_"):
                graph.roots.add(fn_node)

            cursor = fn_node
            for call in _iter_calls_in_order(func):
                name = _call_name(call) or ""
                evidence = f"{rel}:{getattr(call, 'lineno', '?')}"

                if name.split(".")[-1] in BOUNDARY_CALLS and call.args:
                    label = _literal_text(call.args[0])
                    if label:
                        boundary = f"boundary:approval:{label}"
                        graph.boundaries.add(boundary)
                        graph.add(cursor, boundary, "crosses_boundary", evidence)
                        cursor = boundary
                        continue

                short = name.split(".")[-1]
                if short in function_names and short != func.name:
                    graph.add(cursor, f"function:{short}", "calls", evidence)

                if name.endswith("run_workflow") and call.args:
                    wf = _literal_text(call.args[0])
                    if wf:
                        graph.add(cursor, f"workflow:{Path(wf).name}", "mcp_workflow_dispatch", evidence)
                        continue

                for arg in list(call.args) + [kw.value for kw in call.keywords]:
                    text = _literal_text(arg)
                    if not text:
                        continue
                    match = REST_DISPATCH_RE.search(text)
                    if match:
                        graph.add(cursor, f"workflow:{Path(match.group(1)).name}", "rest_workflow_dispatch", evidence)

                if name in {"subprocess.run", "subprocess.call", "subprocess.check_call", "os.system"} and call.args:
                    cmd = _literal_text(call.args[0])
                    if not cmd:
                        continue
                    match = WORKFLOW_RUN_RE.search(cmd)
                    if match:
                        graph.add(cursor, "effect:shell.exec", "invokes", evidence)
                        graph.add("effect:shell.exec", f"workflow:{Path(match.group(1)).name}", "gh_workflow_dispatch", evidence)
                    elif GIT_PUSH_RE.search(cmd):
                        graph.add(cursor, "effect:git_push", "invokes", evidence)

    for wf_name, (triggers, _prod, wf_path) in workflows.items():
        if "push" in triggers:
            graph.add("effect:git_push", f"workflow:{wf_name}", "push_triggers_workflow", str(wf_path.relative_to(repo)))

    return graph


def find_counterexample(
    graph: Graph,
    *,
    consequence: str = "production_deploy",
    required_boundary: str = "P",
) -> Finding:
    target = f"consequence:{consequence}"
    boundary = f"boundary:approval:{required_boundary}"
    property_name = f"every_path_to_{consequence}_crosses_approval_{required_boundary}"

    if target not in graph.consequences:
        return Finding("UNKNOWN", property_name, consequence, required_boundary)

    queue: list[tuple[str, bool, tuple[str, ...], tuple[str, ...]]] = []
    for root in sorted(graph.roots):
        queue.append((root, root == boundary, (root,), ()))
    seen: set[tuple[str, bool]] = set()
    saw_target_via_boundary = False

    while queue:
        node, crossed, path, evidence = queue.pop(0)
        state = (node, crossed)
        if state in seen:
            continue
        seen.add(state)
        if node == target:
            if crossed:
                saw_target_via_boundary = True
                continue
            return Finding(
                "COUNTEREXAMPLE_FOUND",
                property_name,
                consequence,
                required_boundary,
                path,
                evidence,
            )
        for edge in graph.outgoing(node):
            nxt_crossed = crossed or edge.dst == boundary
            queue.append(
                (edge.dst, nxt_crossed, path + (edge.dst,), evidence + (edge.evidence,))
            )

    if saw_target_via_boundary:
        return Finding("COVERED_WITHIN_MODEL", property_name, consequence, required_boundary)
    return Finding("UNKNOWN", property_name, consequence, required_boundary)


def analyze(
    repo: str | Path,
    *,
    consequence: str = "production_deploy",
    required_boundary: str = "P",
) -> Finding:
    return find_counterexample(
        build_graph(repo),
        consequence=consequence,
        required_boundary=required_boundary,
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="RETEST: find enforcement-bypass consequence paths"
    )
    parser.add_argument("repo", nargs="?", default=".")
    parser.add_argument("--consequence", default="production_deploy")
    parser.add_argument("--boundary", default="P")
    args = parser.parse_args(argv)
    finding = analyze(
        args.repo,
        consequence=args.consequence,
        required_boundary=args.boundary,
    )
    print(json.dumps(finding.to_dict(), indent=2, sort_keys=True))
    return 1 if finding.status == "COUNTEREXAMPLE_FOUND" else 0


if __name__ == "__main__":
    raise SystemExit(main())
