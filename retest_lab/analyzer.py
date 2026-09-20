from __future__ import annotations

import ast
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

BOUNDARY_CALLS = {"require_approval", "approval"}
WORKFLOW_RUN_RE = re.compile(r"gh\s+workflow\s+run\s+([^\s;&|]+)")
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


def _static_value(node: ast.AST, env: dict[str, object]) -> object | None:
    if isinstance(node, ast.Name):
        return env.get(node.id)

    try:
        return ast.literal_eval(node)
    except Exception:
        pass

    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[object] = []
        for element in node.elts:
            value = _static_value(element, env)
            if value is None:
                return None
            values.append(value)
        return values if isinstance(node, ast.List) else tuple(values)

    return None


def _literal_text(
    node: ast.AST,
    env: dict[str, object] | None = None,
) -> str | None:
    value = _static_value(node, env or {})
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
        return " ".join(value)
    return None


def _static_env_before(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    lineno: int,
    initial: dict[str, object] | None = None,
) -> dict[str, object]:
    """Resolve only straight-line local constants assigned before a call.

    This deliberately ignores branch-dependent/nested assignments. Unknown
    writes invalidate a previously known value instead of guessing.
    """
    env: dict[str, object] = dict(initial or {})

    for stmt in func.body:
        stmt_line = getattr(stmt, "lineno", 0)
        if stmt_line >= lineno:
            break

        if isinstance(stmt, ast.Assign):
            value = _static_value(stmt.value, env)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    if value is None:
                        env.pop(target.id, None)
                    else:
                        env[target.id] = value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            value = (
                _static_value(stmt.value, env)
                if stmt.value is not None
                else None
            )
            if value is None:
                env.pop(stmt.target.id, None)
            else:
                env[stmt.target.id] = value
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            env.pop(stmt.target.id, None)

    return env


def _iter_calls_in_order(func: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterable[ast.Call]:
    calls: list[tuple[int, int, ast.Call]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            calls.append((getattr(node, "lineno", 0), getattr(node, "col_offset", 0), node))
    for _, _, call in sorted(calls, key=lambda x: (x[0], x[1])):
        yield call


def _parameter_names(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[str]:
    args = list(func.args.posonlyargs) + list(func.args.args)
    return [arg.arg for arg in args]


def _infer_parameter_envs(
    parsed: list[tuple[Path, ast.Module]],
    function_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> dict[str, dict[str, object]]:
    """Infer only callsite-invariant static argument values.

    A parameter is propagated into a callee only when every observed callsite
    provides the same statically-known value. Conflicts or unknown arguments
    deliberately erase the binding rather than guessing.
    """
    observations: dict[str, dict[str, list[object | None]]] = {}

    for _path, tree in parsed:
        for caller in tree.body:
            if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in _iter_calls_in_order(caller):
                name = _call_name(call) or ""
                callee_name = name.split(".")[-1]
                callee = function_defs.get(callee_name)
                if callee is None or callee_name == caller.name:
                    continue

                caller_env = _static_env_before(
                    caller,
                    getattr(call, "lineno", 0),
                )
                params = _parameter_names(callee)
                supplied: dict[str, ast.AST] = {}

                for index, arg in enumerate(call.args):
                    if index < len(params):
                        supplied[params[index]] = arg
                for kw in call.keywords:
                    if kw.arg in params:
                        supplied[kw.arg] = kw.value

                bucket = observations.setdefault(callee_name, {})
                for param in params:
                    values = bucket.setdefault(param, [])
                    node = supplied.get(param)
                    values.append(
                        _static_value(node, caller_env)
                        if node is not None
                        else None
                    )

    resolved: dict[str, dict[str, object]] = {}
    for callee_name, params in observations.items():
        env: dict[str, object] = {}
        for param, values in params.items():
            if not values or any(value is None for value in values):
                continue
            first = values[0]
            if all(value == first for value in values[1:]):
                env[param] = first
        if env:
            resolved[callee_name] = env

    return resolved


def _callsite_bindings(
    caller: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    callee: ast.FunctionDef | ast.AsyncFunctionDef,
    caller_initial: dict[str, object] | None = None,
) -> dict[str, object]:
    caller_env = _static_env_before(
        caller,
        getattr(call, "lineno", 0),
        caller_initial,
    )
    params = _parameter_names(callee)
    bindings: dict[str, object] = {}

    for index, arg in enumerate(call.args):
        if index >= len(params):
            break
        value = _static_value(arg, caller_env)
        if value is not None:
            bindings[params[index]] = value

    for kw in call.keywords:
        if kw.arg in params:
            value = _static_value(kw.value, caller_env)
            if value is not None:
                bindings[kw.arg] = value

    return bindings


def _add_effect_edges_for_function_context(
    *,
    repo: Path,
    graph: Graph,
    rel: Path,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    context_node: str,
    initial_env: dict[str, object],
    function_names: set[str],
) -> None:
    """Add bounded, callsite-specific edges for one function body.

    This supplements the global graph. It does not claim full context-sensitive
    program analysis; it specializes only statically-known arguments at this
    callsite.
    """
    cursor = context_node

    for call in _iter_calls_in_order(func):
        name = _call_name(call) or ""
        evidence = f"{rel}:{getattr(call, 'lineno', '?')}"
        env = _static_env_before(
            func,
            getattr(call, "lineno", 0),
            initial_env,
        )

        if name.split(".")[-1] in BOUNDARY_CALLS and call.args:
            label = _literal_text(call.args[0], env)
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
            wf = _literal_text(call.args[0], env)
            if wf:
                graph.add(
                    cursor,
                    f"workflow:{Path(wf).name}",
                    "mcp_workflow_dispatch",
                    evidence,
                )
                continue

        for arg in list(call.args) + [kw.value for kw in call.keywords]:
            text = _literal_text(arg, env)
            if not text:
                continue
            match = REST_DISPATCH_RE.search(text)
            if match:
                graph.add(
                    cursor,
                    f"workflow:{Path(match.group(1)).name}",
                    "rest_workflow_dispatch",
                    evidence,
                )

        if name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "os.system",
        } and call.args:
            cmd = _literal_text(call.args[0], env)
            if not cmd:
                continue

            linked_script = False
            for ref in _script_refs(cmd):
                script = repo / ref
                if script.is_file():
                    graph.add(
                        cursor,
                        f"script:{Path(ref).as_posix()}",
                        "invokes_script",
                        evidence,
                    )
                    linked_script = True

            match = WORKFLOW_RUN_RE.search(cmd)
            if match:
                graph.add(cursor, "effect:shell.exec", "invokes", evidence)
                graph.add(
                    "effect:shell.exec",
                    f"workflow:{Path(match.group(1)).name}",
                    "gh_workflow_dispatch",
                    evidence,
                )
            elif GIT_PUSH_RE.search(cmd):
                graph.add(cursor, "effect:git_push", "invokes", evidence)
            elif not linked_script:
                graph.add(
                    cursor,
                    "effect:shell.exec:unknown",
                    "invokes",
                    evidence,
                )


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


def _script_refs(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []

    refs: list[str] = []
    for index, token in enumerate(tokens):
        candidate: str | None = None
        if token in {"bash", "sh"} and index + 1 < len(tokens):
            nxt = tokens[index + 1]
            if nxt.endswith(".sh"):
                candidate = nxt
        elif token.endswith(".sh") and (token.startswith("./") or "/" in token):
            candidate = token

        if candidate:
            candidate = candidate.removeprefix("./")
            if candidate not in refs:
                refs.append(candidate)
    return refs


def _add_shell_script_edges(repo: Path, graph: Graph) -> None:
    scripts: dict[str, Path] = {}
    for script in sorted(repo.rglob("*.sh")):
        if ".git" in script.parts:
            continue
        rel = script.relative_to(repo).as_posix()
        scripts[rel] = script

    for rel, script in scripts.items():
        node = f"script:{rel}"
        try:
            lines = script.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue

        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            evidence = f"{rel}:{lineno}"

            match = WORKFLOW_RUN_RE.search(line)
            if match:
                graph.add(
                    node,
                    f"workflow:{Path(match.group(1)).name}",
                    "gh_workflow_dispatch",
                    evidence,
                )

            if GIT_PUSH_RE.search(line):
                graph.add(node, "effect:git_push", "invokes", evidence)

            for ref in _script_refs(line):
                if ref in scripts:
                    graph.add(node, f"script:{ref}", "calls_script", evidence)


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
                graph.add(
                    node,
                    "consequence:production_deploy",
                    "reaches_consequence",
                    str(wf.relative_to(repo)),
                )
                graph.consequences.add("consequence:production_deploy")

    _add_shell_script_edges(repo, graph)

    function_names: set[str] = set()
    function_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
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
                function_defs[node.name] = node

    parameter_envs = _infer_parameter_envs(parsed, function_defs)

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
                env = _static_env_before(
                    func,
                    getattr(call, "lineno", 0),
                    parameter_envs.get(func.name),
                )

                if name.split(".")[-1] in BOUNDARY_CALLS and call.args:
                    label = _literal_text(call.args[0], env)
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
                    wf = _literal_text(call.args[0], env)
                    if wf:
                        graph.add(
                            cursor,
                            f"workflow:{Path(wf).name}",
                            "mcp_workflow_dispatch",
                            evidence,
                        )
                        continue

                for arg in list(call.args) + [kw.value for kw in call.keywords]:
                    text = _literal_text(arg, env)
                    if not text:
                        continue
                    match = REST_DISPATCH_RE.search(text)
                    if match:
                        graph.add(
                            cursor,
                            f"workflow:{Path(match.group(1)).name}",
                            "rest_workflow_dispatch",
                            evidence,
                        )

                if name in {
                    "subprocess.run",
                    "subprocess.call",
                    "subprocess.check_call",
                    "os.system",
                } and call.args:
                    cmd = _literal_text(call.args[0], env)
                    if not cmd:
                        continue

                    linked_script = False
                    for ref in _script_refs(cmd):
                        script = repo / ref
                        if script.is_file():
                            graph.add(
                                cursor,
                                f"script:{Path(ref).as_posix()}",
                                "invokes_script",
                                evidence,
                            )
                            linked_script = True

                    match = WORKFLOW_RUN_RE.search(cmd)
                    if match:
                        graph.add(cursor, "effect:shell.exec", "invokes", evidence)
                        graph.add(
                            "effect:shell.exec",
                            f"workflow:{Path(match.group(1)).name}",
                            "gh_workflow_dispatch",
                            evidence,
                        )
                    elif GIT_PUSH_RE.search(cmd):
                        graph.add(cursor, "effect:git_push", "invokes", evidence)
                    elif not linked_script:
                        # The shell execution exists, but this RETEST model cannot
                        # yet resolve its effect to a protected consequence.
                        graph.add(cursor, "effect:shell.exec:unknown", "invokes", evidence)

    # Supplement the global call graph with callsite-specific function
    # instances whenever a direct call supplies at least one static argument.
    # This lets two callers of the same helper retain different bindings.
    for py, tree in parsed:
        rel = py.relative_to(repo)
        for caller in tree.body:
            if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            caller_initial = parameter_envs.get(caller.name)
            caller_node = f"function:{caller.name}"

            for call in _iter_calls_in_order(caller):
                name = _call_name(call) or ""
                callee_name = name.split(".")[-1]
                callee = function_defs.get(callee_name)
                if callee is None or callee_name == caller.name:
                    continue

                bindings = _callsite_bindings(
                    caller,
                    call,
                    callee,
                    caller_initial,
                )
                if not bindings:
                    continue

                line = getattr(call, "lineno", 0)
                context_node = (
                    f"context:{callee_name}@{caller.name}:{line}"
                )
                evidence = f"{rel}:{line}"
                graph.add(
                    caller_node,
                    context_node,
                    "calls_with_context",
                    evidence,
                )
                _add_effect_edges_for_function_context(
                    repo=repo,
                    graph=graph,
                    rel=rel,
                    func=callee,
                    context_node=context_node,
                    initial_env=bindings,
                    function_names=function_names,
                )

    for wf_name, (triggers, _prod, wf_path) in workflows.items():
        if "push" in triggers:
            graph.add(
                "effect:git_push",
                f"workflow:{wf_name}",
                "push_triggers_workflow",
                str(wf_path.relative_to(repo)),
            )

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
