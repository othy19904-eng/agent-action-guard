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
    certain: bool = True


@dataclass(frozen=True)
class PartialText:
    text: str


@dataclass
class Graph:
    edges: list[Edge] = field(default_factory=list)
    roots: set[str] = field(default_factory=set)
    boundaries: set[str] = field(default_factory=set)
    consequences: set[str] = field(default_factory=set)

    def add(
        self,
        src: str,
        dst: str,
        kind: str,
        evidence: str,
        *,
        certain: bool = True,
    ) -> None:
        edge = Edge(src, dst, kind, evidence, certain)
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


def _expr_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_key(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _static_value(node: ast.AST, env: dict[str, object]) -> object | None:
    key = _expr_key(node)
    if key is not None and key in env:
        return env[key]

    if isinstance(node, ast.Call):
        name = _call_name(node) or ""

        # Environment defaults are candidates, not certainties: runtime state
        # may override them. Preserve the candidate text as PartialText so it
        # can participate in downstream URL construction without becoming a
        # proven edge.
        if name in {"os.getenv", "os.environ.get"} and len(node.args) >= 2:
            default = _static_value(node.args[1], env)
            if isinstance(default, str):
                return PartialText(default)
            if isinstance(default, PartialText):
                return default

        # Model a small set of pure string transforms used in URL/path
        # construction. Uncertainty of the base string is preserved.
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "strip",
            "lstrip",
            "rstrip",
            "removeprefix",
            "removesuffix",
        }:
            base = _static_value(node.func.value, env)
            if isinstance(base, (str, PartialText)):
                base_text = base.text if isinstance(base, PartialText) else base
                args: list[str] = []
                for arg in node.args:
                    value = _static_value(arg, env)
                    if not isinstance(value, str):
                        return None
                    args.append(value)
                try:
                    result = getattr(base_text, node.func.attr)(*args)
                except TypeError:
                    return None
                return PartialText(result) if isinstance(base, PartialText) else result

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

    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        certain = True
        for value_node in node.values:
            if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                parts.append(value_node.value)
                continue
            if isinstance(value_node, ast.FormattedValue):
                value = _static_value(value_node.value, env)
                if isinstance(value, PartialText):
                    parts.append(value.text)
                    certain = False
                elif value is None:
                    parts.append("<UNKNOWN>")
                    certain = False
                else:
                    parts.append(str(value))
                continue
            return None
        text = "".join(parts)
        return text if certain else PartialText(text)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_value(node.left, env)
        right = _static_value(node.right, env)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, (str, PartialText)) and isinstance(right, (str, PartialText)):
            left_text = left.text if isinstance(left, PartialText) else left
            right_text = right.text if isinstance(right, PartialText) else right
            return PartialText(left_text + right_text)

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


def _effect_text(
    node: ast.AST,
    env: dict[str, object] | None = None,
) -> tuple[str, bool] | None:
    value = _static_value(node, env or {})
    if isinstance(value, str):
        return value, True
    if isinstance(value, PartialText):
        return value.text, False
    return None


def _command_text(
    node: ast.AST,
    env: dict[str, object] | None = None,
) -> str | None:
    """Resolve enough of a shell argv to recognize a fixed effect prefix.

    Unknown list elements are kept as placeholders instead of invalidating the
    entire command. This is useful for commands such as:
    ["gh", "workflow", "run", "deploy.yml", "--repo", repo]
    where the consequence-bearing prefix is fully static but a trailing option
    is dynamic.
    """
    env = env or {}
    full = _literal_text(node, env)
    if full is not None:
        return full

    if isinstance(node, (ast.List, ast.Tuple)):
        tokens: list[str] = []
        for element in node.elts:
            value = _static_value(element, env)
            tokens.append(value if isinstance(value, str) else "<UNKNOWN>")
        return " ".join(tokens)

    if isinstance(node, ast.Name):
        value = env.get(node.id)
        if isinstance(value, (list, tuple)):
            return " ".join(
                item if isinstance(item, str) else "<UNKNOWN>"
                for item in value
            )

    return None


def _argparse_dest(call: ast.Call, env: dict[str, object]) -> str | None:
    if not call.args:
        return None
    options: list[str] = []
    for arg in call.args:
        value = _static_value(arg, env)
        if isinstance(value, str):
            options.append(value)
    if not options:
        return None
    long_options = [opt for opt in options if opt.startswith("--")]
    chosen = long_options[-1] if long_options else options[0]
    return chosen.lstrip("-").replace("-", "_")


def _apply_static_statement(
    stmt: ast.stmt,
    env: dict[str, object],
    function_returns: dict[str, dict[str, object]] | None = None,
) -> None:
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
        name = _call_name(call) or ""
        if name.endswith(".add_argument"):
            parser_key = _expr_key(call.func.value) if isinstance(call.func, ast.Attribute) else None
            dest = _argparse_dest(call, env)
            if parser_key and dest:
                default_value: object | None = None
                choices_value: object | None = None
                for kw in call.keywords:
                    if kw.arg == "default":
                        default_value = _static_value(kw.value, env)
                    elif kw.arg == "choices":
                        choices_value = _static_value(kw.value, env)
                if choices_value is not None:
                    env[f"__argparse__.{parser_key}.{dest}.choices"] = choices_value
                if default_value is not None:
                    env[f"__argparse__.{parser_key}.{dest}.default"] = default_value
        return

    if isinstance(stmt, ast.Assign):
        # Local helper returning a statically summarized namespace.
        if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name):
            summary = (function_returns or {}).get(stmt.value.func.id)
            if summary is not None:
                for target in stmt.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    for attr, value in summary.items():
                        env[f"{target.id}.{attr}"] = value
                return

        # argparse Namespace assignment, e.g. args = parser.parse_args()
        if (
            isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Attribute)
            and stmt.value.func.attr == "parse_args"
        ):
            parser_key = _expr_key(stmt.value.func.value)
            for target in stmt.targets:
                if not isinstance(target, ast.Name) or not parser_key:
                    continue
                prefix = f"__argparse__.{parser_key}."
                specs: dict[str, dict[str, object]] = {}
                for key, value in list(env.items()):
                    if not key.startswith(prefix):
                        continue
                    rest = key[len(prefix):]
                    if "." not in rest:
                        continue
                    dest, kind = rest.rsplit(".", 1)
                    specs.setdefault(dest, {})[kind] = value
                for dest, spec in specs.items():
                    if "choices" in spec:
                        env[f"{target.id}.{dest}"] = spec["choices"]
                    elif "default" in spec:
                        env[f"{target.id}.{dest}"] = spec["default"]
            return

        value = _static_value(stmt.value, env)
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                if value is None:
                    env.pop(target.id, None)
                else:
                    env[target.id] = value
        return

    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        value = (
            _static_value(stmt.value, env)
            if stmt.value is not None
            else None
        )
        if value is None:
            env.pop(stmt.target.id, None)
        else:
            env[stmt.target.id] = value
        return

    if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
        env.pop(stmt.target.id, None)


def _bindings_from_env(
    call: ast.Call,
    callee: ast.FunctionDef | ast.AsyncFunctionDef,
    env: dict[str, object],
) -> dict[str, object]:
    params = _parameter_names(callee)
    bindings: dict[str, object] = {}

    for index, arg in enumerate(call.args):
        if index >= len(params):
            break
        value = _static_value(arg, env)
        if value is not None:
            bindings[params[index]] = value

    for kw in call.keywords:
        if kw.arg in params:
            value = _static_value(kw.value, env)
            if value is not None:
                bindings[kw.arg] = value

    defaults = list(callee.args.defaults)
    if defaults:
        first_default = len(params) - len(defaults)
        for offset, default_node in enumerate(defaults):
            param = params[first_default + offset]
            if param in bindings:
                continue
            value = _static_value(default_node, env)
            if value is not None:
                bindings[param] = value

    return bindings


def _static_env_before(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    lineno: int,
    initial: dict[str, object] | None = None,
    function_returns: dict[str, dict[str, object]] | None = None,
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

        _apply_static_statement(stmt, env, function_returns)

    return env


def _static_bool(node: ast.AST, env: dict[str, object]) -> bool | None:
    value = _static_value(node, env)
    if isinstance(value, bool):
        return value

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _static_bool(node.operand, env)
        return None if inner is None else not inner

    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and len(node.comparators) == 1
    ):
        left = _static_value(node.left, env)
        right = _static_value(node.comparators[0], env)
        if left is None or right is None:
            return None
        if isinstance(node.ops[0], ast.Eq):
            return left == right
        if isinstance(node.ops[0], ast.NotEq):
            return left != right

    return None


def _assigned_names(statements: list[ast.stmt]) -> set[str]:
    names: set[str] = set()
    for stmt in statements:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
    return names


def _bind_loop_target(
    target: ast.AST,
    value: object,
    env: dict[str, object],
) -> bool:
    if isinstance(target, ast.Name):
        env[target.id] = value
        return True
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (tuple, list)):
        if len(target.elts) != len(value):
            return False
        for child, item in zip(target.elts, value):
            if not _bind_loop_target(child, item, env):
                return False
        return True
    return False


def _iter_reachable_calls(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    initial: dict[str, object] | None = None,
    function_returns: dict[str, dict[str, object]] | None = None,
) -> Iterable[tuple[ast.Call, dict[str, object], bool]]:
    """Yield calls with bounded static environment and reachability certainty.

    Calls on statically-known control-flow paths are certain. Calls inside
    runtime-dependent branches or loops are still modeled, but marked uncertain.
    This lets the graph preserve possible consequence paths without upgrading
    them to proven counterexamples.
    """
    env: dict[str, object] = dict(initial or {})

    def walk_block(
        statements: list[ast.stmt],
        current: dict[str, object],
        path_certain: bool,
    ) -> Iterable[tuple[ast.Call, dict[str, object], bool]]:
        for stmt in statements:
            if isinstance(stmt, ast.For):
                iterable = _static_value(stmt.iter, current)
                if isinstance(iterable, (list, tuple)) and len(iterable) <= 64:
                    bound_all = True
                    for item in iterable:
                        loop_env = dict(current)
                        if not _bind_loop_target(stmt.target, item, loop_env):
                            bound_all = False
                            break
                        yield from walk_block(
                            stmt.body,
                            loop_env,
                            path_certain,
                        )
                    if bound_all:
                        if stmt.orelse:
                            else_env = dict(current)
                            yield from walk_block(
                                stmt.orelse,
                                else_env,
                                path_certain,
                            )
                        continue

                # Runtime-dependent iterable: the loop body may execute zero or
                # more times, so calls inside it are possible rather than proven.
                loop_env = dict(current)
                yield from walk_block(stmt.body, loop_env, False)
                if stmt.orelse:
                    else_env = dict(current)
                    yield from walk_block(stmt.orelse, else_env, False)
                for name in _assigned_names(stmt.body + stmt.orelse):
                    current.pop(name, None)
                continue

            if isinstance(stmt, ast.If):
                test_calls = [
                    node for node in ast.walk(stmt.test)
                    if isinstance(node, ast.Call)
                ]
                test_calls.sort(
                    key=lambda node: (
                        getattr(node, "lineno", 0),
                        getattr(node, "col_offset", 0),
                    )
                )
                for call in test_calls:
                    yield call, dict(current), path_certain

                decision = _static_bool(stmt.test, current)
                if decision is True:
                    branch_env = dict(current)
                    yield from walk_block(
                        stmt.body,
                        branch_env,
                        path_certain,
                    )
                    current.clear()
                    current.update(branch_env)
                elif decision is False:
                    branch_env = dict(current)
                    yield from walk_block(
                        stmt.orelse,
                        branch_env,
                        path_certain,
                    )
                    current.clear()
                    current.update(branch_env)
                else:
                    body_env = dict(current)
                    else_env = dict(current)
                    yield from walk_block(stmt.body, body_env, False)
                    yield from walk_block(stmt.orelse, else_env, False)
                    for name in _assigned_names(stmt.body + stmt.orelse):
                        current.pop(name, None)
                continue

            calls = [
                node
                for node in ast.walk(stmt)
                if isinstance(node, ast.Call)
            ]
            calls.sort(
                key=lambda node: (
                    getattr(node, "lineno", 0),
                    getattr(node, "col_offset", 0),
                )
            )
            for call in calls:
                yield call, dict(current), path_certain

            _apply_static_statement(stmt, current, function_returns)

    yield from walk_block(func.body, env, True)


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

    for call, env, call_certain in _iter_reachable_calls(func, initial_env):
        name = _call_name(call) or ""
        evidence = f"{rel}:{getattr(call, 'lineno', '?')}"

        if name.split(".")[-1] in BOUNDARY_CALLS and call.args:
            label = _literal_text(call.args[0], env)
            if label:
                boundary = f"boundary:approval:{label}"
                graph.boundaries.add(boundary)
                graph.add(
                    cursor,
                    boundary,
                    "crosses_boundary",
                    evidence,
                    certain=call_certain,
                )
                cursor = boundary
                continue

        short = name.split(".")[-1]
        if short in function_names and short != func.name:
            graph.add(
                cursor,
                f"function:{short}",
                "calls",
                evidence,
                certain=call_certain,
            )

        if name.endswith("run_workflow") and call.args:
            wf = _literal_text(call.args[0], env)
            if wf:
                graph.add(
                    cursor,
                    f"workflow:{Path(wf).name}",
                    "mcp_workflow_dispatch",
                    evidence,
                    certain=call_certain,
                )
                continue

        for arg in list(call.args) + [kw.value for kw in call.keywords]:
            resolved = _effect_text(arg, env)
            if not resolved:
                continue
            text, certain = resolved
            match = REST_DISPATCH_RE.search(text)
            if match:
                graph.add(
                    cursor,
                    f"workflow:{Path(match.group(1)).name}",
                    (
                        "rest_workflow_dispatch"
                        if certain
                        else "possible_rest_workflow_dispatch"
                    ),
                    evidence,
                    certain=call_certain and certain,
                )

        if name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "os.system",
        } and call.args:
            cmd = _command_text(call.args[0], env)
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
                        certain=call_certain,
                    )
                    linked_script = True

            match = WORKFLOW_RUN_RE.search(cmd)
            if match:
                effect_node = f"effect:shell.exec@{context_node}"
                graph.add(
                    cursor,
                    effect_node,
                    "invokes",
                    evidence,
                    certain=call_certain,
                )
                graph.add(
                    effect_node,
                    f"workflow:{Path(match.group(1)).name}",
                    "gh_workflow_dispatch",
                    evidence,
                    certain=call_certain,
                )
            elif GIT_PUSH_RE.search(cmd):
                effect_node = f"effect:git_push@{context_node}"
                graph.add(
                    cursor,
                    effect_node,
                    "invokes",
                    evidence,
                    certain=call_certain,
                )
                # A git push can trigger every modeled push workflow. Keeping
                # the effect node contextual prevents unrelated callsites
                # from borrowing one another's downstream edges.
                for edge in list(graph.edges):
                    if (
                        edge.src == "effect:git_push"
                        and edge.kind == "push_triggers_workflow"
                    ):
                        graph.add(
                            effect_node,
                            edge.dst,
                            edge.kind,
                            evidence,
                            certain=call_certain and edge.certain,
                        )
            elif not linked_script:
                graph.add(
                    cursor,
                    f"effect:shell.exec:unknown@{context_node}",
                    "invokes",
                    evidence,
                    certain=call_certain,
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


def _argparse_return_summary(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    initial: dict[str, object] | None = None,
) -> dict[str, object] | None:
    env = dict(initial or {})
    for stmt in func.body:
        if isinstance(stmt, ast.Return):
            value = stmt.value
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "parse_args"
            ):
                parser_key = _expr_key(value.func.value)
                if not parser_key:
                    return None
                prefix = f"__argparse__.{parser_key}."
                summary: dict[str, object] = {}
                specs: dict[str, dict[str, object]] = {}
                for key, item in env.items():
                    if not key.startswith(prefix):
                        continue
                    rest = key[len(prefix):]
                    if "." not in rest:
                        continue
                    dest, kind = rest.rsplit(".", 1)
                    specs.setdefault(dest, {})[kind] = item
                for dest, spec in specs.items():
                    if "choices" in spec:
                        summary[dest] = spec["choices"]
                    elif "default" in spec:
                        summary[dest] = spec["default"]
                return summary or None
            return None
        _apply_static_statement(stmt, env)
    return None


def _module_static_env(tree: ast.Module) -> dict[str, object]:
    env: dict[str, object] = {}
    for stmt in tree.body:
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
    return env


def _merge_envs(*envs: dict[str, object] | None) -> dict[str, object]:
    merged: dict[str, object] = {}
    for env in envs:
        if env:
            merged.update(env)
    return merged


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
    function_module_envs: dict[str, dict[str, object]] = {}
    module_envs: dict[Path, dict[str, object]] = {}
    parsed: list[tuple[Path, ast.Module]] = []
    for py in sorted(repo.rglob("*.py")):
        if ".git" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except (SyntaxError, UnicodeDecodeError):
            continue
        parsed.append((py, tree))
        module_env = _module_static_env(tree)
        module_envs[py] = module_env
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_names.add(node.name)
                function_defs[node.name] = node
                function_module_envs[node.name] = module_env

    parameter_envs = _infer_parameter_envs(parsed, function_defs)
    function_returns: dict[str, dict[str, object]] = {}
    for py, tree in parsed:
        module_env = module_envs.get(py, {})
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                summary = _argparse_return_summary(node, module_env)
                if summary:
                    function_returns[node.name] = summary

    for py, tree in parsed:
        rel = py.relative_to(repo)
        for func in tree.body:
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fn_node = f"function:{func.name}"
            if func.name.startswith("agent_"):
                graph.roots.add(fn_node)

            cursor = fn_node
            initial_env = _merge_envs(
                module_envs.get(py),
                parameter_envs.get(func.name),
            )
            for call, env, call_certain in _iter_reachable_calls(
                func,
                initial_env,
                function_returns,
            ):
                name = _call_name(call) or ""
                evidence = f"{rel}:{getattr(call, 'lineno', '?')}"

                if name.split(".")[-1] in BOUNDARY_CALLS and call.args:
                    label = _literal_text(call.args[0], env)
                    if label:
                        boundary = f"boundary:approval:{label}"
                        graph.boundaries.add(boundary)
                        graph.add(
                            cursor,
                            boundary,
                            "crosses_boundary",
                            evidence,
                            certain=call_certain,
                        )
                        cursor = boundary
                        continue

                short = name.split(".")[-1]
                if short in function_names and short != func.name:
                    graph.add(
                        cursor,
                        f"function:{short}",
                        "calls",
                        evidence,
                        certain=call_certain,
                    )

                if name.endswith("run_workflow") and call.args:
                    wf = _literal_text(call.args[0], env)
                    if wf:
                        graph.add(
                            cursor,
                            f"workflow:{Path(wf).name}",
                            "mcp_workflow_dispatch",
                            evidence,
                            certain=call_certain,
                        )
                        continue

                for arg in list(call.args) + [kw.value for kw in call.keywords]:
                    resolved = _effect_text(arg, env)
                    if not resolved:
                        continue
                    text, certain = resolved
                    match = REST_DISPATCH_RE.search(text)
                    if match:
                        graph.add(
                            cursor,
                            f"workflow:{Path(match.group(1)).name}",
                            (
                                "rest_workflow_dispatch"
                                if certain
                                else "possible_rest_workflow_dispatch"
                            ),
                            evidence,
                            certain=certain,
                        )

                if name in {
                    "subprocess.run",
                    "subprocess.call",
                    "subprocess.check_call",
                    "os.system",
                } and call.args:
                    cmd = _command_text(call.args[0], env)
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
                                certain=call_certain,
                            )
                            linked_script = True

                    match = WORKFLOW_RUN_RE.search(cmd)
                    if match:
                        graph.add(
                            cursor,
                            "effect:shell.exec",
                            "invokes",
                            evidence,
                            certain=call_certain,
                        )
                        graph.add(
                            "effect:shell.exec",
                            f"workflow:{Path(match.group(1)).name}",
                            "gh_workflow_dispatch",
                            evidence,
                            certain=call_certain,
                        )
                    elif GIT_PUSH_RE.search(cmd):
                        graph.add(
                            cursor,
                            "effect:git_push",
                            "invokes",
                            evidence,
                            certain=call_certain,
                        )
                    elif not linked_script:
                        # The shell execution exists, but this RETEST model cannot
                        # yet resolve its effect to a protected consequence.
                        graph.add(
                            cursor,
                            "effect:shell.exec:unknown",
                            "invokes",
                            evidence,
                            certain=call_certain,
                        )

    # Supplement the global call graph with callsite-specific function
    # instances whenever a direct call supplies at least one static argument.
    # This lets two callers of the same helper retain different bindings.
    for py, tree in parsed:
        rel = py.relative_to(repo)
        for caller in tree.body:
            if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            caller_initial = _merge_envs(
                module_envs.get(py),
                parameter_envs.get(caller.name),
            )
            caller_node = f"function:{caller.name}"

            for call, call_env, call_certain in _iter_reachable_calls(
                caller,
                caller_initial,
                function_returns,
            ):
                name = _call_name(call) or ""
                callee_name = name.split(".")[-1]
                callee = function_defs.get(callee_name)
                if callee is None or callee_name == caller.name:
                    continue

                bindings = _bindings_from_env(
                    call,
                    callee,
                    call_env,
                )
                if not bindings:
                    continue

                line = getattr(call, "lineno", 0)
                binding_label = ",".join(
                    f"{key}={value!r}"
                    for key, value in sorted(bindings.items())
                )
                context_node = (
                    f"context:{callee_name}@{caller.name}:{line}"
                    f"[{binding_label}]"
                )
                evidence = f"{rel}:{line}"
                graph.add(
                    caller_node,
                    context_node,
                    "calls_with_context",
                    evidence,
                    certain=call_certain,
                )
                _add_effect_edges_for_function_context(
                    repo=repo,
                    graph=graph,
                    rel=rel,
                    func=callee,
                    context_node=context_node,
                    initial_env=_merge_envs(
                        function_module_envs.get(callee_name),
                        bindings,
                    ),
                    function_names=function_names,
                )

    # Model explicit script execution as a separate root. This does not claim
    # modules execute automatically: the node "module:<path>" means the file is
    # executed as a script, so __name__ == "__main__" is true.
    for py, tree in parsed:
        rel = py.relative_to(repo)
        module_body = [
            stmt
            for stmt in tree.body
            if not isinstance(
                stmt,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Import,
                    ast.ImportFrom,
                ),
            )
        ]
        if not module_body:
            continue

        pseudo = ast.FunctionDef(
            name="__module_scope__",
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=module_body,
            decorator_list=[],
            returns=None,
            type_comment=None,
        )
        module_node = f"module:{rel.as_posix()}"
        _add_effect_edges_for_function_context(
            repo=repo,
            graph=graph,
            rel=rel,
            func=pseudo,
            context_node=module_node,
            initial_env=_merge_envs(
                module_envs.get(py),
                {"__name__": "__main__"},
            ),
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

    queue: list[
        tuple[str, bool, bool, tuple[str, ...], tuple[str, ...]]
    ] = []
    for root in sorted(graph.roots):
        queue.append((root, root == boundary, True, (root,), ()))
    seen: set[tuple[str, bool, bool]] = set()
    saw_target_via_boundary = False
    saw_uncertain_target = False

    while queue:
        node, crossed, path_certain, path, evidence = queue.pop(0)
        state = (node, crossed, path_certain)
        if state in seen:
            continue
        seen.add(state)
        if node == target:
            if not path_certain:
                saw_uncertain_target = True
                continue
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
                (
                    edge.dst,
                    nxt_crossed,
                    path_certain and edge.certain,
                    path + (edge.dst,),
                    evidence + (edge.evidence,),
                )
            )

    if saw_uncertain_target:
        return Finding("UNKNOWN", property_name, consequence, required_boundary)
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
