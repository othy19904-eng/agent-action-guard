from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from retest_lab.analyzer import Edge, Graph, build_graph


@dataclass(frozen=True)
class ScanResult:
    status: str
    root: str
    target: str
    path: tuple[str, ...] = ()
    edges: tuple[Edge, ...] = ()

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "root": self.root,
            "target": self.target,
            "path": list(self.path),
            "edges": [
                {
                    "src": edge.src,
                    "dst": edge.dst,
                    "kind": edge.kind,
                    "evidence": edge.evidence,
                    "certain": edge.certain,
                }
                for edge in self.edges
            ],
            "note": (
                "PROVEN means the modeled path is supported entirely by certain "
                "edges. It is not a repository-wide completeness claim."
            ),
        }


def normalize_root(value: str) -> str:
    return value if ":" in value else f"function:{value}"


def normalize_target(value: str) -> str:
    return value if ":" in value else f"workflow:{value}"


def scan_graph(graph: Graph, root: str, target: str) -> ScanResult:
    """Return the strongest modeled path from root to target.

    Certain paths are preferred over uncertain paths. An uncertain path is
    reported as POSSIBLE. No modeled path is UNKNOWN.
    """
    root = normalize_root(root)
    target = normalize_target(target)

    queue: list[tuple[str, bool, tuple[str, ...], tuple[Edge, ...]]] = [
        (root, True, (root,), ())
    ]
    seen: set[tuple[str, bool]] = set()
    possible: ScanResult | None = None

    while queue:
        node, certain, path, edges = queue.pop(0)
        state = (node, certain)
        if state in seen:
            continue
        seen.add(state)

        if node == target:
            result = ScanResult(
                "PROVEN" if certain else "POSSIBLE",
                root,
                target,
                path,
                edges,
            )
            if certain:
                return result
            if possible is None:
                possible = result
            continue

        for edge in graph.outgoing(node):
            queue.append(
                (
                    edge.dst,
                    certain and edge.certain,
                    path + (edge.dst,),
                    edges + (edge,),
                )
            )

    if possible is not None:
        return possible
    return ScanResult("UNKNOWN", root, target)


def scan_repository(repo: str | Path, root: str, target: str) -> ScanResult:
    return scan_graph(build_graph(repo), root, target)


def render_text(result: ScanResult) -> str:
    lines = [
        result.status,
        f"root:   {result.root}",
        f"target: {result.target}",
    ]

    if not result.edges:
        lines += [
            "path:   none found in the current model",
            "",
            "UNKNOWN does not mean the path is impossible.",
        ]
        return "\n".join(lines)

    lines.append("path:")
    lines.append(f"  {result.path[0]}")
    for edge in result.edges:
        certainty = "certain" if edge.certain else "uncertain"
        lines.append(
            f"  -> {edge.dst}  [{edge.kind}; {certainty}; {edge.evidence}]"
        )

    if result.status == "PROVEN":
        lines += [
            "",
            "PROVEN means this modeled path is supported entirely by certain edges.",
            "It is not a claim that every repository execution path was modeled.",
        ]
    else:
        lines += [
            "",
            "POSSIBLE means at least one edge depends on unresolved runtime state.",
            "It must not be treated as a proven bypass.",
        ]

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m retest_lab",
        description=(
            "Trace modeled execution paths from a repository entrypoint "
            "to a GitHub workflow consequence."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one root -> target path")
    scan.add_argument(
        "--repo",
        default=".",
        help="repository directory (default: current directory)",
    )
    scan.add_argument(
        "--root",
        required=True,
        help="entrypoint, e.g. main or function:main",
    )
    scan.add_argument(
        "--target",
        required=True,
        help="workflow target, e.g. deploy.yml or workflow:deploy.yml",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        result = scan_repository(args.repo, args.root, args.target)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print(render_text(result))
        return 0

    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
