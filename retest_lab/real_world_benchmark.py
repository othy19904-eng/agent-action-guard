from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from retest_lab.analyzer import Graph, build_graph


@dataclass(frozen=True)
class Case:
    name: str
    repository: str
    commit: str
    root: str
    target: str
    mechanism: str
    baseline_expectation: str


CASES = (
    Case(
        name="travel-guide-direct-gh",
        repository="alx/travel-guide",
        commit="137020d6e3e5fc217373ea5d633ae3c6eace9130",
        root="function:git_push_and_deploy",
        target="workflow:deploy.yml",
        mechanism="direct subprocess gh workflow run deploy.yml",
        baseline_expectation="FOUND",
    ),
    Case(
        name="dpik-brief-direct-gh",
        repository="arhsmoque/dpik-brief",
        commit="e83d4360500c347413e46128cbb543d94c405f48",
        root="function:gh_workflow_run",
        target="workflow:deploy.yml",
        mechanism="direct subprocess literal workflow plus --repo",
        baseline_expectation="FOUND",
    ),
    Case(
        name="questdb-fstring-workflow",
        repository="questdb/questdb",
        commit="b7bb98f43d32af424f897c56ef2098862fb948b1",
        root="function:main",
        target="workflow:rebuild_rust.yml",
        mechanism="subprocess with f-string workflow name",
        baseline_expectation="MISSED_KNOWN_GAP",
    ),
    Case(
        name="demos-os-linux-wrapper",
        repository="veltzer/demos-os-linux",
        commit="5b5ca011c356345d50574b8c911b8c14583808f9",
        root="function:main",
        target="workflow:image.yml",
        mechanism="custom run wrapper plus module WORKFLOW constant",
        baseline_expectation="MISSED_KNOWN_GAP",
    ),
    Case(
        name="tokyo-grid-dynamic-rest",
        repository="wonhongChang/tokyo-grid-ems",
        commit="c681cf942d182c7b86c0680411dfbedfc8c1346d",
        root="function:main",
        target="workflow:deploy.yml",
        mechanism="urllib Request to dynamically built workflow-dispatch URL",
        baseline_expectation="MISSED_KNOWN_GAP",
    ),
)


def _run(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(
        list(args),
        cwd=cwd,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def checkout_case(case: Case, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    _run("git", "init", "-q", cwd=target)
    _run(
        "git",
        "remote",
        "add",
        "origin",
        f"https://github.com/{case.repository}.git",
        cwd=target,
    )
    _run(
        "git",
        "fetch",
        "-q",
        "--depth",
        "1",
        "origin",
        case.commit,
        cwd=target,
    )
    _run("git", "checkout", "-q", "FETCH_HEAD", cwd=target)


def find_path(graph: Graph, root: str, target: str) -> tuple[str, ...] | None:
    queue: list[tuple[str, tuple[str, ...]]] = [(root, (root,))]
    seen: set[str] = set()

    while queue:
        node, path = queue.pop(0)
        if node in seen:
            continue
        seen.add(node)

        if node == target:
            return path

        for edge in graph.outgoing(node):
            queue.append((edge.dst, path + (edge.dst,)))

    return None


def run_case(case: Case, workspace: Path) -> dict:
    repo_dir = workspace / case.name
    checkout_case(case, repo_dir)
    graph = build_graph(repo_dir)
    path = find_path(graph, case.root, case.target)
    observed = "FOUND" if path else "MISSED"
    expectation_met = (
        observed == "FOUND"
        if case.baseline_expectation == "FOUND"
        else observed == "MISSED"
    )

    return {
        "name": case.name,
        "repository": case.repository,
        "commit": case.commit,
        "root": case.root,
        "target": case.target,
        "mechanism": case.mechanism,
        "baseline_expectation": case.baseline_expectation,
        "observed": observed,
        "expectation_met": expectation_met,
        "path": list(path or ()),
        "edge_count": len(graph.edges),
    }


def markdown(results: list[dict]) -> str:
    found = sum(r["observed"] == "FOUND" for r in results)
    missed = sum(r["observed"] == "MISSED" for r in results)
    lines = [
        "# Consequence Boundary Completeness - real-world RETEST",
        "",
        f"Corpus: {len(results)} pinned public repositories",
        f"Paths found: {found}",
        f"Paths missed: {missed}",
        "",
        "| Case | Repository | Mechanism | Baseline | Observed |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['name']} | {r['repository']} | {r['mechanism']} | "
            f"{r['baseline_expectation']} | {r['observed']} |"
        )

    lines += ["", "## Recovered paths", ""]
    for r in results:
        if r["path"]:
            lines.append(f"### {r['name']}")
            for node in r["path"]:
                lines.append(f"    {node}")
            lines.append("")

    lines += [
        "## Interpretation",
        "",
        "This benchmark is diagnostic, not a product claim. A missed path is evidence "
        "about extractor coverage. A found path does not imply repository-wide "
        "enforcement completeness.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out")
    parser.add_argument("--markdown-out")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="cbc-real-world-") as td:
        workspace = Path(td)
        results: list[dict] = []
        for case in CASES:
            print(f"[benchmark] {case.repository}@{case.commit[:12]}", flush=True)
            try:
                result = run_case(case, workspace)
            except subprocess.CalledProcessError as exc:
                result = {
                    "name": case.name,
                    "repository": case.repository,
                    "commit": case.commit,
                    "root": case.root,
                    "target": case.target,
                    "mechanism": case.mechanism,
                    "baseline_expectation": case.baseline_expectation,
                    "observed": "ERROR",
                    "expectation_met": False,
                    "path": [],
                    "error": exc.stderr[-1000:] if exc.stderr else str(exc),
                }
            results.append(result)
            print(f"[benchmark] {case.name}: {result['observed']}", flush=True)

    payload = {
        "corpus_size": len(results),
        "found": sum(r["observed"] == "FOUND" for r in results),
        "missed": sum(r["observed"] == "MISSED" for r in results),
        "errors": sum(r["observed"] == "ERROR" for r in results),
        "results": results,
    }

    rendered = markdown(results)
    print(json.dumps(payload, indent=2))
    print(rendered)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.markdown_out:
        Path(args.markdown_out).write_text(rendered + "\n", encoding="utf-8")

    return 1 if payload["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
