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
    expected: str  # FOUND for a known reachable path, MISSED for a negative control


CASES = (
    # Existing positive cases.
    Case(
        name="travel-guide-direct-gh",
        repository="alx/travel-guide",
        commit="137020d6e3e5fc217373ea5d633ae3c6eace9130",
        root="function:git_push_and_deploy",
        target="workflow:deploy.yml",
        mechanism="direct subprocess gh workflow run deploy.yml",
        expected="FOUND",
    ),
    Case(
        name="dpik-brief-direct-gh",
        repository="arhsmoque/dpik-brief",
        commit="e83d4360500c347413e46128cbb543d94c405f48",
        root="function:gh_workflow_run",
        target="workflow:deploy.yml",
        mechanism="direct subprocess literal workflow plus dynamic --repo",
        expected="FOUND",
    ),
    Case(
        name="questdb-fstring-workflow",
        repository="questdb/questdb",
        commit="b7bb98f43d32af424f897c56ef2098862fb948b1",
        root="function:main",
        target="workflow:rebuild_rust.yml",
        mechanism="argparse choices -> loop -> helper -> f-string workflow name",
        expected="FOUND",
    ),
    Case(
        name="demos-os-linux-wrapper",
        repository="veltzer/demos-os-linux",
        commit="5b5ca011c356345d50574b8c911b8c14583808f9",
        root="function:main",
        target="workflow:image.yml",
        mechanism="custom run wrapper plus module WORKFLOW constant",
        expected="FOUND",
    ),
    Case(
        name="tokyo-grid-dynamic-rest",
        repository="wonhongChang/tokyo-grid-ems",
        commit="c681cf942d182c7b86c0680411dfbedfc8c1346d",
        root="function:main",
        target="workflow:deploy.yml",
        mechanism="argparse default -> helper -> partially dynamic REST dispatch URL",
        expected="FOUND",
    ),

    # Negative controls on the same repositories. These roots should not reach
    # the protected workflow target.
    Case(
        name="travel-guide-negative-generate",
        repository="alx/travel-guide",
        commit="137020d6e3e5fc217373ea5d633ae3c6eace9130",
        root="function:generate",
        target="workflow:deploy.yml",
        mechanism="data generation function with no deployment path",
        expected="MISSED",
    ),
    Case(
        name="dpik-negative-auth-check",
        repository="arhsmoque/dpik-brief",
        commit="e83d4360500c347413e46128cbb543d94c405f48",
        root="function:gh_auth_check",
        target="workflow:deploy.yml",
        mechanism="gh auth status only",
        expected="MISSED",
    ),
    Case(
        name="questdb-negative-auth-check",
        repository="questdb/questdb",
        commit="b7bb98f43d32af424f897c56ef2098862fb948b1",
        root="function:check_gh_authentication",
        target="workflow:rebuild_rust.yml",
        mechanism="gh auth status only",
        expected="MISSED",
    ),
    Case(
        name="demos-negative-generic-run",
        repository="veltzer/demos-os-linux",
        commit="5b5ca011c356345d50574b8c911b8c14583808f9",
        root="function:run",
        target="workflow:image.yml",
        mechanism="generic wrapper without callsite binding",
        expected="MISSED",
    ),
    Case(
        name="tokyo-negative-token-resolution",
        repository="wonhongChang/tokyo-grid-ems",
        commit="c681cf942d182c7b86c0680411dfbedfc8c1346d",
        root="function:_github_token",
        target="workflow:deploy.yml",
        mechanism="credential resolution without dispatch",
        expected="MISSED",
    ),

    # Second-wave positive cases: new repositories and mechanism classes.
    Case(
        name="fmt-module-scope-rest",
        repository="fmtlib/fmt",
        commit="79e48ba9156acb565b4aaa565b2ae2a58da798d2",
        root="module:support/release.py",
        target="workflow:release.yml",
        mechanism="module-scope static urllib REST workflow dispatch",
        expected="FOUND",
    ),
    Case(
        name="opendelta-wrapper-deploy",
        repository="ven2day/opendelta-nse",
        commit="8f918aa166c437d354012c0d0964520a3ba9140b",
        root="function:main",
        target="workflow:deploy.yml",
        mechanism="module constants -> trigger helper -> custom run wrapper",
        expected="FOUND",
    ),
    Case(
        name="turf-mobile-python-tuple-loop",
        repository="MehulBlitz/turf-mobile",
        commit="c0f14548f1375a991bbba224855203c841b39f03",
        root="function:main",
        target="workflow:firebase-deploy.yml",
        mechanism="module list of workflow tuples -> tuple-unpacking loop -> helper",
        expected="FOUND",
    ),
    Case(
        name="turf-mobile-shell-direct",
        repository="MehulBlitz/turf-mobile",
        commit="c0f14548f1375a991bbba224855203c841b39f03",
        root="script:scripts/trigger-all-workflows.sh",
        target="workflow:firebase-deploy.yml",
        mechanism="shell gh workflow run with dynamic repo/ref flags",
        expected="FOUND",
    ),
    Case(
        name="inet-rest-helper-defaults",
        repository="inet-framework/inet",
        commit="98117c3257b2e11661d2baf685c18911c8639b24",
        root="function:start_chart_tests_github_workflow",
        target="workflow:chart-tests.yml",
        mechanism="literal helper arg + default owner/repository -> requests.post REST dispatch",
        expected="FOUND",
    ),

    # Third-wave cases: additional repositories and transport/path shapes.
    Case(
        name="pudl-shell-dispatch",
        repository="catalyst-cooperative/pudl",
        commit="ebd0281a7d74160af7eb299a4c96f8f2cf3d1e9f",
        root="script:builds/pudl_batch.sh",
        target="workflow:deploy-pudl.yml",
        mechanism="shell gh workflow run with environment-driven flags",
        expected="FOUND",
    ),
    Case(
        name="pudl-negative-zip-helper",
        repository="catalyst-cooperative/pudl",
        commit="ebd0281a7d74160af7eb299a4c96f8f2cf3d1e9f",
        root="function:_zip_parquet_files",
        target="workflow:deploy-pudl.yml",
        mechanism="local archive helper with no workflow dispatch",
        expected="MISSED",
    ),
    Case(
        name="mc-san-dynamic-rest-dispatch",
        repository="retiredroca/mc-storage-area-network",
        commit="ab62e4da8f00c9076ce5c5bbc6daa4c57d3d4e08",
        root="function:dispatch_publish_ci",
        target="workflow:publish-release.yml",
        mechanism="dynamic repo_slug plus static workflow in urllib REST URL",
        expected="FOUND",
    ),
    Case(
        name="mc-san-negative-token",
        repository="retiredroca/mc-storage-area-network",
        commit="ab62e4da8f00c9076ce5c5bbc6daa4c57d3d4e08",
        root="function:github_token",
        target="workflow:publish-release.yml",
        mechanism="credential resolution helper without dispatch",
        expected="MISSED",
    ),
    Case(
        name="electron-riscv-main-dispatch",
        repository="riscv-forks/electron-riscv-releases",
        commit="5a16498f6e87b9d85aba9fb30888b7ea2c0f4ad2",
        root="function:main",
        target="workflow:release.yml",
        mechanism="environment defaults -> planning loop -> REST helper dispatch",
        expected="FOUND",
    ),

    # Deeper entrypoints and paired controls.
    Case(
        name="pudl-python-zenodo-dispatch",
        repository="catalyst-cooperative/pudl",
        commit="ebd0281a7d74160af7eb299a4c96f8f2cf3d1e9f",
        root="function:trigger_zenodo_release",
        target="workflow:zenodo-data-release.yml",
        mechanism="business helper -> generic REST dispatcher with static workflow",
        expected="FOUND",
    ),
    Case(
        name="pudl-negative-gcs-hold",
        repository="catalyst-cooperative/pudl",
        commit="ebd0281a7d74160af7eb299a4c96f8f2cf3d1e9f",
        root="function:set_gcs_temporary_hold",
        target="workflow:zenodo-data-release.yml",
        mechanism="cloud storage mutation helper with no GitHub dispatch",
        expected="MISSED",
    ),
    Case(
        name="electron-riscv-negative-fetch-releases",
        repository="riscv-forks/electron-riscv-releases",
        commit="5a16498f6e87b9d85aba9fb30888b7ea2c0f4ad2",
        root="function:fetch_stable_releases",
        target="workflow:release.yml",
        mechanism="read-only upstream release fetch",
        expected="MISSED",
    ),
    Case(
        name="mc-san-main-to-publish",
        repository="retiredroca/mc-storage-area-network",
        commit="ab62e4da8f00c9076ce5c5bbc6daa4c57d3d4e08",
        root="function:main",
        target="workflow:publish-release.yml",
        mechanism="full release orchestration -> dynamic REST publish dispatch",
        expected="FOUND",
    ),
    Case(
        name="mc-san-negative-verify",
        repository="retiredroca/mc-storage-area-network",
        commit="ab62e4da8f00c9076ce5c5bbc6daa4c57d3d4e08",
        root="function:verify",
        target="workflow:publish-release.yml",
        mechanism="local artifact verification with no workflow dispatch",
        expected="MISSED",
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


def repo_dir_for(case: Case, workspace: Path) -> Path:
    safe_repo = case.repository.replace("/", "__")
    return workspace / f"{safe_repo}-{case.commit[:12]}"


def checkout_case(case: Case, target: Path) -> None:
    if (target / ".git").exists():
        return
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


def find_path(
    graph: Graph,
    root: str,
    target: str,
) -> tuple[tuple[str, ...], bool] | None:
    queue: list[tuple[str, bool, tuple[str, ...]]] = [(root, True, (root,))]
    seen: set[tuple[str, bool]] = set()

    while queue:
        node, certain, path = queue.pop(0)
        state = (node, certain)
        if state in seen:
            continue
        seen.add(state)

        if node == target:
            return path, certain

        for edge in graph.outgoing(node):
            queue.append(
                (
                    edge.dst,
                    certain and edge.certain,
                    path + (edge.dst,),
                )
            )

    return None


def run_case(case: Case, workspace: Path, graph_cache: dict[Path, Graph]) -> dict:
    repo_dir = repo_dir_for(case, workspace)
    checkout_case(case, repo_dir)
    graph = graph_cache.get(repo_dir)
    if graph is None:
        graph = build_graph(repo_dir)
        graph_cache[repo_dir] = graph

    found = find_path(graph, case.root, case.target)
    path = found[0] if found else ()
    path_certain = found[1] if found else False
    observed = (
        "FOUND"
        if found and path_certain
        else "POSSIBLE"
        if found
        else "MISSED"
    )

    return {
        "name": case.name,
        "repository": case.repository,
        "commit": case.commit,
        "root": case.root,
        "target": case.target,
        "mechanism": case.mechanism,
        "expected": case.expected,
        "observed": observed,
        "expectation_met": observed == case.expected,
        "path": list(path),
        "path_certain": path_certain,
        "edge_count": len(graph.edges),
    }


def metrics(results: list[dict]) -> dict:
    positives = [r for r in results if r["expected"] == "FOUND"]
    negatives = [r for r in results if r["expected"] == "MISSED"]
    return {
        "cases": len(results),
        "positive_cases": len(positives),
        "negative_controls": len(negatives),
        "confirmed_positive": sum(r["observed"] == "FOUND" for r in positives),
        "uncertain_positive": sum(r["observed"] == "POSSIBLE" for r in positives),
        "missed_positive": sum(r["observed"] == "MISSED" for r in positives),
        "true_negative": sum(r["observed"] == "MISSED" for r in negatives),
        "false_positive_certain": sum(r["observed"] == "FOUND" for r in negatives),
        "false_positive_possible": sum(r["observed"] == "POSSIBLE" for r in negatives),
        "errors": sum(r["observed"] == "ERROR" for r in results),
    }


def markdown(results: list[dict]) -> str:
    m = metrics(results)
    lines = [
        "# Consequence Boundary Completeness - real-world RETEST",
        "",
        f"Cases: {m['cases']} across pinned public repositories",
        f"Positive cases: {m['positive_cases']}",
        f"Negative controls: {m['negative_controls']}",
        f"Confirmed positive paths: {m['confirmed_positive']}",
        f"Uncertain positive paths: {m['uncertain_positive']}",
        f"Missed positive paths: {m['missed_positive']}",
        f"True negatives: {m['true_negative']}",
        f"Certain false positives: {m['false_positive_certain']}",
        f"Possible false positives: {m['false_positive_possible']}",
        "",
        "| Case | Repository | Expected | Observed | Mechanism |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['name']} | {r['repository']} | {r['expected']} | "
            f"{r['observed']} | {r['mechanism']} |"
        )

    lines += ["", "## Recovered paths", ""]
    for r in results:
        if r["path"]:
            qualifier = "certain" if r["path_certain"] else "uncertain"
            lines.append(f"### {r['name']} ({qualifier})")
            for node in r["path"]:
                lines.append(f"    {node}")
            lines.append("")

    lines += [
        "## Interpretation",
        "",
        "This benchmark is diagnostic, not a product claim. FOUND means the modeled "
        "path is fully supported by certain edges. POSSIBLE means the target is "
        "reachable only through at least one incomplete/uncertain extraction edge. "
        "MISSED is correct for negative controls but a recall failure for positive cases.",
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
        graph_cache: dict[Path, Graph] = {}
        results: list[dict] = []
        for case in CASES:
            print(f"[benchmark] {case.repository}@{case.commit[:12]} {case.name}", flush=True)
            try:
                result = run_case(case, workspace, graph_cache)
            except subprocess.CalledProcessError as exc:
                result = {
                    "name": case.name,
                    "repository": case.repository,
                    "commit": case.commit,
                    "root": case.root,
                    "target": case.target,
                    "mechanism": case.mechanism,
                    "expected": case.expected,
                    "observed": "ERROR",
                    "expectation_met": False,
                    "path": [],
                    "path_certain": False,
                    "error": exc.stderr[-1000:] if exc.stderr else str(exc),
                }
            results.append(result)
            print(
                f"[benchmark] {case.name}: expected={case.expected} "
                f"observed={result['observed']}",
                flush=True,
            )

    m = metrics(results)
    payload = {**m, "results": results}
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

    return 1 if m["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
