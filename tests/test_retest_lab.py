import tempfile
import textwrap
import unittest
from pathlib import Path

from retest_lab.analyzer import analyze, build_graph


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures"


class RetestLabTests(unittest.TestCase):
    def test_finds_counterexample(self):
        finding = analyze(FIXTURE)
        self.assertEqual(finding.status, "COUNTEREXAMPLE_FOUND")
        self.assertTrue(finding.path[0].startswith("function:agent_"))
        self.assertEqual(finding.path[-1], "consequence:production_deploy")
        self.assertNotIn("boundary:approval:P", finding.path)

    def test_finds_multistep_helper_shell_workflow_counterexample(self):
        graph = build_graph(FIXTURE)
        graph.roots = {"function:agent_helper_bypass"}
        from retest_lab.analyzer import find_counterexample

        finding = find_counterexample(graph)
        self.assertEqual(finding.status, "COUNTEREXAMPLE_FOUND")
        self.assertEqual(
            finding.path,
            (
                "function:agent_helper_bypass",
                "function:trigger_prod",
                "effect:shell.exec",
                "workflow:deploy.yml",
                "consequence:production_deploy",
            ),
        )

    def test_discovers_cross_file_shell_script_bypass(self):
        graph = build_graph(FIXTURE)
        graph.roots = {"function:agent_external_script_bypass"}
        from retest_lab.analyzer import find_counterexample

        finding = find_counterexample(graph)
        self.assertEqual(finding.status, "COUNTEREXAMPLE_FOUND")
        self.assertEqual(
            finding.path,
            (
                "function:agent_external_script_bypass",
                "script:scripts/deploy.sh",
                "workflow:deploy.yml",
                "consequence:production_deploy",
            ),
        )

    def test_discovers_dataflow_indirection_bypass(self):
        graph = build_graph(FIXTURE)
        graph.roots = {"function:agent_dataflow_bypass"}
        from retest_lab.analyzer import find_counterexample

        finding = find_counterexample(graph)
        self.assertEqual(finding.status, "COUNTEREXAMPLE_FOUND")
        self.assertEqual(
            finding.path,
            (
                "function:agent_dataflow_bypass",
                "effect:shell.exec",
                "workflow:deploy.yml",
                "consequence:production_deploy",
            ),
        )

    def test_discovers_interprocedural_argument_flow_bypass(self):
        graph = build_graph(FIXTURE)
        graph.roots = {"function:agent_interprocedural_bypass"}
        from retest_lab.analyzer import find_counterexample

        finding = find_counterexample(graph)
        self.assertEqual(finding.status, "COUNTEREXAMPLE_FOUND")
        self.assertEqual(
            finding.path,
            (
                "function:agent_interprocedural_bypass",
                "function:launch_workflow",
                "effect:shell.exec",
                "workflow:deploy.yml",
                "consequence:production_deploy",
            ),
        )

    def test_context_sensitive_callsites_are_kept_separate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def agent_prod():
                        launch("deploy.yml")

                    def agent_staging():
                        launch("staging.yml")

                    def launch(workflow):
                        cmd = ["gh", "workflow", "run", workflow]
                        subprocess.run(cmd, check=True)
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/deploy.yml").write_text(
                textwrap.dedent(
                    """\
                    on:
                      workflow_dispatch:
                    jobs:
                      deploy:
                        environment: production
                        steps:
                          - run: echo production_deploy
                    """
                ),
                encoding="utf-8",
            )

            graph = build_graph(root)
            from retest_lab.analyzer import find_counterexample

            graph.roots = {"function:agent_prod"}
            prod = find_counterexample(graph)
            self.assertEqual(prod.status, "COUNTEREXAMPLE_FOUND")
            self.assertIn("workflow:deploy.yml", prod.path)

            graph.roots = {"function:agent_staging"}
            staging = find_counterexample(graph)
            self.assertEqual(staging.status, "UNKNOWN")

    def test_context_sensitive_constant_branches_are_respected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def agent_prod():
                        launch("deploy.yml", True)

                    def agent_safe():
                        launch("deploy.yml", False)

                    def launch(workflow, allow_prod):
                        if allow_prod:
                            subprocess.run(
                                ["gh", "workflow", "run", workflow],
                                check=True,
                            )
                        else:
                            print("dry-run only")
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/deploy.yml").write_text(
                textwrap.dedent(
                    """\
                    on:
                      workflow_dispatch:
                    jobs:
                      deploy:
                        environment: production
                        steps:
                          - run: echo production_deploy
                    """
                ),
                encoding="utf-8",
            )

            graph = build_graph(root)
            from retest_lab.analyzer import find_counterexample

            graph.roots = {"function:agent_prod"}
            prod = find_counterexample(graph)
            self.assertEqual(prod.status, "COUNTEREXAMPLE_FOUND")

            graph.roots = {"function:agent_safe"}
            safe = find_counterexample(graph)
            self.assertEqual(safe.status, "UNKNOWN")

    def test_unknown_branch_condition_stays_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def agent_unknown(flag):
                        launch("deploy.yml", flag)

                    def launch(workflow, allow_prod):
                        if allow_prod:
                            subprocess.run(
                                ["gh", "workflow", "run", workflow],
                                check=True,
                            )
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/deploy.yml").write_text(
                textwrap.dedent(
                    """\
                    on:
                      workflow_dispatch:
                    jobs:
                      deploy:
                        environment: production
                        steps:
                          - run: echo production_deploy
                    """
                ),
                encoding="utf-8",
            )

            graph = build_graph(root)
            graph.roots = {"function:agent_unknown"}
            from retest_lab.analyzer import find_counterexample

            finding = find_counterexample(graph)
            self.assertEqual(finding.status, "UNKNOWN")

    def test_dynamic_trailing_command_arg_keeps_static_workflow_prefix(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def agent_dispatch(repo):
                        subprocess.run(
                            ["gh", "workflow", "run", "deploy.yml", "--repo", repo],
                            check=True,
                        )
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/deploy.yml").write_text(
                textwrap.dedent(
                    """\
                    on:
                      workflow_dispatch:
                    jobs:
                      deploy:
                        environment: production
                        steps:
                          - run: echo production_deploy
                    """
                ),
                encoding="utf-8",
            )

            graph = build_graph(root)
            graph.roots = {"function:agent_dispatch"}
            from retest_lab.analyzer import find_counterexample

            finding = find_counterexample(graph)
            self.assertEqual(finding.status, "COUNTEREXAMPLE_FOUND")

    def test_static_fstring_workflow_name_is_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def agent_fstring():
                        action = "deploy"
                        subprocess.run(
                            ["gh", "workflow", "run", f"{action}.yml"],
                            check=True,
                        )
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/deploy.yml").write_text(
                "on:\n  workflow_dispatch:\n",
                encoding="utf-8",
            )

            graph = build_graph(root)
            paths = {(e.src, e.dst) for e in graph.edges}
            self.assertIn(
                ("effect:shell.exec", "workflow:deploy.yml"),
                paths,
            )

    def test_wrapper_with_module_constant_workflow_is_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    WORKFLOW = "image.yml"

                    def run(args):
                        return subprocess.run(args, check=False)

                    def agent_wrapper():
                        run(["gh", "workflow", "run", WORKFLOW])
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/image.yml").write_text(
                "on:\n  workflow_dispatch:\n",
                encoding="utf-8",
            )

            graph = build_graph(root)
            graph.roots = {"function:agent_wrapper"}
            from retest_lab.analyzer import find_counterexample

            path_nodes = set()
            queue = list(graph.roots)
            while queue:
                node = queue.pop(0)
                if node in path_nodes:
                    continue
                path_nodes.add(node)
                queue.extend(edge.dst for edge in graph.outgoing(node))

            self.assertIn("workflow:image.yml", path_nodes)

    def test_argparse_choices_flow_through_loop_into_fstring(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import argparse
                    import subprocess

                    ACTIONS = ["rebuild_rust", "other"]

                    def trigger(action):
                        subprocess.run(
                            ["gh", "workflow", "run", f"{action}.yml"],
                            check=True,
                        )

                    def parse_args():
                        parser = argparse.ArgumentParser()
                        parser.add_argument("actions", choices=ACTIONS, nargs="*")
                        return parser.parse_args()

                    def agent_cli():
                        args = parse_args()
                        for action in args.actions:
                            trigger(action)
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/rebuild_rust.yml").write_text(
                "on:\n  workflow_dispatch:\n",
                encoding="utf-8",
            )
            (root / ".github/workflows/other.yml").write_text(
                "on:\n  workflow_dispatch:\n",
                encoding="utf-8",
            )

            graph = build_graph(root)
            graph.roots = {"function:agent_cli"}

            reachable = set()
            queue = list(graph.roots)
            while queue:
                node = queue.pop(0)
                if node in reachable:
                    continue
                reachable.add(node)
                queue.extend(edge.dst for edge in graph.outgoing(node))

            self.assertIn("workflow:rebuild_rust.yml", reachable)
            self.assertIn("workflow:other.yml", reachable)

    def test_graph_links_shell_to_workflow_to_consequence(self):
        graph = build_graph(FIXTURE)
        triples = {(e.src, e.dst, e.kind) for e in graph.edges}
        self.assertIn(
            ("effect:shell.exec", "workflow:deploy.yml", "gh_workflow_dispatch"),
            triples,
        )
        self.assertIn(
            (
                "workflow:deploy.yml",
                "consequence:production_deploy",
                "reaches_consequence",
            ),
            triples,
        )

    def test_guarded_only_path_is_covered_within_model(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "agent").mkdir()
            (root / ".github/workflows").mkdir(parents=True)
            (root / "agent/main.py").write_text(
                textwrap.dedent(
                    """\
                    def require_approval(label): pass
                    class github_mcp:
                        @staticmethod
                        def run_workflow(name): pass
                    def agent_guarded():
                        require_approval("P")
                        github_mcp.run_workflow("deploy.yml")
                    """
                ),
                encoding="utf-8",
            )
            (root / ".github/workflows/deploy.yml").write_text(
                textwrap.dedent(
                    """\
                    on:
                      workflow_dispatch:
                    jobs:
                      deploy:
                        environment: production
                        steps:
                          - run: echo production_deploy
                    """
                ),
                encoding="utf-8",
            )
            finding = analyze(root)
            self.assertEqual(finding.status, "COVERED_WITHIN_MODEL")

    def test_no_modeled_consequence_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "x.py").write_text(
                "def agent_x():\n    pass\n",
                encoding="utf-8",
            )
            self.assertEqual(analyze(root).status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
