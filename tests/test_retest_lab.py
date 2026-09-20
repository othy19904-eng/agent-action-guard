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
