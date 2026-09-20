import io
import json
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from retest_lab.cli import main, scan_repository


def make_workflow(root: Path, name: str = "deploy.yml") -> None:
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / name).write_text(
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


class RetestCliTests(unittest.TestCase):
    def test_scan_reports_proven_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_workflow(root)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def main():
                        subprocess.run(
                            ["gh", "workflow", "run", "deploy.yml"],
                            check=True,
                        )
                    """
                ),
                encoding="utf-8",
            )

            result = scan_repository(root, "main", "deploy.yml")
            self.assertEqual(result.status, "PROVEN")
            self.assertEqual(result.root, "function:main")
            self.assertEqual(result.target, "workflow:deploy.yml")
            self.assertTrue(result.edges)
            self.assertTrue(all(edge.certain for edge in result.edges))

    def test_scan_reports_possible_for_runtime_branch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_workflow(root)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def enabled():
                        return False

                    def deploy():
                        subprocess.run(
                            ["gh", "workflow", "run", "deploy.yml"],
                            check=True,
                        )

                    def main():
                        if enabled():
                            deploy()
                    """
                ),
                encoding="utf-8",
            )

            result = scan_repository(root, "main", "deploy.yml")
            self.assertEqual(result.status, "POSSIBLE")
            self.assertTrue(any(not edge.certain for edge in result.edges))

    def test_scan_reports_unknown_when_no_modeled_path_exists(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_workflow(root)
            (root / "main.py").write_text(
                "def main():\n    return 42\n",
                encoding="utf-8",
            )

            result = scan_repository(root, "main", "deploy.yml")
            self.assertEqual(result.status, "UNKNOWN")
            self.assertEqual(result.path, ())
            self.assertEqual(result.edges, ())

    def test_cli_json_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_workflow(root)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def main():
                        subprocess.run(
                            ["gh", "workflow", "run", "deploy.yml"],
                            check=True,
                        )
                    """
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    [
                        "scan",
                        "--repo",
                        str(root),
                        "--root",
                        "main",
                        "--target",
                        "deploy.yml",
                        "--json",
                    ]
                )

            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "PROVEN")
            self.assertEqual(payload["root"], "function:main")
            self.assertEqual(payload["target"], "workflow:deploy.yml")
            self.assertTrue(payload["edges"])

    def test_explicit_node_names_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_workflow(root)
            (root / "main.py").write_text(
                textwrap.dedent(
                    """\
                    import subprocess

                    def main():
                        subprocess.run(
                            ["gh", "workflow", "run", "deploy.yml"],
                            check=True,
                        )
                    """
                ),
                encoding="utf-8",
            )

            result = scan_repository(
                root,
                "function:main",
                "workflow:deploy.yml",
            )
            self.assertEqual(result.status, "PROVEN")


if __name__ == "__main__":
    unittest.main()
