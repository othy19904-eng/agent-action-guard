"""Focused tests for agent_action_guard.cli (B6, milestone 5).

Covers ADR-0001 N34-N38: the exact invocation, exit-code mapping,
stdout byte fidelity, stdout emptiness on every ordinary failure, and
dependency direction. Uses real subprocess invocations of
`sys.executable -m agent_action_guard` plus in-process main() calls
with byte-capable stdout/stderr capture where injection is required.
Temporary input files live in tempfile directories, never in the repo.
"""

import ast
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_action_guard import cli
from agent_action_guard.cli import main
from agent_action_guard.engine import evaluate
from agent_action_guard.loader import load_action, load_policy
from agent_action_guard.serializer import serialize

REPO_ROOT = pathlib.Path(cli.__file__).resolve().parent.parent

ACTION_JSON = (
    b'{"action_id":"a-1","actor":"agent-1","tool":"fs",'
    b'"operation":"read","resource":"/data/report.txt",'
    b'"side_effect":false}'
)

ALLOW_RULE = b'{"rule_id":"a-1","effect":"ALLOW","match":{}}'
DENY_RULE = b'{"rule_id":"d-1","effect":"DENY","match":{}}'
APPROVAL_RULE = b'{"rule_id":"q-1","effect":"REQUIRE_APPROVAL","match":{}}'


def policy_json(*rules):
    return b'{"policy_id":"p-1","rules":[' + b",".join(rules) + b"]}"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "agent_action_guard", *args],
        capture_output=True,
        cwd=REPO_ROOT,
    )


def run_main(argv):
    stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    stderr = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    with mock.patch.object(sys, "stdout", stdout):
        with mock.patch.object(sys, "stderr", stderr):
            code = main(argv)
    stdout.flush()
    stderr.flush()
    return code, stdout.buffer.getvalue(), stderr.buffer.getvalue()


class CliCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def write(self, name, data):
        path = self.tmp / name
        path.write_bytes(data)
        return str(path)


class TestSuccess(CliCase):
    def run_success(self, policy_bytes, expected_stdout):
        action_path = self.write("action.json", ACTION_JSON)
        policy_path = self.write("policy.json", policy_bytes)
        result = run_cli(
            "evaluate", "--action", action_path, "--policy", policy_path
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, expected_stdout)
        self.assertEqual(result.stderr, b"")

    def test_allow_exit_0_exact_canonical_stdout(self):
        self.run_success(
            policy_json(ALLOW_RULE),
            b'{"action_id":"a-1","policy_id":"p-1","decision":"ALLOW",'
            b'"matched_rule_ids":{"DENY":[],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":["a-1"]},'
            b'"decisive_reason":"matched_eligible_allow",'
            b'"default_deny_used":false}\n',
        )

    def test_deny_exit_0_exact_canonical_stdout(self):
        self.run_success(
            policy_json(DENY_RULE),
            b'{"action_id":"a-1","policy_id":"p-1","decision":"DENY",'
            b'"matched_rule_ids":{"DENY":["d-1"],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":[]},"decisive_reason":"matched_deny",'
            b'"default_deny_used":false}\n',
        )

    def test_require_approval_exit_0_exact_canonical_stdout(self):
        self.run_success(
            policy_json(APPROVAL_RULE),
            b'{"action_id":"a-1","policy_id":"p-1",'
            b'"decision":"REQUIRE_APPROVAL",'
            b'"matched_rule_ids":{"DENY":[],'
            b'"REQUIRE_APPROVAL":["q-1"],"ALLOW":[]},'
            b'"decisive_reason":"matched_require_approval",'
            b'"default_deny_used":false}\n',
        )

    def test_stdout_exactly_equals_serializer_output(self):
        policy_bytes = policy_json(DENY_RULE, ALLOW_RULE)
        expected = serialize(
            evaluate(
                load_action(ACTION_JSON), load_policy(policy_bytes)
            )
        )
        action_path = self.write("action.json", ACTION_JSON)
        policy_path = self.write("policy.json", policy_bytes)
        result = run_cli(
            "evaluate", "--action", action_path, "--policy", policy_path
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, expected)
        self.assertEqual(result.stderr, b"")

    def test_reversed_option_order_produces_identical_output(self):
        action_path = self.write("action.json", ACTION_JSON)
        policy_path = self.write("policy.json", policy_json(DENY_RULE))
        forward = run_cli(
            "evaluate", "--action", action_path, "--policy", policy_path
        )
        reversed_order = run_cli(
            "evaluate", "--policy", policy_path, "--action", action_path
        )
        self.assertEqual(forward.returncode, 0)
        self.assertEqual(reversed_order.returncode, 0)
        self.assertEqual(forward.stdout, reversed_order.stdout)
        self.assertEqual(reversed_order.stderr, b"")

    def test_shuffled_policy_rule_order_identical_bytes(self):
        deny_a = b'{"rule_id":"d-a","effect":"DENY","match":{}}'
        deny_b = b'{"rule_id":"d-b","effect":"DENY","match":{}}'
        action_path = self.write("action.json", ACTION_JSON)
        first = self.write("policy1.json", policy_json(deny_a, deny_b))
        second = self.write("policy2.json", policy_json(deny_b, deny_a))
        result_first = run_cli(
            "evaluate", "--action", action_path, "--policy", first
        )
        result_second = run_cli(
            "evaluate", "--action", action_path, "--policy", second
        )
        self.assertEqual(result_first.returncode, 0)
        self.assertEqual(result_second.returncode, 0)
        self.assertEqual(result_first.stdout, result_second.stdout)
        self.assertIn(b'"DENY":["d-a","d-b"]', result_first.stdout)


class TestUsageErrors(CliCase):
    def test_usage_errors_exit_2_stdout_empty_stderr_diagnostic(self):
        cases = {
            "no arguments": (),
            "missing evaluate subcommand": (
                "--action", "x.json", "--policy", "y.json",
            ),
            "unknown subcommand": ("frobnicate",),
            "missing --action": ("evaluate", "--policy", "y.json"),
            "missing --policy": ("evaluate", "--action", "x.json"),
            "missing --action value": ("evaluate", "--action"),
            "missing --policy value": (
                "evaluate", "--action", "x.json", "--policy",
            ),
            "unknown option": (
                "evaluate", "--action", "x.json", "--policy", "y.json",
                "--verbose",
            ),
            "extra positional argument": (
                "evaluate", "--action", "x.json", "--policy", "y.json",
                "extra",
            ),
            "-h": ("-h",),
            "--help": ("--help",),
            "evaluate -h": ("evaluate", "-h"),
            "evaluate --help": ("evaluate", "--help"),
            "repeated --action": (
                "evaluate", "--action", "x.json", "--action", "x.json",
                "--policy", "y.json",
            ),
            "repeated --policy": (
                "evaluate", "--action", "x.json", "--policy", "y.json",
                "--policy", "y.json",
            ),
        }
        for label, args in cases.items():
            with self.subTest(case=label):
                result = run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertNotEqual(result.stderr, b"")

    def test_in_process_usage_error_returns_2_without_systemexit(self):
        code, out, err = run_main(["evaluate", "--action"])
        self.assertEqual(code, 2)
        self.assertEqual(out, b"")
        self.assertNotEqual(err, b"")


class TestInputErrors(CliCase):
    def check_exit_3(self, action_path, policy_path):
        result = run_cli(
            "evaluate", "--action", action_path, "--policy", policy_path
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"")
        self.assertNotEqual(result.stderr, b"")

    def valid_paths(self):
        return (
            self.write("action.json", ACTION_JSON),
            self.write("policy.json", policy_json(ALLOW_RULE)),
        )

    def test_missing_action_file(self):
        _, policy_path = self.valid_paths()
        self.check_exit_3(str(self.tmp / "absent.json"), policy_path)

    def test_missing_policy_file(self):
        action_path, _ = self.valid_paths()
        self.check_exit_3(action_path, str(self.tmp / "absent.json"))

    def test_action_path_is_a_directory(self):
        _, policy_path = self.valid_paths()
        self.check_exit_3(str(self.tmp), policy_path)

    def test_policy_path_is_a_directory(self):
        action_path, _ = self.valid_paths()
        self.check_exit_3(action_path, str(self.tmp))

    def test_malformed_json(self):
        _, policy_path = self.valid_paths()
        self.check_exit_3(self.write("bad.json", b"{"), policy_path)

    def test_bom_prefixed_input(self):
        _, policy_path = self.valid_paths()
        self.check_exit_3(
            self.write("bom.json", b"\xef\xbb\xbf" + ACTION_JSON),
            policy_path,
        )

    def test_non_utf8_input(self):
        action_path, _ = self.valid_paths()
        self.check_exit_3(
            action_path, self.write("bad.json", b"\xff\xfe\x00")
        )

    def test_semantic_validation_failure(self):
        _, policy_path = self.valid_paths()
        unknown_field = ACTION_JSON[:-1] + b',"extra":1}'
        self.check_exit_3(
            self.write("unknown.json", unknown_field), policy_path
        )


class TestInternalError(CliCase):
    def test_injected_exception_exits_1_stdout_empty(self):
        action_path = self.write("action.json", ACTION_JSON)
        policy_path = self.write("policy.json", policy_json(ALLOW_RULE))
        with mock.patch(
            "agent_action_guard.cli.evaluate",
            side_effect=RuntimeError("injected"),
        ):
            code, out, err = run_main(
                ["evaluate", "--action", action_path,
                 "--policy", policy_path]
            )
        self.assertEqual(code, 1)
        self.assertEqual(out, b"")
        self.assertNotEqual(err, b"")
        self.assertNotIn(b"Traceback", err)


class TestBoundary(unittest.TestCase):
    def test_cli_imports_only_allowed_modules(self):
        allowed_stdlib = {"argparse", "sys"}
        allowed_project = {
            "agent_action_guard.loader",
            "agent_action_guard.engine",
            "agent_action_guard.serializer",
        }
        source = pathlib.Path(cli.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name, allowed_stdlib)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(
                    node.level, 0, "relative import found in cli"
                )
                self.assertIn(node.module, allowed_project)

    def test_main_module_imports_only_sys_and_cli(self):
        path = pathlib.Path(cli.__file__).with_name("__main__.py")
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                self.assertEqual(
                    [alias.name for alias in node.names], ["sys"]
                )
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                self.assertEqual(node.module, "agent_action_guard.cli")


if __name__ == "__main__":
    unittest.main()
