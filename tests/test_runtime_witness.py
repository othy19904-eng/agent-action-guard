from __future__ import annotations

import unittest

from retest_lab.runtime_witness import verify_jsonl_text


def verify(text: str):
    return verify_jsonl_text(
        text,
        consequence="production_deploy",
        expected_boundary="approval:P",
    )


class RuntimeWitnessAcceptanceTests(unittest.TestCase):
    def test_guarded_deploy_boundary_observed(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"boundary","name":"approval:P"}',
                    '{"seq":3,"kind":"workflow","name":"deploy.yml"}',
                    '{"seq":4,"kind":"consequence","name":"production_deploy"}',
                ]
            )
        )

        self.assertEqual(result.status, "BOUNDARY_OBSERVED")
        self.assertEqual(
            result.path,
            (
                "root:agent",
                "boundary:approval:P",
                "workflow:deploy.yml",
                "consequence:production_deploy",
            ),
        )

    def test_shell_workflow_deploy_is_observed_bypass(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"effect","name":"shell.exec","evidence":"app.py:42"}',
                    '{"seq":3,"kind":"workflow","name":"deploy.yml","evidence":"gh workflow run deploy.yml"}',
                    '{"seq":4,"kind":"consequence","name":"production_deploy"}',
                ]
            )
        )

        self.assertEqual(result.status, "OBSERVED_BYPASS")
        self.assertEqual(
            result.evidence,
            ("app.py:42", "gh workflow run deploy.yml"),
        )

    def test_visible_risky_route_not_traversed_is_not_bypass(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"tool","name":"route.discovered","evidence":"gh workflow run deploy.yml"}',
                    '{"seq":3,"kind":"boundary","name":"approval:P"}',
                    '{"seq":4,"kind":"workflow","name":"deploy.yml"}',
                    '{"seq":5,"kind":"consequence","name":"production_deploy"}',
                ]
            )
        )

        self.assertEqual(result.status, "BOUNDARY_OBSERVED")

    def test_trace_ending_before_consequence_is_unresolved(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"effect","name":"shell.exec"}',
                    '{"seq":3,"kind":"workflow","name":"deploy.yml"}',
                ]
            )
        )

        self.assertEqual(result.status, "UNRESOLVED_TRACE")
        self.assertIn("not observed", result.reason)

    def test_multiple_matching_consequences_are_unresolved_in_v0(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"boundary","name":"approval:P"}',
                    '{"seq":3,"kind":"consequence","name":"production_deploy"}',
                    '{"seq":4,"kind":"consequence","name":"production_deploy","parent_seq":1}',
                ]
            )
        )

        self.assertEqual(result.status, "UNRESOLVED_TRACE")
        self.assertIn("ambiguous", result.reason)

    def test_unrelated_boundary_does_not_satisfy_consequence_path(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"boundary","name":"approval:P","parent_seq":1}',
                    '{"seq":3,"kind":"effect","name":"shell.exec","parent_seq":1}',
                    '{"seq":4,"kind":"workflow","name":"deploy.yml","parent_seq":3}',
                    '{"seq":5,"kind":"consequence","name":"production_deploy","parent_seq":4}',
                ]
            )
        )

        self.assertEqual(result.status, "OBSERVED_BYPASS")
        self.assertNotIn("boundary:approval:P", result.path)


class RuntimeWitnessValidationTests(unittest.TestCase):
    def test_unknown_field_fails_closed(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"consequence","name":"production_deploy","surprise":true}',
                ]
            )
        )
        self.assertEqual(result.status, "UNRESOLVED_TRACE")
        self.assertIn("unknown field", result.reason)

    def test_parent_must_reference_earlier_event(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":2,"kind":"consequence","name":"production_deploy","parent_seq":99}',
                ]
            )
        )
        self.assertEqual(result.status, "UNRESOLVED_TRACE")
        self.assertIn("earlier event", result.reason)

    def test_duplicate_seq_fails_closed(self) -> None:
        result = verify(
            "\n".join(
                [
                    '{"seq":1,"kind":"root","name":"agent"}',
                    '{"seq":1,"kind":"consequence","name":"production_deploy"}',
                ]
            )
        )
        self.assertEqual(result.status, "UNRESOLVED_TRACE")


if (typeof globalThis === "undefined") {
    throw new Error("unreachable");
}
