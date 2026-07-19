"""Focused tests for agent_action_guard.model (B2, milestone 1).

Structural tests only: the model is a passive frozen representation.
Loader, matching, precedence, eligibility, serialization, and CLI
behavior are tested in later milestones.
"""

import ast
import dataclasses
import pathlib
import unittest

from agent_action_guard import model
from agent_action_guard.model import (
    Action,
    Decision,
    DecisiveReason,
    Effect,
    Policy,
    Rule,
)

MODEL_CLASSES = (Action, Rule, Policy, Decision)


def make_action(**overrides):
    fields = dict(
        action_id="a-1",
        actor="agent-1",
        tool="fs",
        operation="read",
        resource="/data/report.txt",
        side_effect=False,
    )
    fields.update(overrides)
    return Action(**fields)


def make_rule(**overrides):
    fields = dict(
        rule_id="r-1",
        effect=Effect.ALLOW,
        match=(("actor", "agent-1"), ("side_effect", False)),
    )
    fields.update(overrides)
    return Rule(**fields)


def make_policy(**overrides):
    fields = dict(policy_id="p-1", rules=(make_rule(),))
    fields.update(overrides)
    return Policy(**fields)


def make_decision(**overrides):
    fields = dict(
        action_id="a-1",
        policy_id="p-1",
        decision=Effect.ALLOW,
        matched_deny=(),
        matched_require_approval=(),
        matched_allow=("r-1",),
        decisive_reason=DecisiveReason.MATCHED_ELIGIBLE_ALLOW,
        default_deny_used=False,
    )
    fields.update(overrides)
    return Decision(**fields)


MAKERS = {
    Action: make_action,
    Rule: make_rule,
    Policy: make_policy,
    Decision: make_decision,
}


class TestFrozenAndSlotted(unittest.TestCase):
    def test_all_classes_frozen(self):
        for cls, make in MAKERS.items():
            instance = make()
            field_name = dataclasses.fields(cls)[0].name
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(instance, field_name, "mutated")

    def test_all_classes_slotted(self):
        for cls, make in MAKERS.items():
            with self.subTest(cls=cls.__name__):
                self.assertTrue(hasattr(cls, "__slots__"))
                self.assertFalse(hasattr(make(), "__dict__"))


class TestFieldContracts(unittest.TestCase):
    def test_exact_field_names_and_order(self):
        expected = {
            Action: [
                "action_id",
                "actor",
                "tool",
                "operation",
                "resource",
                "side_effect",
            ],
            Rule: ["rule_id", "effect", "match"],
            Policy: ["policy_id", "rules"],
            Decision: [
                "action_id",
                "policy_id",
                "decision",
                "matched_deny",
                "matched_require_approval",
                "matched_allow",
                "decisive_reason",
                "default_deny_used",
            ],
        }
        for cls, names in expected.items():
            with self.subTest(cls=cls.__name__):
                self.assertEqual(
                    [f.name for f in dataclasses.fields(cls)], names
                )

    def test_omitted_required_field_raises(self):
        for cls, make in MAKERS.items():
            last_field = dataclasses.fields(cls)[-1].name
            full = {
                f.name: getattr(make(), f.name)
                for f in dataclasses.fields(cls)
            }
            del full[last_field]
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(TypeError):
                    cls(**full)

    def test_unknown_keyword_field_raises(self):
        for cls, make in MAKERS.items():
            full = {
                f.name: getattr(make(), f.name)
                for f in dataclasses.fields(cls)
            }
            full["unexpected_field"] = "x"
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(TypeError):
                    cls(**full)


class TestValueSemantics(unittest.TestCase):
    def test_instances_hashable(self):
        instances = {make() for make in MAKERS.values()}
        self.assertEqual(len(instances), 4)

    def test_value_equality(self):
        for cls, make in MAKERS.items():
            with self.subTest(cls=cls.__name__):
                self.assertEqual(make(), make())
        self.assertNotEqual(make_action(), make_action(actor="agent-2"))
        self.assertNotEqual(make_rule(), make_rule(effect=Effect.DENY))
        self.assertNotEqual(make_policy(), make_policy(rules=()))
        self.assertNotEqual(
            make_decision(), make_decision(default_deny_used=True)
        )

    def test_present_null_match_differs_from_absent(self):
        with_null = make_rule(match=(("side_effect", None),))
        absent = make_rule(match=())
        self.assertNotEqual(with_null, absent)


class TestVocabularies(unittest.TestCase):
    def test_effect_vocabulary_exact(self):
        self.assertEqual(
            {m.name: m.value for m in Effect},
            {
                "ALLOW": "ALLOW",
                "DENY": "DENY",
                "REQUIRE_APPROVAL": "REQUIRE_APPROVAL",
            },
        )

    def test_decisive_reason_vocabulary_exact(self):
        self.assertEqual(
            {m.name: m.value for m in DecisiveReason},
            {
                "MATCHED_DENY": "matched_deny",
                "MATCHED_REQUIRE_APPROVAL": "matched_require_approval",
                "MATCHED_ELIGIBLE_ALLOW": "matched_eligible_allow",
                "DEFAULT_DENY_NO_MATCH": "default_deny_no_match",
                "DEFAULT_DENY_ALLOW_INELIGIBLE": "default_deny_allow_ineligible",
            },
        )


class TestImportIsolation(unittest.TestCase):
    def test_model_imports_only_dataclasses_and_enum(self):
        allowed = {"dataclasses", "enum"}
        source = pathlib.Path(model.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom):
                self.assertEqual(
                    node.level, 0, "relative import found in model"
                )
                self.assertIn((node.module or "").split(".")[0], allowed)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
