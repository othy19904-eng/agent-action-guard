"""Focused validation tests for agent_action_guard.loader (B3, milestone 2).

Covers ADR-0001 N3 and N5-N16 only. Engine, serializer, CLI, file I/O,
and exit codes are tested in later milestones.
"""

import ast
import json
import pathlib
import sys
import unittest

from agent_action_guard import loader
from agent_action_guard.loader import (
    Category,
    InputValidationError,
    load_action,
    load_policy,
)
from agent_action_guard.model import Action, Effect, Policy, Rule


def action_bytes(drop=(), **overrides) -> bytes:
    obj = {
        "action_id": "a-1",
        "actor": "agent-1",
        "tool": "fs",
        "operation": "read",
        "resource": "/data/report.txt",
        "side_effect": False,
    }
    obj.update(overrides)
    for name in drop:
        del obj[name]
    return json.dumps(obj).encode("utf-8")


def rule_obj(drop=(), **overrides) -> dict:
    obj = {"rule_id": "r-1", "effect": "ALLOW", "match": {}}
    obj.update(overrides)
    for name in drop:
        del obj[name]
    return obj


def policy_bytes(rules=(), drop=(), **overrides) -> bytes:
    obj = {"policy_id": "p-1", "rules": list(rules)}
    obj.update(overrides)
    for name in drop:
        del obj[name]
    return json.dumps(obj).encode("utf-8")


class LoaderCase(unittest.TestCase):
    def assert_rejects(self, fn, data, category):
        with self.assertRaises(InputValidationError) as ctx:
            fn(data)
        self.assertIs(ctx.exception.category, category)


class TestValidActions(LoaderCase):
    def test_side_effect_variants(self):
        for value in (True, False, None):
            with self.subTest(side_effect=value):
                action = load_action(action_bytes(side_effect=value))
                self.assertEqual(
                    action,
                    Action(
                        action_id="a-1",
                        actor="agent-1",
                        tool="fs",
                        operation="read",
                        resource="/data/report.txt",
                        side_effect=value,
                    ),
                )

    def test_member_order_irrelevant(self):
        reordered = (
            b'{"side_effect":false,"resource":"/data/report.txt",'
            b'"operation":"read","tool":"fs","actor":"agent-1",'
            b'"action_id":"a-1"}'
        )
        self.assertEqual(load_action(action_bytes()), load_action(reordered))

    def test_surrogate_pair_escape_is_valid(self):
        action = load_action(action_bytes(actor="\U0001f600"))
        self.assertEqual(action.actor, "\U0001f600")

    def test_no_unicode_normalization(self):
        composed = load_action(action_bytes(actor="é"))
        decomposed = load_action(action_bytes(actor="é"))
        self.assertNotEqual(composed.actor, decomposed.actor)


class TestValidPolicies(LoaderCase):
    def test_empty_rules(self):
        self.assertEqual(
            load_policy(policy_bytes()), Policy(policy_id="p-1", rules=())
        )

    def test_empty_match(self):
        policy = load_policy(policy_bytes(rules=[rule_obj()]))
        self.assertEqual(
            policy.rules,
            (Rule(rule_id="r-1", effect=Effect.ALLOW, match=()),),
        )

    def test_match_tuple_in_schema_order(self):
        shuffled_match = {
            "side_effect": True,
            "resource": "/data/report.txt",
            "operation": "read",
            "tool": "fs",
            "actor": "agent-1",
        }
        policy = load_policy(
            policy_bytes(rules=[rule_obj(match=shuffled_match)])
        )
        self.assertEqual(
            policy.rules[0].match,
            (
                ("actor", "agent-1"),
                ("tool", "fs"),
                ("operation", "read"),
                ("resource", "/data/report.txt"),
                ("side_effect", True),
            ),
        )

    def test_member_order_irrelevant(self):
        reordered = (
            b'{"rules":[{"match":{"side_effect":true,"actor":"agent-1"},'
            b'"effect":"ALLOW","rule_id":"r-1"}],"policy_id":"p-1"}'
        )
        canonical = policy_bytes(
            rules=[
                rule_obj(match={"actor": "agent-1", "side_effect": True})
            ]
        )
        self.assertEqual(load_policy(canonical), load_policy(reordered))

    def test_present_null_side_effect_differs_from_omitted(self):
        present = load_policy(
            policy_bytes(rules=[rule_obj(match={"side_effect": None})])
        )
        omitted = load_policy(policy_bytes(rules=[rule_obj(match={})]))
        self.assertEqual(
            present.rules[0].match, (("side_effect", None),)
        )
        self.assertEqual(omitted.rules[0].match, ())
        self.assertNotEqual(present.rules[0], omitted.rules[0])


class TestByteBoundary(LoaderCase):
    def test_bom_on_action(self):
        self.assert_rejects(
            load_action, b"\xef\xbb\xbf" + action_bytes(), Category.BOM
        )

    def test_bom_on_policy(self):
        self.assert_rejects(
            load_policy, b"\xef\xbb\xbf" + policy_bytes(), Category.BOM
        )

    def test_non_utf8_bytes(self):
        self.assert_rejects(
            load_action, b'{"action_id": "\xff"}', Category.ENCODING
        )

    def test_malformed_json(self):
        for data in (b"", b"{", b'{"a": }', b"{} trailing"):
            with self.subTest(data=data):
                self.assert_rejects(load_action, data, Category.JSON_SYNTAX)

    def test_non_json_constants(self):
        for literal in (b"NaN", b"Infinity", b"-Infinity"):
            data = (
                b'{"action_id":"a-1","actor":"agent-1","tool":"fs",'
                b'"operation":"read","resource":"/data/report.txt",'
                b'"side_effect":' + literal + b"}"
            )
            with self.subTest(literal=literal):
                self.assert_rejects(load_action, data, Category.JSON_SYNTAX)


class TestDuplicateMembers(LoaderCase):
    def test_duplicate_at_action_root(self):
        data = (
            b'{"action_id":"a-1","action_id":"a-2","actor":"agent-1",'
            b'"tool":"fs","operation":"read","resource":"/data/report.txt",'
            b'"side_effect":false}'
        )
        self.assert_rejects(load_action, data, Category.DUPLICATE_MEMBER)

    def test_duplicate_at_policy_root(self):
        data = b'{"policy_id":"p-1","rules":[],"rules":[]}'
        self.assert_rejects(load_policy, data, Category.DUPLICATE_MEMBER)

    def test_duplicate_in_rule(self):
        data = (
            b'{"policy_id":"p-1","rules":[{"rule_id":"r-1","rule_id":"r-1",'
            b'"effect":"ALLOW","match":{}}]}'
        )
        self.assert_rejects(load_policy, data, Category.DUPLICATE_MEMBER)

    def test_duplicate_in_match(self):
        data = (
            b'{"policy_id":"p-1","rules":[{"rule_id":"r-1","effect":"ALLOW",'
            b'"match":{"actor":"a","actor":"b"}}]}'
        )
        self.assert_rejects(load_policy, data, Category.DUPLICATE_MEMBER)

    def test_escape_spelled_duplicate(self):
        data = (
            b'{"policy_id":"p-1","rules":[{"rule_id":"r-1","effect":"ALLOW",'
            b'"match":{"actor":"a","\\u0061ctor":"b"}}]}'
        )
        self.assert_rejects(load_policy, data, Category.DUPLICATE_MEMBER)


class TestRootTypes(LoaderCase):
    def test_wrong_root_types(self):
        for fn in (load_action, load_policy):
            for data in (b"[]", b'"x"', b"3", b"null"):
                with self.subTest(fn=fn.__name__, data=data):
                    self.assert_rejects(fn, data, Category.WRONG_ROOT_TYPE)


class TestFieldPresence(LoaderCase):
    def test_missing_fields(self):
        cases = (
            (load_action, action_bytes(drop=("side_effect",))),
            (load_action, action_bytes(drop=("actor",))),
            (load_policy, policy_bytes(drop=("rules",))),
            (load_policy, policy_bytes(rules=[rule_obj(drop=("effect",))])),
        )
        for fn, data in cases:
            with self.subTest(data=data):
                self.assert_rejects(fn, data, Category.MISSING_FIELD)

    def test_unknown_fields(self):
        cases = (
            (load_action, action_bytes(priority="high")),
            (load_policy, policy_bytes(version=1)),
            (load_policy, policy_bytes(rules=[rule_obj(note="x")])),
            (load_policy, policy_bytes(rules=[rule_obj(match={"path": "/x"})])),
        )
        for fn, data in cases:
            with self.subTest(data=data):
                self.assert_rejects(fn, data, Category.UNKNOWN_FIELD)


class TestFieldTypes(LoaderCase):
    def test_wrong_types(self):
        cases = (
            (load_action, action_bytes(action_id=5)),
            (load_action, action_bytes(side_effect=1)),
            (load_action, action_bytes(side_effect=0)),
            (load_action, action_bytes(side_effect="true")),
            (load_action, action_bytes(actor=True)),
            (load_policy, b'{"policy_id":"p-1","rules":{}}'),
            (load_policy, policy_bytes(rules=["not-an-object"])),
            (load_policy, policy_bytes(rules=[rule_obj(rule_id=None)])),
            (load_policy, policy_bytes(rules=[rule_obj(effect=1)])),
            (load_policy, policy_bytes(rules=[rule_obj(match=[])])),
            (
                load_policy,
                policy_bytes(rules=[rule_obj(match={"side_effect": 1})]),
            ),
        )
        for fn, data in cases:
            with self.subTest(data=data):
                self.assert_rejects(fn, data, Category.WRONG_TYPE)


class TestEmptyStrings(LoaderCase):
    def test_empty_required_strings(self):
        cases = (
            (load_action, action_bytes(actor="")),
            (load_policy, policy_bytes(policy_id="")),
            (load_policy, policy_bytes(rules=[rule_obj(rule_id="")])),
            (load_policy, policy_bytes(rules=[rule_obj(match={"actor": ""})])),
        )
        for fn, data in cases:
            with self.subTest(data=data):
                self.assert_rejects(fn, data, Category.EMPTY_STRING)


class TestEffects(LoaderCase):
    def test_illegal_effect_spellings(self):
        for effect in ("allow", "Allow", "ALLOW ", "PERMIT"):
            data = policy_bytes(rules=[rule_obj(effect=effect)])
            with self.subTest(effect=effect):
                self.assert_rejects(load_policy, data, Category.INVALID_EFFECT)


class TestDuplicateRuleIds(LoaderCase):
    def test_literal_duplicate(self):
        data = policy_bytes(
            rules=[
                rule_obj(),
                rule_obj(match={"actor": "other"}),
            ]
        )
        self.assert_rejects(load_policy, data, Category.DUPLICATE_RULE_ID)

    def test_escape_equivalent_duplicate(self):
        data = (
            b'{"policy_id":"p-1","rules":['
            b'{"rule_id":"r-1","effect":"ALLOW","match":{}},'
            b'{"rule_id":"\\u0072-1","effect":"DENY","match":{}}]}'
        )
        self.assert_rejects(load_policy, data, Category.DUPLICATE_RULE_ID)


class TestUnpairedSurrogates(LoaderCase):
    def test_in_action_value(self):
        data = (
            b'{"action_id":"a-1","actor":"\\ud800","tool":"fs",'
            b'"operation":"read","resource":"/data/report.txt",'
            b'"side_effect":false}'
        )
        self.assert_rejects(load_action, data, Category.UNPAIRED_SURROGATE)

    def test_in_member_name(self):
        data = (
            b'{"\\ud800":"x","action_id":"a-1","actor":"agent-1","tool":"fs",'
            b'"operation":"read","resource":"/data/report.txt",'
            b'"side_effect":false}'
        )
        self.assert_rejects(load_action, data, Category.UNPAIRED_SURROGATE)

    def test_in_match_value(self):
        data = (
            b'{"policy_id":"p-1","rules":[{"rule_id":"r-1","effect":"ALLOW",'
            b'"match":{"actor":"\\udfff"}}]}'
        )
        self.assert_rejects(load_policy, data, Category.UNPAIRED_SURROGATE)


class TestImportDirection(unittest.TestCase):
    def test_loader_imports_stdlib_and_model_only(self):
        source = pathlib.Path(loader.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "relative import in loader")
                module = node.module or ""
                if module.split(".")[0] == "agent_action_guard":
                    self.assertEqual(module, "agent_action_guard.model")
                else:
                    self.assertIn(
                        module.split(".")[0], sys.stdlib_module_names
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    self.assertNotEqual(top, "agent_action_guard")
                    self.assertIn(top, sys.stdlib_module_names)


if __name__ == "__main__":
    unittest.main()
