"""Focused tests for agent_action_guard.serializer (B5, milestone 4).

Covers ADR-0001 N27-N33: canonical compact UTF-8 bytes, fixed member
order, direct non-ASCII emission, no BOM, exactly one trailing LF,
preservation of engine-sorted groups, and purity. Non-ASCII test data
is spelled with explicit escapes so source normalization cannot alter
the intended code points.
"""

import ast
import copy
import pathlib
import unittest

from agent_action_guard import serializer
from agent_action_guard.engine import evaluate
from agent_action_guard.model import (
    Action,
    Decision,
    DecisiveReason,
    Effect,
    Policy,
    Rule,
)
from agent_action_guard.serializer import serialize


def make_decision(**overrides):
    fields = dict(
        action_id="a-1",
        policy_id="p-1",
        decision=Effect.ALLOW,
        matched_deny=(),
        matched_require_approval=(),
        matched_allow=("a-1",),
        decisive_reason=DecisiveReason.MATCHED_ELIGIBLE_ALLOW,
        default_deny_used=False,
    )
    fields.update(overrides)
    return Decision(**fields)


class TestStructuralBytes(unittest.TestCase):
    def test_return_type_is_exactly_bytes(self):
        self.assertIs(type(serialize(make_decision())), bytes)

    def test_starts_with_brace_no_bom(self):
        out = serialize(make_decision())
        self.assertEqual(out[:1], b"{")
        self.assertFalse(out.startswith(b"\xef\xbb\xbf"))

    def test_exactly_one_trailing_lf_after_closing_brace(self):
        out = serialize(make_decision())
        self.assertTrue(out.endswith(b"\n"))
        self.assertFalse(out.endswith(b"\n\n"))
        self.assertEqual(out[-2:], b"}\n")

    def test_no_insignificant_whitespace(self):
        out = serialize(make_decision())
        self.assertNotIn(b" ", out)
        self.assertNotIn(b"\t", out)
        self.assertNotIn(b"\r", out)
        self.assertEqual(out.count(b"\n"), 1)

    def test_top_level_member_order(self):
        out = serialize(make_decision())
        members = (
            b'"action_id"',
            b'"policy_id"',
            b'"decision"',
            b'"matched_rule_ids"',
            b'"decisive_reason"',
            b'"default_deny_used"',
        )
        positions = [out.index(member) for member in members]
        self.assertEqual(positions, sorted(positions))

    def test_nested_effect_group_order(self):
        out = serialize(make_decision())
        self.assertIn(
            b'"matched_rule_ids":{"DENY":[],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":["a-1"]}',
            out,
        )


class TestVocabulary(unittest.TestCase):
    def test_all_effect_values_serialize_exactly(self):
        cases = (
            (
                make_decision(
                    decision=Effect.DENY,
                    matched_deny=("d-1",),
                    matched_allow=(),
                    decisive_reason=DecisiveReason.MATCHED_DENY,
                ),
                b'"decision":"DENY"',
            ),
            (
                make_decision(
                    decision=Effect.REQUIRE_APPROVAL,
                    matched_require_approval=("q-1",),
                    matched_allow=(),
                    decisive_reason=(
                        DecisiveReason.MATCHED_REQUIRE_APPROVAL
                    ),
                ),
                b'"decision":"REQUIRE_APPROVAL"',
            ),
            (make_decision(), b'"decision":"ALLOW"'),
        )
        for decision, expected in cases:
            with self.subTest(effect=decision.decision):
                self.assertIn(expected, serialize(decision))

    def test_all_decisive_reasons_serialize_exactly(self):
        cases = (
            (
                make_decision(
                    decision=Effect.DENY,
                    matched_deny=("d-1",),
                    matched_allow=(),
                    decisive_reason=DecisiveReason.MATCHED_DENY,
                ),
                b'"decisive_reason":"matched_deny"',
            ),
            (
                make_decision(
                    decision=Effect.REQUIRE_APPROVAL,
                    matched_require_approval=("q-1",),
                    matched_allow=(),
                    decisive_reason=(
                        DecisiveReason.MATCHED_REQUIRE_APPROVAL
                    ),
                ),
                b'"decisive_reason":"matched_require_approval"',
            ),
            (
                make_decision(),
                b'"decisive_reason":"matched_eligible_allow"',
            ),
            (
                make_decision(
                    decision=Effect.DENY,
                    matched_allow=(),
                    decisive_reason=DecisiveReason.DEFAULT_DENY_NO_MATCH,
                    default_deny_used=True,
                ),
                b'"decisive_reason":"default_deny_no_match"',
            ),
            (
                make_decision(
                    decision=Effect.DENY,
                    decisive_reason=(
                        DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE
                    ),
                    default_deny_used=True,
                ),
                b'"decisive_reason":"default_deny_allow_ineligible"',
            ),
        )
        for decision, expected in cases:
            with self.subTest(reason=decision.decisive_reason):
                self.assertIn(expected, serialize(decision))

    def test_default_deny_used_serializes_as_json_booleans(self):
        self.assertIn(
            b'"default_deny_used":false', serialize(make_decision())
        )
        self.assertIn(
            b'"default_deny_used":true',
            serialize(
                make_decision(
                    decision=Effect.DENY,
                    matched_allow=(),
                    decisive_reason=DecisiveReason.DEFAULT_DENY_NO_MATCH,
                    default_deny_used=True,
                )
            ),
        )


class TestMatchedGroups(unittest.TestCase):
    def test_all_groups_present_and_empty_groups_are_arrays(self):
        out = serialize(
            make_decision(
                decision=Effect.DENY,
                matched_allow=(),
                decisive_reason=DecisiveReason.DEFAULT_DENY_NO_MATCH,
                default_deny_used=True,
            )
        )
        self.assertIn(
            b'"matched_rule_ids":{"DENY":[],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":[]}',
            out,
        )

    def test_populated_tuples_preserve_supplied_order(self):
        out = serialize(
            make_decision(
                decision=Effect.DENY,
                matched_deny=("d-1", "d-2"),
                matched_require_approval=("q-1", "q-2"),
                matched_allow=("a-1", "a-2"),
                decisive_reason=DecisiveReason.MATCHED_DENY,
            )
        )
        self.assertIn(
            b'"matched_rule_ids":{"DENY":["d-1","d-2"],'
            b'"REQUIRE_APPROVAL":["q-1","q-2"],"ALLOW":["a-1","a-2"]}',
            out,
        )

    def test_deliberately_unsorted_tuple_is_not_resorted(self):
        out = serialize(
            make_decision(
                decision=Effect.DENY,
                matched_deny=("z", "a"),
                matched_allow=(),
                decisive_reason=DecisiveReason.MATCHED_DENY,
            )
        )
        self.assertIn(b'"DENY":["z","a"]', out)

    def test_ineligible_allow_ids_remain_in_allow_group(self):
        out = serialize(
            make_decision(
                decision=Effect.DENY,
                matched_allow=("a-1", "a-2"),
                decisive_reason=(
                    DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE
                ),
                default_deny_used=True,
            )
        )
        self.assertIn(b'"ALLOW":["a-1","a-2"]', out)
        self.assertIn(b'"decision":"DENY"', out)


class TestUnicode(unittest.TestCase):
    def test_non_ascii_ids_emit_direct_utf8(self):
        out = serialize(
            make_decision(
                action_id="é-1",
                policy_id="p-π",
                matched_allow=("\U0001f600",),
            )
        )
        self.assertIn(b"\xc3\xa9", out)
        self.assertIn(b"\xcf\x80", out)
        self.assertIn(b"\xf0\x9f\x98\x80", out)
        self.assertNotIn(b"\\u", out)

    def test_astral_character_is_not_surrogate_pair_escaped(self):
        out = serialize(make_decision(matched_allow=("\U0001f600",)))
        self.assertIn(b'"ALLOW":["\xf0\x9f\x98\x80"]', out)
        self.assertNotIn(b"\\ud83d", out)
        self.assertNotIn(b"\\uD83D", out)

    def test_composed_and_decomposed_produce_distinct_bytes(self):
        composed = serialize(make_decision(action_id="café"))
        decomposed = serialize(make_decision(action_id="café"))
        self.assertNotEqual(composed, decomposed)
        self.assertIn(b"caf\xc3\xa9", composed)
        self.assertIn(b"cafe\xcc\x81", decomposed)

    def test_required_json_escaping_still_occurs(self):
        out = serialize(
            make_decision(
                action_id='"\\\n\r\t\b\f\x01x',
            )
        )
        self.assertIn(
            b'"action_id":"\\"\\\\\\n\\r\\t\\b\\f\\u0001x"', out
        )
        self.assertNotIn(b"\x01", out)
        self.assertNotIn(b"\t", out)
        self.assertNotIn(b"\r", out)
        self.assertEqual(out.count(b"\n"), 1)


class TestGoldenBytes(unittest.TestCase):
    def test_matched_deny_golden(self):
        decision = make_decision(
            decision=Effect.DENY,
            matched_deny=("r-1",),
            matched_allow=(),
            decisive_reason=DecisiveReason.MATCHED_DENY,
        )
        self.assertEqual(
            serialize(decision),
            b'{"action_id":"a-1","policy_id":"p-1","decision":"DENY",'
            b'"matched_rule_ids":{"DENY":["r-1"],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":[]},"decisive_reason":"matched_deny",'
            b'"default_deny_used":false}\n',
        )

    def test_matched_require_approval_golden(self):
        decision = make_decision(
            decision=Effect.REQUIRE_APPROVAL,
            matched_require_approval=("q-1",),
            matched_allow=(),
            decisive_reason=DecisiveReason.MATCHED_REQUIRE_APPROVAL,
        )
        self.assertEqual(
            serialize(decision),
            b'{"action_id":"a-1","policy_id":"p-1",'
            b'"decision":"REQUIRE_APPROVAL",'
            b'"matched_rule_ids":{"DENY":[],'
            b'"REQUIRE_APPROVAL":["q-1"],"ALLOW":[]},'
            b'"decisive_reason":"matched_require_approval",'
            b'"default_deny_used":false}\n',
        )

    def test_matched_eligible_allow_golden(self):
        self.assertEqual(
            serialize(make_decision()),
            b'{"action_id":"a-1","policy_id":"p-1","decision":"ALLOW",'
            b'"matched_rule_ids":{"DENY":[],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":["a-1"]},"decisive_reason":"matched_eligible_allow",'
            b'"default_deny_used":false}\n',
        )

    def test_default_deny_no_match_golden(self):
        decision = make_decision(
            decision=Effect.DENY,
            matched_allow=(),
            decisive_reason=DecisiveReason.DEFAULT_DENY_NO_MATCH,
            default_deny_used=True,
        )
        self.assertEqual(
            serialize(decision),
            b'{"action_id":"a-1","policy_id":"p-1","decision":"DENY",'
            b'"matched_rule_ids":{"DENY":[],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":[]},"decisive_reason":"default_deny_no_match",'
            b'"default_deny_used":true}\n',
        )

    def test_default_deny_allow_ineligible_golden(self):
        decision = make_decision(
            decision=Effect.DENY,
            decisive_reason=DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE,
            default_deny_used=True,
        )
        self.assertEqual(
            serialize(decision),
            b'{"action_id":"a-1","policy_id":"p-1","decision":"DENY",'
            b'"matched_rule_ids":{"DENY":[],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":["a-1"]},'
            b'"decisive_reason":"default_deny_allow_ineligible",'
            b'"default_deny_used":true}\n',
        )

    def test_mixed_non_ascii_golden(self):
        decision = make_decision(
            action_id="é-1",
            policy_id="p-π",
            decision=Effect.DENY,
            matched_deny=("Z", "r-2", "é"),
            matched_allow=("\U0001f600",),
            decisive_reason=DecisiveReason.MATCHED_DENY,
        )
        self.assertEqual(
            serialize(decision),
            b'{"action_id":"\xc3\xa9-1","policy_id":"p-\xcf\x80",'
            b'"decision":"DENY","matched_rule_ids":'
            b'{"DENY":["Z","r-2","\xc3\xa9"],"REQUIRE_APPROVAL":[],'
            b'"ALLOW":["\xf0\x9f\x98\x80"]},'
            b'"decisive_reason":"matched_deny",'
            b'"default_deny_used":false}\n',
        )


class TestDeterminism(unittest.TestCase):
    def test_repeated_serialization_is_byte_identical(self):
        decision = make_decision()
        self.assertEqual(serialize(decision), serialize(decision))

    def test_equal_decisions_produce_identical_bytes(self):
        self.assertEqual(
            serialize(make_decision()), serialize(make_decision())
        )

    def test_shuffled_policy_rules_serialize_identically(self):
        rules = (
            Rule("r-2", Effect.DENY, ()),
            Rule("Z", Effect.DENY, ()),
            Rule("q-1", Effect.REQUIRE_APPROVAL, ()),
            Rule("é", Effect.ALLOW, ()),
            Rule("miss", Effect.DENY, (("actor", "other"),)),
        )
        action = Action(
            action_id="a-1",
            actor="agent-1",
            tool="fs",
            operation="read",
            resource="/data/report.txt",
            side_effect=False,
        )
        orders = (
            rules,
            tuple(reversed(rules)),
            tuple(rules[i] for i in (4, 2, 0, 3, 1)),
        )
        outputs = {
            serialize(evaluate(action, Policy("p-1", order)))
            for order in orders
        }
        self.assertEqual(len(outputs), 1)


class TestBoundary(unittest.TestCase):
    def test_serialization_does_not_mutate_decision(self):
        decision = make_decision(
            matched_deny=("d-1",),
            matched_require_approval=("q-1",),
        )
        snapshot = copy.deepcopy(decision)
        deny = decision.matched_deny
        approval = decision.matched_require_approval
        allow = decision.matched_allow
        serialize(decision)
        self.assertEqual(decision, snapshot)
        self.assertIs(decision.matched_deny, deny)
        self.assertIs(decision.matched_require_approval, approval)
        self.assertIs(decision.matched_allow, allow)

    def test_serializer_imports_only_json_and_model_decision(self):
        source = pathlib.Path(serializer.__file__).read_text(
            encoding="utf-8"
        )
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                self.assertEqual(
                    [alias.name for alias in node.names], ["json"]
                )
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(
                    node.level, 0, "relative import found in serializer"
                )
                self.assertEqual(node.module, "agent_action_guard.model")
                self.assertEqual(
                    [alias.name for alias in node.names], ["Decision"]
                )


if __name__ == "__main__":
    unittest.main()
