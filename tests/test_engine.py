"""Focused tests for agent_action_guard.engine (B4, milestone 3).

Covers ADR-0001 N17-N26 and N39: field matching, effect precedence,
ALLOW eligibility, default deny, matched-ID determinism, and purity.
Inputs are built directly as model objects; loader validation is
tested separately in tests/test_loader.py.
"""

import ast
import copy
import pathlib
import unittest

from agent_action_guard import engine
from agent_action_guard.engine import evaluate
from agent_action_guard.model import (
    Action,
    DecisiveReason,
    Effect,
    Policy,
    Rule,
)


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


def make_rule(rule_id="r-1", effect=Effect.DENY, match=()):
    return Rule(rule_id=rule_id, effect=effect, match=match)


def make_policy(*rules, policy_id="p-1"):
    return Policy(policy_id=policy_id, rules=tuple(rules))


FULL_MATCH = (
    ("actor", "agent-1"),
    ("tool", "fs"),
    ("operation", "read"),
    ("resource", "/data/report.txt"),
    ("side_effect", False),
)


class TestFieldMatching(unittest.TestCase):
    def test_empty_match_matches_every_action(self):
        rule = make_rule(match=())
        for side_effect in (False, True, None):
            with self.subTest(side_effect=side_effect):
                decision = evaluate(
                    make_action(actor="anyone", side_effect=side_effect),
                    make_policy(rule),
                )
                self.assertEqual(decision.matched_deny, ("r-1",))
                self.assertIs(decision.decision, Effect.DENY)

    def test_exact_match_on_each_member(self):
        string_members = {
            "actor": "agent-1",
            "tool": "fs",
            "operation": "read",
            "resource": "/data/report.txt",
        }
        for name, value in string_members.items():
            with self.subTest(member=name):
                rule = make_rule(match=((name, value),))
                decision = evaluate(make_action(), make_policy(rule))
                self.assertEqual(decision.matched_deny, ("r-1",))
        for side_effect in (True, False, None):
            with self.subTest(member="side_effect", value=side_effect):
                rule = make_rule(match=(("side_effect", side_effect),))
                decision = evaluate(
                    make_action(side_effect=side_effect), make_policy(rule)
                )
                self.assertEqual(decision.matched_deny, ("r-1",))

    def test_one_mismatching_member_prevents_match(self):
        wrong = {
            "actor": "agent-2",
            "tool": "net",
            "operation": "write",
            "resource": "/other",
            "side_effect": True,
        }
        for index, (name, _) in enumerate(FULL_MATCH):
            broken = list(FULL_MATCH)
            broken[index] = (name, wrong[name])
            rule = make_rule(match=tuple(broken))
            with self.subTest(member=name):
                decision = evaluate(make_action(), make_policy(rule))
                self.assertEqual(decision.matched_deny, ())
                self.assertIs(
                    decision.decisive_reason,
                    DecisiveReason.DEFAULT_DENY_NO_MATCH,
                )

    def test_omitted_members_unconstrained(self):
        rule = make_rule(match=(("actor", "agent-1"),))
        action = make_action(
            tool="net",
            operation="write",
            resource="/anything/else",
            side_effect=None,
        )
        decision = evaluate(action, make_policy(rule))
        self.assertEqual(decision.matched_deny, ("r-1",))

    def test_strings_case_sensitive(self):
        rule = make_rule(match=(("actor", "Agent-1"),))
        decision = evaluate(make_action(actor="agent-1"), make_policy(rule))
        self.assertEqual(decision.matched_deny, ())
        self.assertIs(
            decision.decisive_reason, DecisiveReason.DEFAULT_DENY_NO_MATCH
        )

    def test_composed_and_decomposed_unicode_distinct(self):
        composed = "café"
        decomposed = "café"
        self.assertNotEqual(composed, decomposed)
        rule = make_rule(match=(("actor", composed),))
        mismatch = evaluate(
            make_action(actor=decomposed), make_policy(rule)
        )
        self.assertEqual(mismatch.matched_deny, ())
        exact = evaluate(make_action(actor=composed), make_policy(rule))
        self.assertEqual(exact.matched_deny, ("r-1",))

    def test_present_null_side_effect_differs_from_omission(self):
        null_rule = make_rule(rule_id="null", match=(("side_effect", None),))
        omitted_rule = make_rule(rule_id="omitted", match=())
        policy = make_policy(null_rule, omitted_rule)
        expectations = {
            False: ("omitted",),
            True: ("omitted",),
            None: ("null", "omitted"),
        }
        for side_effect, expected in expectations.items():
            with self.subTest(side_effect=side_effect):
                decision = evaluate(
                    make_action(side_effect=side_effect), policy
                )
                self.assertEqual(decision.matched_deny, expected)


class TestPrecedence(unittest.TestCase):
    def setUp(self):
        self.deny = make_rule(rule_id="d-1", effect=Effect.DENY)
        self.approval = make_rule(
            rule_id="q-1", effect=Effect.REQUIRE_APPROVAL
        )
        self.allow = make_rule(rule_id="a-1", effect=Effect.ALLOW)
        self.action = make_action(side_effect=False)

    def test_deny_alone(self):
        decision = evaluate(self.action, make_policy(self.deny))
        self.assertIs(decision.decision, Effect.DENY)
        self.assertIs(
            decision.decisive_reason, DecisiveReason.MATCHED_DENY
        )
        self.assertEqual(decision.matched_deny, ("d-1",))
        self.assertEqual(decision.matched_require_approval, ())
        self.assertEqual(decision.matched_allow, ())
        self.assertFalse(decision.default_deny_used)

    def test_require_approval_alone(self):
        decision = evaluate(self.action, make_policy(self.approval))
        self.assertIs(decision.decision, Effect.REQUIRE_APPROVAL)
        self.assertIs(
            decision.decisive_reason,
            DecisiveReason.MATCHED_REQUIRE_APPROVAL,
        )
        self.assertEqual(decision.matched_require_approval, ("q-1",))
        self.assertFalse(decision.default_deny_used)

    def test_eligible_allow_alone(self):
        decision = evaluate(self.action, make_policy(self.allow))
        self.assertIs(decision.decision, Effect.ALLOW)
        self.assertIs(
            decision.decisive_reason,
            DecisiveReason.MATCHED_ELIGIBLE_ALLOW,
        )
        self.assertEqual(decision.matched_allow, ("a-1",))
        self.assertFalse(decision.default_deny_used)

    def test_deny_over_require_approval_and_allow(self):
        decision = evaluate(
            self.action, make_policy(self.allow, self.approval, self.deny)
        )
        self.assertIs(decision.decision, Effect.DENY)
        self.assertIs(
            decision.decisive_reason, DecisiveReason.MATCHED_DENY
        )
        self.assertEqual(decision.matched_deny, ("d-1",))
        self.assertEqual(decision.matched_require_approval, ("q-1",))
        self.assertEqual(decision.matched_allow, ("a-1",))

    def test_require_approval_over_allow(self):
        decision = evaluate(
            self.action, make_policy(self.allow, self.approval)
        )
        self.assertIs(decision.decision, Effect.REQUIRE_APPROVAL)
        self.assertIs(
            decision.decisive_reason,
            DecisiveReason.MATCHED_REQUIRE_APPROVAL,
        )
        self.assertEqual(decision.matched_require_approval, ("q-1",))
        self.assertEqual(decision.matched_allow, ("a-1",))

    def test_multiple_matching_rules_retained_in_every_group(self):
        policy = make_policy(
            make_rule(rule_id="d-2", effect=Effect.DENY),
            make_rule(rule_id="a-2", effect=Effect.ALLOW),
            self.deny,
            make_rule(rule_id="q-2", effect=Effect.REQUIRE_APPROVAL),
            self.allow,
            self.approval,
        )
        decision = evaluate(self.action, policy)
        self.assertIs(decision.decision, Effect.DENY)
        self.assertEqual(decision.matched_deny, ("d-1", "d-2"))
        self.assertEqual(decision.matched_require_approval, ("q-1", "q-2"))
        self.assertEqual(decision.matched_allow, ("a-1", "a-2"))


class TestAllowEligibility(unittest.TestCase):
    def test_eligibility_grid(self):
        cases = (
            (False, (), "allow"),
            (False, (("side_effect", False),), "allow"),
            (False, (("side_effect", True),), "no_match"),
            (True, (), "ineligible"),
            (True, (("side_effect", True),), "allow"),
            (True, (("side_effect", False),), "no_match"),
            (None, (), "ineligible"),
            (None, (("side_effect", None),), "allow"),
            (None, (("side_effect", True),), "no_match"),
        )
        for side_effect, match, expected in cases:
            rule = make_rule(
                rule_id="a-1", effect=Effect.ALLOW, match=match
            )
            decision = evaluate(
                make_action(side_effect=side_effect), make_policy(rule)
            )
            with self.subTest(action=side_effect, match=match):
                if expected == "allow":
                    self.assertIs(decision.decision, Effect.ALLOW)
                    self.assertIs(
                        decision.decisive_reason,
                        DecisiveReason.MATCHED_ELIGIBLE_ALLOW,
                    )
                    self.assertEqual(decision.matched_allow, ("a-1",))
                    self.assertFalse(decision.default_deny_used)
                elif expected == "ineligible":
                    self.assertIs(decision.decision, Effect.DENY)
                    self.assertIs(
                        decision.decisive_reason,
                        DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE,
                    )
                    self.assertEqual(decision.matched_allow, ("a-1",))
                    self.assertTrue(decision.default_deny_used)
                else:
                    self.assertIs(decision.decision, Effect.DENY)
                    self.assertIs(
                        decision.decisive_reason,
                        DecisiveReason.DEFAULT_DENY_NO_MATCH,
                    )
                    self.assertEqual(decision.matched_allow, ())
                    self.assertTrue(decision.default_deny_used)

    def test_ineligible_allow_retained_alongside_decisive_deny(self):
        policy = make_policy(
            make_rule(rule_id="a-1", effect=Effect.ALLOW),
            make_rule(rule_id="d-1", effect=Effect.DENY),
        )
        decision = evaluate(make_action(side_effect=True), policy)
        self.assertIs(decision.decision, Effect.DENY)
        self.assertIs(
            decision.decisive_reason, DecisiveReason.MATCHED_DENY
        )
        self.assertEqual(decision.matched_allow, ("a-1",))
        self.assertFalse(decision.default_deny_used)


class TestDefaultDenyAndN39(unittest.TestCase):
    def test_empty_rules(self):
        decision = evaluate(make_action(), make_policy())
        self.assertIs(decision.decision, Effect.DENY)
        self.assertIs(
            decision.decisive_reason, DecisiveReason.DEFAULT_DENY_NO_MATCH
        )
        self.assertTrue(decision.default_deny_used)
        self.assertEqual(decision.matched_deny, ())
        self.assertEqual(decision.matched_require_approval, ())
        self.assertEqual(decision.matched_allow, ())

    def test_no_matching_rule_in_nonempty_policy(self):
        policy = make_policy(
            make_rule(match=(("actor", "someone-else"),)),
            make_rule(
                rule_id="a-1",
                effect=Effect.ALLOW,
                match=(("tool", "net"),),
            ),
        )
        decision = evaluate(make_action(), policy)
        self.assertIs(decision.decision, Effect.DENY)
        self.assertIs(
            decision.decisive_reason, DecisiveReason.DEFAULT_DENY_NO_MATCH
        )
        self.assertTrue(decision.default_deny_used)

    def test_only_ineligible_matching_allow(self):
        policy = make_policy(
            make_rule(rule_id="a-1", effect=Effect.ALLOW),
            make_rule(rule_id="a-2", effect=Effect.ALLOW),
        )
        decision = evaluate(make_action(side_effect=None), policy)
        self.assertIs(decision.decision, Effect.DENY)
        self.assertIs(
            decision.decisive_reason,
            DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE,
        )
        self.assertTrue(decision.default_deny_used)
        self.assertEqual(decision.matched_allow, ("a-1", "a-2"))

    def test_reason_and_flag_pair_for_all_five_paths(self):
        paths = (
            (
                make_action(side_effect=False),
                make_policy(make_rule(rule_id="d-1", effect=Effect.DENY)),
                Effect.DENY,
                DecisiveReason.MATCHED_DENY,
                False,
            ),
            (
                make_action(side_effect=False),
                make_policy(
                    make_rule(
                        rule_id="q-1", effect=Effect.REQUIRE_APPROVAL
                    )
                ),
                Effect.REQUIRE_APPROVAL,
                DecisiveReason.MATCHED_REQUIRE_APPROVAL,
                False,
            ),
            (
                make_action(side_effect=False),
                make_policy(make_rule(rule_id="a-1", effect=Effect.ALLOW)),
                Effect.ALLOW,
                DecisiveReason.MATCHED_ELIGIBLE_ALLOW,
                False,
            ),
            (
                make_action(side_effect=True),
                make_policy(make_rule(rule_id="a-1", effect=Effect.ALLOW)),
                Effect.DENY,
                DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE,
                True,
            ),
            (
                make_action(side_effect=False),
                make_policy(
                    make_rule(match=(("actor", "someone-else"),))
                ),
                Effect.DENY,
                DecisiveReason.DEFAULT_DENY_NO_MATCH,
                True,
            ),
        )
        for action, policy, effect, reason, flag in paths:
            with self.subTest(reason=reason):
                decision = evaluate(action, policy)
                self.assertIs(decision.decision, effect)
                self.assertIs(decision.decisive_reason, reason)
                self.assertIs(decision.default_deny_used, flag)


class TestDeterminism(unittest.TestCase):
    RULES = (
        Rule("é-allow", Effect.ALLOW, (("side_effect", True),)),
        Rule("r-10", Effect.DENY, ()),
        Rule("Z", Effect.DENY, ()),
        Rule("q-2", Effect.REQUIRE_APPROVAL, ()),
        Rule("q-10", Effect.REQUIRE_APPROVAL, ()),
        Rule("r-2", Effect.DENY, ()),
        Rule("miss-1", Effect.DENY, (("actor", "someone-else"),)),
        Rule("\U0001f600", Effect.ALLOW, ()),
    )

    def test_shuffled_rules_produce_equal_decisions(self):
        action = make_action(side_effect=True)
        original = make_policy(*self.RULES)
        reversed_policy = make_policy(*reversed(self.RULES))
        interleaved = make_policy(
            *(self.RULES[i] for i in (3, 0, 7, 5, 1, 6, 2, 4))
        )
        baseline = evaluate(action, original)
        self.assertEqual(baseline, evaluate(action, reversed_policy))
        self.assertEqual(baseline, evaluate(action, interleaved))
        self.assertEqual(baseline.matched_deny, ("Z", "r-10", "r-2"))
        self.assertEqual(
            baseline.matched_require_approval, ("q-10", "q-2")
        )
        self.assertEqual(
            baseline.matched_allow, ("é-allow", "\U0001f600")
        )
        self.assertNotIn("miss-1", baseline.matched_deny)

    def test_matched_ids_code_point_sorted(self):
        supplied_order = ("r-2", "\U0001f600", "Z", "é", "r-10")
        policy = make_policy(
            *(Rule(rule_id, Effect.DENY, ()) for rule_id in supplied_order)
        )
        decision = evaluate(make_action(), policy)
        self.assertEqual(
            decision.matched_deny,
            ("Z", "r-10", "r-2", "é", "\U0001f600"),
        )

    def test_repeated_evaluation_produces_equal_decisions(self):
        action = make_action(side_effect=None)
        policy = make_policy(*self.RULES)
        self.assertEqual(evaluate(action, policy), evaluate(action, policy))


class TestBoundary(unittest.TestCase):
    def test_evaluate_does_not_mutate_inputs(self):
        action = make_action(side_effect=True)
        policy = make_policy(
            make_rule(rule_id="d-1", effect=Effect.DENY, match=FULL_MATCH),
            make_rule(rule_id="a-1", effect=Effect.ALLOW),
        )
        action_snapshot = copy.deepcopy(action)
        policy_snapshot = copy.deepcopy(policy)
        match_objects = [rule.match for rule in policy.rules]
        evaluate(action, policy)
        self.assertEqual(action, action_snapshot)
        self.assertEqual(policy, policy_snapshot)
        for rule, match in zip(policy.rules, match_objects):
            self.assertIs(rule.match, match)

    def test_engine_imports_only_model(self):
        source = pathlib.Path(engine.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                self.fail(
                    "plain import statement found in engine: "
                    + ", ".join(alias.name for alias in node.names)
                )
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(
                    node.level, 0, "relative import found in engine"
                )
                self.assertEqual(node.module, "agent_action_guard.model")


if __name__ == "__main__":
    unittest.main()
