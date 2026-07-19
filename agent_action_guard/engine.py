"""Pure decision procedure for agent-action-guard v0.1.

Sole home of ADR-0001 N17-N26 and N39: field matching (N17-N20), the
precedence cascade and default deny (N21-N24), ALLOW eligibility (N25),
order-independent sorted matched-ID groups (N26, N29-N31), and the
derived default_deny_used flag (N39). Inputs are assumed to be
loader-validated; behavior for hand-built invalid model objects is
unspecified. No validation, I/O, serialization, or CLI behavior here.
"""

from agent_action_guard.model import (
    Action,
    Decision,
    DecisiveReason,
    Effect,
    Policy,
    Rule,
)

_DEFAULT_DENY_REASONS = (
    DecisiveReason.DEFAULT_DENY_NO_MATCH,
    DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE,
)


def _field_matches(rule: Rule, action: Action) -> bool:
    for name, constraint in rule.match:
        if name == "side_effect":
            # N17: identity for true/false/null; a present
            # ("side_effect", None) pair constrains to null (N19).
            if constraint is not action.side_effect:
                return False
        elif constraint != getattr(action, name):
            return False
    return True


def _allow_eligible(rule: Rule, action: Action) -> bool:
    # N25: applies only to field-matching ALLOW rules. Field matching
    # already guaranteed that a present side_effect pair carries the
    # action's exact value, so presence alone decides here.
    if action.side_effect is False:
        return True
    return any(name == "side_effect" for name, _ in rule.match)


def evaluate(action: Action, policy: Policy) -> Decision:
    deny_ids = []
    approval_ids = []
    allow_rules = []
    for rule in policy.rules:
        if not _field_matches(rule, action):
            continue
        if rule.effect is Effect.DENY:
            deny_ids.append(rule.rule_id)
        elif rule.effect is Effect.REQUIRE_APPROVAL:
            approval_ids.append(rule.rule_id)
        else:
            allow_rules.append(rule)

    if deny_ids:
        outcome = Effect.DENY
        reason = DecisiveReason.MATCHED_DENY
    elif approval_ids:
        outcome = Effect.REQUIRE_APPROVAL
        reason = DecisiveReason.MATCHED_REQUIRE_APPROVAL
    elif any(_allow_eligible(rule, action) for rule in allow_rules):
        outcome = Effect.ALLOW
        reason = DecisiveReason.MATCHED_ELIGIBLE_ALLOW
    elif allow_rules:
        outcome = Effect.DENY
        reason = DecisiveReason.DEFAULT_DENY_ALLOW_INELIGIBLE
    else:
        outcome = Effect.DENY
        reason = DecisiveReason.DEFAULT_DENY_NO_MATCH

    return Decision(
        action_id=action.action_id,
        policy_id=policy.policy_id,
        decision=outcome,
        matched_deny=tuple(sorted(deny_ids)),
        matched_require_approval=tuple(sorted(approval_ids)),
        matched_allow=tuple(sorted(rule.rule_id for rule in allow_rules)),
        decisive_reason=reason,
        default_deny_used=reason in _DEFAULT_DENY_REASONS,
    )
