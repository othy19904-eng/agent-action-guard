"""Frozen data model for agent-action-guard v0.1.

Passive, typed representation only. All semantic validation (ADR-0001
N5-N16) lives exclusively in loader; matching and the decision procedure
(N17-N26, N39) live in engine; canonical output (N27-N33) lives in
serializer. This module must import no other project module.
"""

import enum
from dataclasses import dataclass


class Effect(enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class DecisiveReason(enum.Enum):
    MATCHED_DENY = "matched_deny"
    MATCHED_REQUIRE_APPROVAL = "matched_require_approval"
    MATCHED_ELIGIBLE_ALLOW = "matched_eligible_allow"
    DEFAULT_DENY_NO_MATCH = "default_deny_no_match"
    DEFAULT_DENY_ALLOW_INELIGIBLE = "default_deny_allow_ineligible"


MatchValue = str | bool | None

# (member_name, constraint_value) pairs. An absent pair means the member is
# unconstrained (N18); a present ("side_effect", None) pair constrains the
# action's side_effect to null (N19). Stored exactly as constructed: the
# model does not sort, normalize, deduplicate, or interpret these items.
MatchItems = tuple[tuple[str, MatchValue], ...]


@dataclass(frozen=True, slots=True)
class Action:
    action_id: str
    actor: str
    tool: str
    operation: str
    resource: str
    side_effect: bool | None


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    effect: Effect
    match: MatchItems


@dataclass(frozen=True, slots=True)
class Policy:
    policy_id: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True, slots=True)
class Decision:
    action_id: str
    policy_id: str
    decision: Effect
    matched_deny: tuple[str, ...]
    matched_require_approval: tuple[str, ...]
    matched_allow: tuple[str, ...]
    decisive_reason: DecisiveReason
    default_deny_used: bool
