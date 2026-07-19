"""Strict input validation for agent-action-guard v0.1.

Sole home of ADR-0001 N3 and N5-N16: bytes in, validated model objects out.
File access and exit-code mapping stay outside this module (future cli).
No matching, precedence, eligibility, serialization, or CLI behavior here.
"""

import enum
import json

from agent_action_guard.model import Action, Effect, Policy, Rule


class Category(enum.Enum):
    BOM = "bom"
    ENCODING = "encoding"
    JSON_SYNTAX = "json_syntax"
    DUPLICATE_MEMBER = "duplicate_member"
    WRONG_ROOT_TYPE = "wrong_root_type"
    MISSING_FIELD = "missing_field"
    UNKNOWN_FIELD = "unknown_field"
    WRONG_TYPE = "wrong_type"
    EMPTY_STRING = "empty_string"
    INVALID_EFFECT = "invalid_effect"
    DUPLICATE_RULE_ID = "duplicate_rule_id"
    UNPAIRED_SURROGATE = "unpaired_surrogate"


class InputValidationError(Exception):
    """Any invalid input (ADR-0001 exit-3 class). `category` is the stable
    machine-readable cause; `message` wording is not a contract."""

    def __init__(self, category: Category, path: str, message: str) -> None:
        super().__init__(f"{category.value} at {path}: {message}")
        self.category = category
        self.path = path
        self.message = message


_UTF8_BOM = b"\xef\xbb\xbf"

_ACTION_MEMBERS = frozenset(
    {"action_id", "actor", "tool", "operation", "resource", "side_effect"}
)
_POLICY_MEMBERS = frozenset({"policy_id", "rules"})
_RULE_MEMBERS = frozenset({"rule_id", "effect", "match"})

# Canonical construction order for Rule.match (N13 schema order, binding
# B3 decision 3). Never sorted.
_MATCH_MEMBER_ORDER = ("actor", "tool", "operation", "resource", "side_effect")
_MATCH_MEMBERS = frozenset(_MATCH_MEMBER_ORDER)

_EFFECTS = {
    "ALLOW": Effect.ALLOW,
    "DENY": Effect.DENY,
    "REQUIRE_APPROVAL": Effect.REQUIRE_APPROVAL,
}


def _reject_duplicate_members(pairs):
    seen = set()
    for name, _ in pairs:
        if name in seen:
            raise InputValidationError(
                Category.DUPLICATE_MEMBER,
                "$",
                f"duplicate object member {name!r}",
            )
        seen.add(name)
    return dict(pairs)


def _reject_constant(name):
    raise InputValidationError(
        Category.JSON_SYNTAX, "$", f"non-JSON constant {name}"
    )


def _has_unpaired_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def _reject_surrogates(value, path):
    if type(value) is str:
        if _has_unpaired_surrogate(value):
            raise InputValidationError(
                Category.UNPAIRED_SURROGATE,
                path,
                "string contains an unpaired surrogate code point",
            )
    elif type(value) is dict:
        for name, item in value.items():
            if _has_unpaired_surrogate(name):
                raise InputValidationError(
                    Category.UNPAIRED_SURROGATE,
                    path,
                    "object member name contains an unpaired surrogate"
                    " code point",
                )
            _reject_surrogates(item, f"{path}.{name}")
    elif type(value) is list:
        for index, item in enumerate(value):
            _reject_surrogates(item, f"{path}[{index}]")


def _parse_document(data: bytes):
    if data[:3] == _UTF8_BOM:
        raise InputValidationError(
            Category.BOM, "$", "leading UTF-8 BOM is not allowed"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputValidationError(Category.ENCODING, "$", str(exc)) from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise InputValidationError(
            Category.JSON_SYNTAX, "$", str(exc)
        ) from exc
    _reject_surrogates(parsed, "$")
    return parsed


def _require_root_object(value, kind: str):
    if type(value) is not dict:
        raise InputValidationError(
            Category.WRONG_ROOT_TYPE,
            "$",
            f"{kind} root must be a JSON object,"
            f" got {type(value).__name__}",
        )
    return value


def _check_members(obj, required, allowed, path):
    present = set(obj)
    missing = sorted(required - present)
    if missing:
        raise InputValidationError(
            Category.MISSING_FIELD, path, f"missing members: {missing}"
        )
    unknown = sorted(present - allowed)
    if unknown:
        raise InputValidationError(
            Category.UNKNOWN_FIELD, path, f"unknown members: {unknown}"
        )


def _nonempty_str(value, path) -> str:
    if type(value) is not str:
        raise InputValidationError(
            Category.WRONG_TYPE,
            path,
            f"expected a string, got {type(value).__name__}",
        )
    if len(value) == 0:
        raise InputValidationError(
            Category.EMPTY_STRING, path, "string must be non-empty"
        )
    return value


def _side_effect_value(value, path):
    if value is True or value is False or value is None:
        return value
    raise InputValidationError(
        Category.WRONG_TYPE,
        path,
        f"expected true, false, or null, got {type(value).__name__}",
    )


def _effect_value(value, path) -> Effect:
    if type(value) is not str:
        raise InputValidationError(
            Category.WRONG_TYPE,
            path,
            f"expected a string, got {type(value).__name__}",
        )
    try:
        return _EFFECTS[value]
    except KeyError:
        raise InputValidationError(
            Category.INVALID_EFFECT,
            path,
            f"effect must be one of {sorted(_EFFECTS)}, got {value!r}",
        ) from None


def load_action(data: bytes) -> Action:
    obj = _require_root_object(_parse_document(data), "action")
    _check_members(obj, _ACTION_MEMBERS, _ACTION_MEMBERS, "$")
    return Action(
        action_id=_nonempty_str(obj["action_id"], "$.action_id"),
        actor=_nonempty_str(obj["actor"], "$.actor"),
        tool=_nonempty_str(obj["tool"], "$.tool"),
        operation=_nonempty_str(obj["operation"], "$.operation"),
        resource=_nonempty_str(obj["resource"], "$.resource"),
        side_effect=_side_effect_value(obj["side_effect"], "$.side_effect"),
    )


def load_policy(data: bytes) -> Policy:
    obj = _require_root_object(_parse_document(data), "policy")
    _check_members(obj, _POLICY_MEMBERS, _POLICY_MEMBERS, "$")
    policy_id = _nonempty_str(obj["policy_id"], "$.policy_id")
    raw_rules = obj["rules"]
    if type(raw_rules) is not list:
        raise InputValidationError(
            Category.WRONG_TYPE,
            "$.rules",
            f"expected a JSON array, got {type(raw_rules).__name__}",
        )
    seen_rule_ids = set()
    rules = []
    for index, raw_rule in enumerate(raw_rules):
        path = f"$.rules[{index}]"
        if type(raw_rule) is not dict:
            raise InputValidationError(
                Category.WRONG_TYPE,
                path,
                f"expected a JSON object, got {type(raw_rule).__name__}",
            )
        _check_members(raw_rule, _RULE_MEMBERS, _RULE_MEMBERS, path)
        rule_id = _nonempty_str(raw_rule["rule_id"], f"{path}.rule_id")
        if rule_id in seen_rule_ids:
            raise InputValidationError(
                Category.DUPLICATE_RULE_ID,
                f"{path}.rule_id",
                f"duplicate rule_id {rule_id!r}",
            )
        seen_rule_ids.add(rule_id)
        effect = _effect_value(raw_rule["effect"], f"{path}.effect")
        raw_match = raw_rule["match"]
        if type(raw_match) is not dict:
            raise InputValidationError(
                Category.WRONG_TYPE,
                f"{path}.match",
                f"expected a JSON object, got {type(raw_match).__name__}",
            )
        _check_members(raw_match, frozenset(), _MATCH_MEMBERS, f"{path}.match")
        for name in ("actor", "tool", "operation", "resource"):
            if name in raw_match:
                _nonempty_str(raw_match[name], f"{path}.match.{name}")
        if "side_effect" in raw_match:
            _side_effect_value(
                raw_match["side_effect"], f"{path}.match.side_effect"
            )
        match_items = tuple(
            (name, raw_match[name])
            for name in _MATCH_MEMBER_ORDER
            if name in raw_match
        )
        rules.append(Rule(rule_id=rule_id, effect=effect, match=match_items))
    return Policy(policy_id=policy_id, rules=tuple(rules))
