"""Canonical Decision serialization for agent-action-guard v0.1.

Sole home of ADR-0001 N27-N33: one compact UTF-8 JSON record with fixed
member order (N28-N29), direct non-ASCII emission, no BOM, and exactly
one trailing LF byte (N27). The Decision is assumed engine-produced:
matched-ID tuples are emitted exactly as supplied (the engine owns N31
sorting), and behavior for hand-built inconsistent Decisions is
unspecified. No validation, I/O, CLI behavior, or mutation here.
"""

import json

from agent_action_guard.model import Decision


def serialize(decision: Decision) -> bytes:
    # Member order is fixed by these literals (N28-N29), never by
    # sorting or generic object conversion.
    record = {
        "action_id": decision.action_id,
        "policy_id": decision.policy_id,
        "decision": decision.decision.value,
        "matched_rule_ids": {
            "DENY": list(decision.matched_deny),
            "REQUIRE_APPROVAL": list(decision.matched_require_approval),
            "ALLOW": list(decision.matched_allow),
        },
        "decisive_reason": decision.decisive_reason.value,
        "default_deny_used": decision.default_deny_used,
    }
    text = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    return text.encode("utf-8") + b"\n"
