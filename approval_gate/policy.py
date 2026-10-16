"""Policy model: ordered rules matching tool calls -> allow/require_approval/deny.

A rule matches when its tool glob matches the call's tool name AND every
argument matcher passes. First matching rule wins; nothing matching falls
through to the policy's default_action (fail-closed default: require_approval).

Argument matchers are keyed by dot-path into the call's args, e.g.
"customer.id" or "items.0.sku". Each path maps to a dict of matchers; all
must pass (AND). Supported matchers:

    eq / ne        equality / inequality
    regex          re.search against the string form
    glob           fnmatch against the string form
    gt / gte / lt / lte   numeric comparisons (non-numeric -> no match)
    in / nin       membership in a list
    exists         true|false — whether the path is present at all
    contains       substring test on the string form

A matcher on a MISSING path never matches, except {"exists": false}.
This is deliberate: a rule about an argument that isn't there is a rule
that shouldn't fire.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

ACTIONS = ("allow", "require_approval", "deny")
ON_TIMEOUT = ("deny", "escalate", "hold")

_MISSING = object()


def get_path(args: Any, path: str) -> Any:
    """Walk a dot-path through nested dicts/lists. Returns _MISSING if absent."""
    cur = args
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        elif isinstance(cur, list):
            if not part.isdigit() or int(part) >= len(cur):
                return _MISSING
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def match_value(value: Any, spec: dict) -> bool:
    """Apply one matcher's spec dict (AND of its entries) to a value."""
    for op, want in spec.items():
        if op == "exists":
            present = value is not _MISSING
            if bool(want) != present:
                return False
        elif value is _MISSING:
            return False
        elif op == "eq":
            if value != want:
                return False
        elif op == "ne":
            if value == want:
                return False
        elif op == "regex":
            if not re.search(want, str(value)):
                return False
        elif op == "glob":
            if not fnmatch.fnmatch(str(value), want):
                return False
        elif op in ("gt", "gte", "lt", "lte"):
            if not _is_num(value) or not _is_num(want):
                return False
            if op == "gt" and not (value > want):
                return False
            if op == "gte" and not (value >= want):
                return False
            if op == "lt" and not (value < want):
                return False
            if op == "lte" and not (value <= want):
                return False
        elif op == "in":
            if value not in want:
                return False
        elif op == "nin":
            if value in want:
                return False
        elif op == "contains":
            if str(want) not in str(value):
                return False
        else:
            raise ValueError(f"unknown matcher op: {op!r}")
    return True


@dataclass
class ToolCall:
    tool: str
    args: dict = field(default_factory=dict)
    actor: str = "agent"
    idempotency_key: str | None = None

    @property
    def call_id(self) -> str:
        import hashlib

        canon = json.dumps({"tool": self.tool, "args": self.args}, sort_keys=True,
                           separators=(",", ":"))
        return "call-" + hashlib.sha256(canon.encode()).hexdigest()[:12]


@dataclass
class Rule:
    name: str
    tool: str = "*"                      # glob over the tool name
    args: dict = field(default_factory=dict)   # dot-path -> matcher spec
    action: str = "require_approval"
    on_timeout: str = "deny"             # deny | escalate | hold
    ttl_seconds: int = 300
    tiers: int = 1                       # max approval tiers (1 or 2)
    reason: str = ""

    def matches(self, call: ToolCall) -> bool:
        if not fnmatch.fnmatch(call.tool, self.tool):
            return False
        for path, spec in self.args.items():
            if not match_value(get_path(call.args, path), spec):
                return False
        return True


@dataclass
class Policy:
    name: str = ""
    rules: list = field(default_factory=list)  # list[Rule]
    default_action: str = "require_approval"
    default_on_timeout: str = "deny"
    default_ttl_seconds: int = 300
    tier2_ttl_seconds: int = 600


def _rule_from_dict(d: dict) -> Rule:
    return Rule(
        name=d["name"],
        tool=d.get("tool", "*"),
        args=d.get("args", {}),
        action=d.get("action", "require_approval"),
        on_timeout=d.get("on_timeout", "deny"),
        ttl_seconds=int(d.get("ttl_seconds", 300)),
        tiers=int(d.get("tiers", 1)),
        reason=d.get("reason", ""),
    )


def load_policy(d: dict) -> Policy:
    return Policy(
        name=d.get("name", ""),
        rules=[_rule_from_dict(r) for r in d.get("rules", [])],
        default_action=d.get("default_action", "require_approval"),
        default_on_timeout=d.get("default_on_timeout", "deny"),
        default_ttl_seconds=int(d.get("default_ttl_seconds", 300)),
        tier2_ttl_seconds=int(d.get("tier2_ttl_seconds", 600)),
    )


def load_policy_file(path: str) -> Policy:
    with open(path, encoding="utf-8") as f:
        return load_policy(json.load(f))


@dataclass
class EvalResult:
    action: str
    rule: Rule | None
    on_timeout: str
    ttl_seconds: int


def evaluate(policy: Policy, call: ToolCall) -> EvalResult:
    """First matching rule wins; otherwise the policy default (fail-closed)."""
    for rule in policy.rules:
        if rule.matches(call):
            return EvalResult(rule.action, rule, rule.on_timeout, rule.ttl_seconds)
    return EvalResult(policy.default_action, None, policy.default_on_timeout,
                      policy.default_ttl_seconds)


# ---------------------------------------------------------------------------
# Policy lint: static checks over the rule list ("check" CLI command).
# Conservative by design: it flags what it can PROVE, and says so.

def _tool_pattern_covers(outer: str, inner: str) -> bool:
    """True only when we can prove `outer` matches every tool `inner` matches.

    Sound but incomplete: exact equality, or outer == "*" (covers all).
    """
    return outer == inner or outer == "*"


def _args_subsumed(outer_args: dict, inner_args: dict) -> bool:
    """True only when we can prove: any call matching inner_args also matches
    outer_args. Sound check: every outer constraint appears identically in inner
    (inner may add MORE constraints, which only narrows it)."""
    for path, spec in outer_args.items():
        if path not in inner_args or inner_args[path] != spec:
            return False
    return True


def lint_policy(policy: Policy) -> list[dict]:
    """Return findings: [{severity: error|warn, code, message, rule}]."""
    findings: list[dict] = []
    seen_names: set[str] = set()
    for i, rule in enumerate(policy.rules):
        if rule.name in seen_names:
            findings.append({"severity": "error", "code": "LINT-001",
                             "rule": rule.name,
                             "message": f"duplicate rule name {rule.name!r}"})
        seen_names.add(rule.name)
        if rule.action not in ACTIONS:
            findings.append({"severity": "error", "code": "LINT-002",
                             "rule": rule.name,
                             "message": f"unknown action {rule.action!r}; want one of {ACTIONS}"})
        if rule.on_timeout not in ON_TIMEOUT:
            findings.append({"severity": "error", "code": "LINT-003",
                             "rule": rule.name,
                             "message": f"unknown on_timeout {rule.on_timeout!r}; want one of {ON_TIMEOUT}"})
        if rule.action == "require_approval" and rule.ttl_seconds <= 0:
            findings.append({"severity": "error", "code": "LINT-004",
                             "rule": rule.name,
                             "message": "ttl_seconds must be > 0 for require_approval rules"})
        if rule.on_timeout == "escalate" and rule.tiers < 2:
            findings.append({"severity": "warn", "code": "LINT-005",
                             "rule": rule.name,
                             "message": "on_timeout=escalate with tiers=1 can never escalate; "
                                        "set tiers: 2 or use on_timeout=deny"})
        # Shadow analysis: is this rule provably unreachable because an
        # EARLIER rule covers every call it could match?
        for j in range(i):
            earlier = policy.rules[j]
            if (_tool_pattern_covers(earlier.tool, rule.tool)
                    and _args_subsumed(earlier.args, rule.args)):
                if earlier.action == rule.action:
                    findings.append({"severity": "warn", "code": "LINT-006",
                                     "rule": rule.name,
                                     "message": f"unreachable: earlier rule {earlier.name!r} "
                                                f"covers every call this rule could match "
                                                f"(same action {rule.action})"})
                else:
                    findings.append({"severity": "error", "code": "LINT-007",
                                     "rule": rule.name,
                                     "message": f"shadowed: earlier rule {earlier.name!r} "
                                                f"(action={earlier.action}) covers every call this "
                                                f"rule could match, so this rule (action={rule.action}) "
                                                f"never fires — reorder or narrow the earlier rule"})
                break
    if policy.default_action not in ACTIONS:
        findings.append({"severity": "error", "code": "LINT-008", "rule": "(policy)",
                         "message": f"unknown default_action {policy.default_action!r}"})
    return findings
