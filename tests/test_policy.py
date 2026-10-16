"""Unit tests: matchers, rule matching, evaluation order, lint."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approval_gate.policy import (
    ToolCall, Rule, Policy, load_policy, evaluate, lint_policy,
    get_path, match_value, _MISSING,
)


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class TestGetPath(unittest.TestCase):
    def test_nested(self):
        self.assertEqual(get_path({"a": {"b": 1}}, "a.b"), 1)

    def test_list_index(self):
        self.assertEqual(get_path({"items": [{"sku": "x"}]}, "items.0.sku"), "x")

    def test_missing(self):
        self.assertIs(get_path({"a": 1}, "b"), _MISSING)
        self.assertIs(get_path({"a": 1}, "a.b.c"), _MISSING)
        self.assertIs(get_path({"items": []}, "items.0"), _MISSING)


class TestMatchers(unittest.TestCase):
    def test_eq_ne(self):
        self.assertTrue(match_value("prod", {"eq": "prod"}))
        self.assertFalse(match_value("dev", {"eq": "prod"}))
        self.assertTrue(match_value("dev", {"ne": "prod"}))

    def test_regex_glob(self):
        self.assertTrue(match_value("delete_user", {"regex": "^delete"}))
        self.assertFalse(match_value("undelete", {"regex": "^delete"}))
        self.assertTrue(match_value("db.get_order", {"glob": "db.get_*"}))

    def test_numeric(self):
        self.assertTrue(match_value(1200, {"gt": 500}))
        self.assertFalse(match_value(500, {"gt": 500}))
        self.assertTrue(match_value(500, {"gte": 500, "lte": 500}))
        # non-numeric never matches a numeric comparison (no silent coercion)
        self.assertFalse(match_value("1200", {"gt": 500}))
        # bools are not numbers for this purpose
        self.assertFalse(match_value(True, {"gt": 0}))

    def test_in_nin(self):
        self.assertTrue(match_value("prod", {"in": ["prod", "staging"]}))
        self.assertTrue(match_value("dev", {"nin": ["prod", "staging"]}))

    def test_exists(self):
        self.assertTrue(match_value(_MISSING, {"exists": False}))
        self.assertFalse(match_value(_MISSING, {"exists": True}))
        self.assertTrue(match_value(0, {"exists": True}))

    def test_contains(self):
        self.assertTrue(match_value("please delete everything", {"contains": "delete"}))

    def test_missing_path_only_exists_false_matches(self):
        # a matcher on an absent arg must not fire, except exists:false
        self.assertFalse(match_value(_MISSING, {"eq": "prod"}))
        self.assertFalse(match_value(_MISSING, {"gt": 1}))

    def test_and_semantics(self):
        self.assertTrue(match_value(750, {"gt": 500, "lt": 1000}))
        self.assertFalse(match_value(1500, {"gt": 500, "lt": 1000}))

    def test_unknown_op_raises(self):
        with self.assertRaises(ValueError):
            match_value(1, {"frob": 2})


class TestRuleMatching(unittest.TestCase):
    def test_tool_glob(self):
        r = Rule(name="r", tool="db.*", action="deny")
        self.assertTrue(r.matches(ToolCall(tool="db.delete")))
        self.assertFalse(r.matches(ToolCall(tool="billing.refund")))

    def test_args_all_must_match(self):
        r = Rule(name="r", tool="billing.*",
                 args={"amount": {"gt": 500}, "env": {"eq": "prod"}}, action="deny")
        self.assertTrue(r.matches(ToolCall(tool="billing.refund",
                                           args={"amount": 600, "env": "prod"})))
        self.assertFalse(r.matches(ToolCall(tool="billing.refund",
                                            args={"amount": 600, "env": "dev"})))
        self.assertFalse(r.matches(ToolCall(tool="billing.refund",
                                            args={"amount": 600})))


class TestEvaluate(unittest.TestCase):
    def _policy(self):
        return Policy(name="t", rules=[
            Rule(name="deny-prod", tool="db.*", args={"env": {"eq": "prod"}},
                 action="deny"),
            Rule(name="big-refund", tool="billing.refund",
                 args={"amount": {"gt": 500}}, action="require_approval",
                 ttl_seconds=60),
        ], default_action="require_approval")

    def test_first_match_wins(self):
        p = self._policy()
        res = evaluate(p, ToolCall(tool="db.drop", args={"env": "prod"}))
        self.assertEqual((res.action, res.rule.name), ("deny", "deny-prod"))

    def test_later_rule(self):
        p = self._policy()
        res = evaluate(p, ToolCall(tool="billing.refund", args={"amount": 900}))
        self.assertEqual(res.action, "require_approval")
        self.assertEqual(res.ttl_seconds, 60)

    def test_default_fail_closed(self):
        p = self._policy()
        res = evaluate(p, ToolCall(tool="email.send", args={}))
        self.assertEqual(res.action, "require_approval")
        self.assertIsNone(res.rule)

    def test_call_id_deterministic(self):
        c1 = ToolCall(tool="a.b", args={"x": 1, "y": [1, 2]})
        c2 = ToolCall(tool="a.b", args={"y": [1, 2], "x": 1})
        self.assertEqual(c1.call_id, c2.call_id)
        self.assertNotEqual(c1.call_id, ToolCall(tool="a.b", args={"x": 2}).call_id)


class TestLint(unittest.TestCase):
    def test_clean_policy(self):
        p = Policy(rules=[Rule(name="a", tool="db.*", action="deny")])
        self.assertEqual(lint_policy(p), [])

    def test_duplicate_name(self):
        p = Policy(rules=[Rule(name="a", tool="x"), Rule(name="a", tool="y")])
        codes = [f["code"] for f in lint_policy(p) if f["severity"] == "error"]
        self.assertIn("LINT-001", codes)

    def test_bad_action(self):
        p = Policy(rules=[Rule(name="a", tool="x", action="explode")])
        codes = [f["code"] for f in lint_policy(p)]
        self.assertIn("LINT-002", codes)

    def test_zero_ttl(self):
        p = Policy(rules=[Rule(name="a", tool="x", action="require_approval",
                               ttl_seconds=0)])
        codes = [f["code"] for f in lint_policy(p)]
        self.assertIn("LINT-004", codes)

    def test_escalate_without_tier2(self):
        p = Policy(rules=[Rule(name="a", tool="x", action="require_approval",
                               on_timeout="escalate", tiers=1)])
        codes = [f["code"] for f in lint_policy(p) if f["severity"] == "warn"]
        self.assertIn("LINT-005", codes)

    def test_shadowed_unreachable(self):
        p = Policy(rules=[
            Rule(name="catchall", tool="*", action="deny"),
            Rule(name="specific", tool="db.drop", args={"env": {"eq": "prod"}},
                 action="allow"),
        ])
        by_code = {}
        for f in lint_policy(p):
            by_code.setdefault(f["code"], []).append(f["rule"])
        # same tool-coverage, different action -> shadowed error on the later rule
        self.assertIn("specific", by_code.get("LINT-007", []))

    def test_same_action_shadow_is_warn_not_error(self):
        p = Policy(rules=[
            Rule(name="catchall", tool="*", action="deny"),
            Rule(name="also-deny", tool="db.*", action="deny"),
        ])
        findings = [f for f in lint_policy(p) if f["rule"] == "also-deny"]
        self.assertTrue(findings)
        self.assertTrue(all(f["severity"] == "warn" for f in findings))

    def test_narrower_earlier_rule_does_not_shadow(self):
        p = Policy(rules=[
            Rule(name="narrow", tool="db.drop", args={"env": {"eq": "prod"}},
                 action="deny"),
            Rule(name="broad", tool="db.*", action="require_approval"),
        ])
        shadowed = [f for f in lint_policy(p)
                    if f["code"] in ("LINT-006", "LINT-007")]
        self.assertEqual(shadowed, [])

    def test_bad_default_action(self):
        p = Policy(rules=[], default_action="maybe")
        codes = [f["code"] for f in lint_policy(p)]
        self.assertIn("LINT-008", codes)

    def test_lint_fixture_findings(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "fixtures", "lint_bad_policy.json")
        import json
        with open(path, encoding="utf-8") as f:
            policy = load_policy(json.load(f))
        findings = lint_policy(policy)
        codes = sorted(f["code"] for f in findings)
        # pinned: the fixture must produce exactly these findings
        self.assertEqual(codes, ["LINT-001", "LINT-002", "LINT-004", "LINT-005",
                                 "LINT-006", "LINT-006", "LINT-007", "LINT-007",
                                 "LINT-007", "LINT-007"])
        self.assertTrue(any(f["severity"] == "error" for f in findings))


if __name__ == "__main__":
    unittest.main()
