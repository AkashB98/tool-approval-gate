"""Unit tests: approval lifecycle, timeouts, escalation, idempotency."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approval_gate.approvals import ApprovalStore
from approval_gate.policy import ToolCall, Rule


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def _rule(**kw):
    base = dict(name="r", tool="*", action="require_approval",
                on_timeout="deny", ttl_seconds=100, tiers=1)
    base.update(kw)
    return Rule(**base)


def _call(tool="billing.refund", **args):
    return ToolCall(tool=tool, args=args)


class TestApprovalLifecycle(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.store = ApprovalStore(clock=self.clock)

    def test_request_ids_sequential(self):
        r1 = self.store.request(_call(), _rule(), 100)
        r2 = self.store.request(_call(x=1), _rule(), 100)
        self.assertEqual((r1.id, r2.id), ("apr-0001", "apr-0002"))

    def test_approve(self):
        r = self.store.request(_call(), _rule(), 100)
        self.store.approve(r.id, "priya", "looks good")
        self.assertEqual(r.status, "approved")
        self.assertEqual(r.decided_by, "priya")

    def test_reject(self):
        r = self.store.request(_call(), _rule(), 100)
        self.store.reject(r.id, "priya", "nope")
        self.assertEqual(r.status, "rejected")

    def test_double_decide_raises(self):
        r = self.store.request(_call(), _rule(), 100)
        self.store.approve(r.id, "priya")
        with self.assertRaises(ValueError):
            self.store.reject(r.id, "priya")

    def test_unknown_request(self):
        with self.assertRaises(KeyError):
            self.store.approve("apr-9999", "priya")

    def test_live_request_returned_not_duplicated(self):
        c = _call()
        r1 = self.store.request(c, _rule(), 100)
        r2 = self.store.request(c, _rule(), 100)
        self.assertIs(r1, r2)
        self.assertEqual(len(self.store.all_requests()), 1)

    def test_decided_call_gets_new_request(self):
        c = _call()
        r1 = self.store.request(c, _rule(), 100)
        self.store.approve(r1.id, "priya")
        r2 = self.store.request(c, _rule(), 100)
        self.assertIsNot(r1, r2)


class TestTimeouts(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_timeout_denies_fail_closed(self):
        store = ApprovalStore(clock=self.clock)
        r = store.request(_call(), _rule(on_timeout="deny"), 100)
        self.clock.advance(101)
        fired = store.sweep()
        self.assertEqual([x.id for x in fired], [r.id])
        self.assertEqual(r.status, "timed_out")
        self.assertEqual(r.decided_by, "system(timeout)")

    def test_no_timeout_before_deadline(self):
        store = ApprovalStore(clock=self.clock)
        r = store.request(_call(), _rule(), 100)
        self.clock.advance(99)
        self.assertEqual(store.sweep(), [])
        self.assertEqual(r.status, "pending")

    def test_escalate_moves_to_tier2_with_fresh_ttl(self):
        store = ApprovalStore(clock=self.clock, tier2_ttl_seconds=600)
        r = store.request(_call(), _rule(on_timeout="escalate", tiers=2), 100)
        self.clock.advance(101)
        store.sweep()
        self.assertEqual(r.status, "pending")
        self.assertEqual(r.tier, 2)
        self.assertAlmostEqual(r.deadline, self.clock() + 600)
        events = [e["event"] for e in r.history]
        self.assertIn("escalated", events)

    def test_tier2_timeout_fails_closed(self):
        store = ApprovalStore(clock=self.clock, tier2_ttl_seconds=600)
        r = store.request(_call(), _rule(on_timeout="escalate", tiers=2), 100)
        self.clock.advance(101)
        store.sweep()          # -> tier 2
        self.clock.advance(601)
        store.sweep()          # tier-2 timeout -> deny
        self.assertEqual(r.status, "timed_out")

    def test_escalate_past_max_tiers_denies(self):
        store = ApprovalStore(clock=self.clock)
        # tiers=1 but on_timeout=escalate: nothing to escalate TO -> deny
        r = store.request(_call(), _rule(on_timeout="escalate", tiers=1), 100)
        self.clock.advance(101)
        store.sweep()
        self.assertEqual(r.status, "timed_out")

    def test_hold_never_times_out(self):
        store = ApprovalStore(clock=self.clock)
        r = store.request(_call(), _rule(on_timeout="hold"), 100)
        self.clock.advance(10_000)
        self.assertEqual(store.sweep(), [])
        self.assertEqual(r.status, "pending")

    def test_pending_applies_sweep(self):
        store = ApprovalStore(clock=self.clock)
        r = store.request(_call(), _rule(), 100)
        self.clock.advance(101)
        self.assertEqual(store.pending(), [])
        self.assertEqual(r.status, "timed_out")

    def test_pending_tier_filter(self):
        store = ApprovalStore(clock=self.clock, tier2_ttl_seconds=600)
        r1 = self.store_request(store, tier_rule=True)
        r2 = store.request(_call(x=2), _rule(), 100)
        self.assertEqual([r.id for r in store.pending(tier=2)], [r1.id])
        self.assertEqual([r.id for r in store.pending(tier=1)], [r2.id])

    def store_request(self, store, tier_rule=False):
        r = store.request(_call(), _rule(on_timeout="escalate", tiers=2), 100)
        self.clock.advance(101)
        store.sweep()
        return r


if __name__ == "__main__":
    unittest.main()
