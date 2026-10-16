"""Unit tests: Gate orchestration — submit/check/approve/reject, idempotency."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approval_gate import Gate, ToolCall, AuditLog, ApprovalStore, load_policy


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def make_gate():
    fixtures = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "fixtures")
    with open(os.path.join(fixtures, "policy.json"), encoding="utf-8") as f:
        policy = load_policy(json.load(f))
    clock = FakeClock()
    audit = AuditLog(tempfile.mktemp(suffix=".jsonl"), clock=clock)
    store = ApprovalStore(clock=clock, tier2_ttl_seconds=policy.tier2_ttl_seconds)
    gate = Gate(policy, store=store, audit=audit, clock=clock)
    return gate, clock, audit


class TestGate(unittest.TestCase):
    def test_allow_path(self):
        gate, _, _ = make_gate()
        d = gate.submit(ToolCall(tool="helios.get_order", args={"order_id": "H-1"}))
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.rule_name, "read-only tools")
        self.assertIsNone(d.request_id)

    def test_deny_path(self):
        gate, _, _ = make_gate()
        d = gate.submit(ToolCall(tool="db.delete_customer",
                                 args={"env": "prod", "customer_id": "C-1"}))
        self.assertEqual(d.verdict, "denied")
        self.assertEqual(d.rule_name, "no prod deletes")

    def test_default_require_approval(self):
        gate, _, _ = make_gate()
        d = gate.submit(ToolCall(tool="email.send", args={}))
        self.assertEqual(d.verdict, "pending_approval")
        self.assertEqual(d.rule_name, "(default)")  # default action labeled in audit trail
        self.assertTrue(d.request_id.startswith("apr-"))

    def test_approve_flow(self):
        gate, _, _ = make_gate()
        d = gate.submit(ToolCall(tool="billing.refund",
                                 args={"amount": 900, "order_id": "H-2"}))
        d2 = gate.approve(d.request_id, "priya", "ok")
        self.assertEqual(d2.verdict, "allowed")
        self.assertIn("priya", d2.note)

    def test_reject_flow(self):
        gate, _, _ = make_gate()
        d = gate.submit(ToolCall(tool="billing.refund",
                                 args={"amount": 900, "order_id": "H-2"}))
        d2 = gate.reject(d.request_id, "priya", "dup")
        self.assertEqual(d2.verdict, "denied")

    def test_check_timeout_denies(self):
        gate, clock, _ = make_gate()
        d = gate.submit(ToolCall(tool="billing.refund",
                                 args={"amount": 900, "order_id": "H-2"}))
        clock.advance(301)
        d2 = gate.check(d.request_id)
        self.assertEqual(d2.verdict, "denied")
        self.assertIn("timeout", d2.note)

    def test_escalation_flow(self):
        gate, clock, _ = make_gate()
        d = gate.submit(ToolCall(tool="warehouse.ship_high_value",
                                 args={"qty": 50, "sku": "S"}))
        clock.advance(121)
        d2 = gate.check(d.request_id)
        self.assertEqual(d2.verdict, "pending_approval")
        self.assertIn("tier 2", d2.note)
        d3 = gate.approve(d.request_id, "manager-dev")
        self.assertEqual(d3.verdict, "allowed")

    def test_idempotent_replay(self):
        gate, _, _ = make_gate()
        n0 = len(gate.store.all_requests())
        d1 = gate.submit(ToolCall(tool="helios.get_order", args={},
                                  idempotency_key="k-1"))
        d2 = gate.submit(ToolCall(tool="helios.get_order", args={"other": 1},
                                  idempotency_key="k-1"))
        self.assertTrue(d2.replayed)
        self.assertEqual(d2.verdict, d1.verdict)
        self.assertEqual(len(gate.store.all_requests()), n0)

    def test_idempotent_replay_of_pending(self):
        gate, _, _ = make_gate()
        d1 = gate.submit(ToolCall(tool="billing.refund", args={"amount": 900},
                                  idempotency_key="k-2"))
        d2 = gate.submit(ToolCall(tool="billing.refund", args={"amount": 900},
                                  idempotency_key="k-2"))
        self.assertTrue(d2.replayed)
        self.assertEqual(d2.request_id, d1.request_id)
        self.assertEqual(len(gate.store.all_requests()), 1)

    def test_audit_chronology(self):
        gate, _, audit = make_gate()
        d = gate.submit(ToolCall(tool="billing.refund",
                                 args={"amount": 900, "order_id": "H-9"}))
        gate.approve(d.request_id, "priya")
        events = [r["event"] for r in audit.read_all()]
        # approval_requested must precede the decision that references it
        self.assertLess(events.index("approval_requested"), events.index("decision"))
        self.assertIn("approval_approved", events)
        ok, _ = audit.verify()
        self.assertTrue(ok)

    def test_check_unknown_request_raises(self):
        gate, _, _ = make_gate()
        with self.assertRaises(KeyError):
            gate.check("apr-9999")


if __name__ == "__main__":
    unittest.main()
