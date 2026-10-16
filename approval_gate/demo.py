"""End-to-end demo: the Helios Home support agent under the approval gate.

Fixed clock (t=1_000_000) so the whole scenario is deterministic.
Exercises: allow, deny, approve-in-time, reject, timeout->deny (fail closed),
timeout->escalate->tier2 approve, hold, idempotent replay, audit chain.
"""

from __future__ import annotations

import json
import os

from . import Gate, ToolCall, AuditLog, ApprovalStore, load_policy

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "fixtures")


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def build_gate(audit_path: str | None = None) -> tuple[Gate, Clock]:
    import tempfile

    with open(os.path.join(FIXTURES, "policy.json"), encoding="utf-8") as f:
        policy = load_policy(json.load(f))
    clock = Clock()
    store = ApprovalStore(clock=clock, tier2_ttl_seconds=policy.tier2_ttl_seconds)
    audit = AuditLog(audit_path or tempfile.mktemp(suffix=".jsonl"), clock=clock)
    return Gate(policy, store=store, audit=audit, clock=clock), clock


def run() -> None:
    gate, clock = build_gate()
    print("== tool-approval-gate demo: Helios Home support agent ==")

    # 1. Read-only lookup -> allowed immediately.
    d = gate.submit(ToolCall(tool="helios.get_order", args={"order_id": "H-1001"}))
    assert d.verdict == "allowed" and d.rule_name == "read-only tools", d
    print(f"1. get_order            -> {d.verdict} (rule: {d.rule_name})")

    # 2. Prod delete without a ticket -> denied outright.
    d = gate.submit(ToolCall(tool="db.delete_customer",
                             args={"customer_id": "C-9", "env": "prod"}))
    assert d.verdict == "denied" and d.rule_name == "no prod deletes", d
    print(f"2. prod delete         -> {d.verdict} (rule: {d.rule_name})")

    # 3. Large refund -> approval; human approves in time -> allowed.
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1002", "amount": 1200}))
    assert d.verdict == "pending_approval", d
    d2 = gate.approve(d.request_id, "oncall-priya", "customer confirmed by phone")
    assert d2.verdict == "allowed", d2
    print(f"3. $1200 refund        -> pending -> {d2.verdict} (approved by oncall-priya)")

    # 4. Same shape, small amount -> allowed (threshold matcher).
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1003", "amount": 40}))
    assert d.verdict == "allowed", d
    print(f"4. $40 refund          -> {d.verdict} (under the $500 approval threshold)")

    # 5. Rejected approval -> denied.
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1004", "amount": 900}))
    assert d.verdict == "pending_approval", d
    d2 = gate.reject(d.request_id, "oncall-priya", "duplicate of H-1002")
    assert d2.verdict == "denied", d2
    print(f"5. $900 refund         -> pending -> {d2.verdict} (rejected: duplicate)")

    # 6. Timeout with on_timeout=deny -> fail closed.
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1005", "amount": 750}))
    rid = d.request_id
    clock.advance(301)  # past the 300s TTL, nobody answered
    d2 = gate.check(rid)
    assert d2.verdict == "denied" and "timeout" in d2.note, d2
    print(f"6. $750 refund, silent -> pending -> {d2.verdict} (timeout: fail closed)")

    # 7. Escalation path: warehouse.ship_high_value escalates to tier 2.
    d = gate.submit(ToolCall(tool="warehouse.ship_high_value",
                             args={"sku": "HELIOS-PRO", "qty": 50}))
    assert d.verdict == "pending_approval", d
    clock.advance(121)  # past the 120s tier-1 TTL
    d2 = gate.check(d.request_id)
    assert d2.verdict == "pending_approval" and "tier 2" in d2.note, d2
    req = gate.store.get(d.request_id)
    assert req.tier == 2 and req.status == "pending", req.to_dict()
    d3 = gate.approve(d.request_id, "manager-dev", "quarterly stock approved")
    assert d3.verdict == "allowed", d3
    print(f"7. high-value shipment -> tier-1 timeout -> escalated to tier 2 -> {d3.verdict}")

    # 8. Tier-2 silence -> fail closed (escalation is not a loophole).
    d = gate.submit(ToolCall(tool="warehouse.ship_high_value",
                             args={"sku": "HELIOS-PRO", "qty": 75}))
    clock.advance(121)
    gate.check(d.request_id)          # -> tier 2
    clock.advance(601)                # past tier-2 TTL
    d2 = gate.check(d.request_id)
    assert d2.verdict == "denied", d2
    print(f"8. tier-2 silent        -> {d2.verdict} (escalation still fails closed)")

    # 9. Idempotent replay: same key, same decision, no duplicate request.
    n_before = len(gate.store.all_requests())
    d = gate.submit(ToolCall(tool="helios.get_order", args={"order_id": "H-1001"},
                             idempotency_key="op-42"))
    d2 = gate.submit(ToolCall(tool="helios.get_order", args={"order_id": "H-1001"},
                              idempotency_key="op-42"))
    assert d2.replayed and d2.verdict == d.verdict, (d, d2)
    assert len(gate.store.all_requests()) == n_before, "replay must not create requests"
    print(f"9. idempotent replay   -> {d2.verdict} (replayed, no duplicate)")

    # 10. Audit chain verifies.
    ok, msg = gate.audit.verify()
    assert ok, msg
    print(f"10. audit log          -> {msg}")

    print("\ndemo complete: every path behaved as the policy declares.")


if __name__ == "__main__":
    run()
