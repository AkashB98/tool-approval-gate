#!/usr/bin/env python3
"""Golden evals for tool-approval-gate.

Deterministic end-to-end scenarios with PINNED expectations (evals/golden.json).
Every scenario runs on a fixed clock, so eval_report.json must be byte-identical
across runs — the md5 pin is the determinism proof.

Usage: python evals/run_evals.py [--report evals/eval_report.json]
Exit 0 iff every golden eval passes.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approval_gate import (  # noqa: E402
    Gate, ToolCall, AuditLog, ApprovalStore, load_policy, lint_policy,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "fixtures")


class Clock:
    def __init__(self, t=2_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def fresh_gate():
    with open(os.path.join(FIXTURES, "policy.json"), encoding="utf-8") as f:
        policy = load_policy(json.load(f))
    clock = Clock()
    audit = AuditLog(tempfile.mktemp(suffix=".jsonl"), clock=clock)
    store = ApprovalStore(clock=clock, tier2_ttl_seconds=policy.tier2_ttl_seconds)
    return Gate(policy, store=store, audit=audit, clock=clock), clock, audit


def scenario_allow_read(gate, clock):
    d = gate.submit(ToolCall(tool="helios.get_order", args={"order_id": "H-1001"}))
    return {"verdict": d.verdict, "rule": d.rule_name}


def scenario_deny_prod_delete(gate, clock):
    d = gate.submit(ToolCall(tool="db.delete_customer",
                             args={"customer_id": "C-9", "env": "prod"}))
    return {"verdict": d.verdict, "rule": d.rule_name}


def scenario_approve_in_time(gate, clock):
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1002", "amount": 1200}))
    pending = {"verdict": d.verdict, "request_id": d.request_id}
    clock.advance(10)
    d2 = gate.approve(d.request_id, "oncall-priya", "confirmed")
    return {"pending": pending, "final": d2.verdict}


def scenario_reject(gate, clock):
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1004", "amount": 900}))
    d2 = gate.reject(d.request_id, "oncall-priya", "duplicate")
    return {"final": d2.verdict}


def scenario_timeout_deny(gate, clock):
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1005", "amount": 750}))
    clock.advance(301)
    d2 = gate.check(d.request_id)
    return {"final": d2.verdict, "timeout_noted": "timeout" in d2.note}


def scenario_escalate_tier2_approve(gate, clock):
    d = gate.submit(ToolCall(tool="warehouse.ship_high_value",
                             args={"sku": "HELIOS-PRO", "qty": 50}))
    clock.advance(121)
    d2 = gate.check(d.request_id)
    tier = gate.store.get(d.request_id).tier
    d3 = gate.approve(d.request_id, "manager-dev", "ok")
    return {"after_timeout": d2.verdict, "tier": tier, "final": d3.verdict}


def scenario_tier2_timeout_deny(gate, clock):
    d = gate.submit(ToolCall(tool="warehouse.ship_high_value",
                             args={"sku": "HELIOS-PRO", "qty": 75}))
    clock.advance(121)
    gate.check(d.request_id)
    clock.advance(601)
    d2 = gate.check(d.request_id)
    return {"final": d2.verdict}


def scenario_idempotent_replay(gate, clock):
    n0 = len(gate.store.all_requests())
    d1 = gate.submit(ToolCall(tool="helios.get_order", args={"order_id": "H-1"},
                              idempotency_key="eval-1"))
    d2 = gate.submit(ToolCall(tool="helios.get_order", args={"order_id": "H-1"},
                              idempotency_key="eval-1"))
    return {"replayed": d2.replayed, "verdict": d2.verdict,
            "new_requests": len(gate.store.all_requests()) - n0}


def scenario_default_action(gate, clock):
    d = gate.submit(ToolCall(tool="email.send", args={"to": "x@y.z"}))
    return {"verdict": d.verdict, "rule": d.rule_name}


def scenario_lint_fixture(gate, clock):
    with open(os.path.join(FIXTURES, "lint_bad_policy.json"), encoding="utf-8") as f:
        policy = load_policy(json.load(f))
    return {"finding_codes": sorted(f["code"] for f in lint_policy(policy))}


def scenario_audit_chain(gate, clock):
    d = gate.submit(ToolCall(tool="billing.refund",
                             args={"order_id": "H-1002", "amount": 1200}))
    gate.approve(d.request_id, "oncall-priya")
    ok, msg = gate.audit.verify()
    recs = gate.audit.read_all()
    return {"chain_ok": ok,
            "record_count": len(recs),
            "chain_md5": hashlib.md5(
                "".join(r["hash"] for r in recs).encode()).hexdigest()}


SCENARIOS = {
    "allow_read": scenario_allow_read,
    "deny_prod_delete": scenario_deny_prod_delete,
    "approve_in_time": scenario_approve_in_time,
    "reject": scenario_reject,
    "timeout_deny": scenario_timeout_deny,
    "escalate_tier2_approve": scenario_escalate_tier2_approve,
    "tier2_timeout_deny": scenario_tier2_timeout_deny,
    "idempotent_replay": scenario_idempotent_replay,
    "default_action": scenario_default_action,
    "lint_fixture": scenario_lint_fixture,
    "audit_chain": scenario_audit_chain,
}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=os.path.join(ROOT, "evals", "eval_report.json"))
    ap.add_argument("--golden", default=os.path.join(ROOT, "evals", "golden.json"))
    a = ap.parse_args(argv)

    with open(a.golden, encoding="utf-8") as f:
        golden = json.load(f)

    results = []
    for name, fn in SCENARIOS.items():
        gate, clock, _ = fresh_gate()
        try:
            actual = fn(gate, clock)
            expected = golden[name]
            passed = actual == expected
            detail = "" if passed else f"expected {expected}, got {actual}"
        except Exception as e:  # noqa: BLE001
            actual, passed, detail = {"error": str(e)}, False, f"raised {e!r}"
        results.append({"name": name, "passed": passed,
                        "expected": golden.get(name), "actual": actual,
                        "detail": detail})
        print(f"{'PASS' if passed else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))

    report = {"evals": results,
              "passed": sum(r["passed"] for r in results),
              "total": len(results)}
    with open(a.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(a.report, "rb") as f:
        md5 = hashlib.md5(f.read()).hexdigest()
    print(f"\n{report['passed']}/{report['total']} golden evals passed; report md5={md5}")
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
