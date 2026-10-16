#!/usr/bin/env python3
"""CLI for tool-approval-gate.

    demo                        end-to-end scripted scenario (asserts inline)
    check <policy.json>         lint the policy; exit 0 clean / 1 warnings / 2 errors
    simulate <policy> <calls>   dry-run calls (JSONL) through the policy; print verdicts
    serve [--port N] [--policy P] [--audit PATH]
    pending [--policy P]        list live approval requests (sweep applied)
    approve <id> <approver> [--policy P] [--note T]
    reject  <id> <approver> [--policy P] [--note T]
    audit [--verify]            print the audit log / verify the hash chain
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approval_gate import (  # noqa: E402
    Gate, ToolCall, load_policy_file, lint_policy, AuditLog, ApprovalStore,
)
from approval_gate import demo as demo_mod  # noqa: E402
from approval_gate.server import serve  # noqa: E402

DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "fixtures", "policy.json")
DEFAULT_AUDIT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "var", "audit.jsonl")


def _gate(policy_path: str, audit_path: str) -> Gate:
    policy = load_policy_file(policy_path)
    return Gate(policy, audit=AuditLog(audit_path))


def cmd_check(a) -> int:
    findings = lint_policy(load_policy_file(a.policy))
    for f in findings:
        print(f"[{f['severity'].upper():5}] {f['code']} ({f['rule']}): {f['message']}")
    if not findings:
        print("policy clean: no findings")
        return 0
    if any(f["severity"] == "error" for f in findings):
        return 2
    return 1


def cmd_simulate(a) -> int:
    policy = load_policy_file(a.policy)
    gate = Gate(policy)  # no audit: dry run
    with open(a.calls, encoding="utf-8") as f:
        calls = [json.loads(line) for line in f if line.strip()]
    for c in calls:
        d = gate.submit(ToolCall(tool=c["tool"], args=c.get("args", {}),
                                 actor=c.get("actor", "agent"),
                                 idempotency_key=c.get("idempotency_key")))
        rule = d.rule_name or "(default)"
        extra = f" [{d.request_id}]" if d.request_id else ""
        print(f"{d.verdict:16} {c['tool']:28} rule={rule}{extra}")
    return 0


def cmd_pending(a) -> int:
    gate = _gate(a.policy, a.audit)
    reqs = gate.store.pending()
    if not reqs:
        print("no pending approval requests")
        return 0
    for r in reqs:
        wait = f"{r.deadline - r.created_at:.0f}s ttl" if r.deadline else "hold"
        print(f"{r.id} tier={r.tier} {r.tool} rule={r.rule_name} {wait}")
        print(f"    args={json.dumps(r.args, sort_keys=True)[:160]}")
    return 0


def cmd_decide(a, approve: bool) -> int:
    gate = _gate(a.policy, a.audit)
    try:
        d = gate.approve(a.request_id, a.approver, a.note) if approve \
            else gate.reject(a.request_id, a.approver, a.note)
    except (KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{d.verdict} ({d.note})")
    return 0


def cmd_audit(a) -> int:
    log = AuditLog(a.audit)
    if a.verify:
        ok, msg = log.verify()
        print(msg)
        return 0 if ok else 1
    for rec in log.read_all():
        print(json.dumps(rec, sort_keys=True))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="approval-gate")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("demo"); s.set_defaults(fn=lambda a: demo_mod.run() or 0)
    s = sub.add_parser("check"); s.add_argument("policy"); s.set_defaults(fn=cmd_check)
    s = sub.add_parser("simulate")
    s.add_argument("policy"); s.add_argument("calls"); s.set_defaults(fn=cmd_simulate)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8471)
    s.add_argument("--policy", default=DEFAULT_POLICY)
    s.add_argument("--audit", default=DEFAULT_AUDIT)
    s.set_defaults(fn=lambda a: serve(_gate(a.policy, a.audit), a.port) or 0)
    for name in ("pending",):
        s = sub.add_parser(name)
        s.add_argument("--policy", default=DEFAULT_POLICY)
        s.add_argument("--audit", default=DEFAULT_AUDIT)
        s.set_defaults(fn=cmd_pending)
    for name, approve in (("approve", True), ("reject", False)):
        s = sub.add_parser(name)
        s.add_argument("request_id"); s.add_argument("approver")
        s.add_argument("--note", default="")
        s.add_argument("--policy", default=DEFAULT_POLICY)
        s.add_argument("--audit", default=DEFAULT_AUDIT)
        s.set_defaults(fn=lambda a, ap=approve: cmd_decide(a, ap))
    s = sub.add_parser("audit")
    s.add_argument("--verify", action="store_true")
    s.add_argument("--audit", default=DEFAULT_AUDIT)
    s.set_defaults(fn=cmd_audit)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
