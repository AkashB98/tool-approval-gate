"""Gate: the single choke point between an agent's planner and its executor.

    decision = gate.submit(call)   # -> GateDecision(allowed|denied|pending_approval)

- allow            -> execute immediately; decision audited.
- deny             -> do not execute; decision audited with the matched rule.
- pending_approval -> an ApprovalRequest was created; the agent MUST NOT
                      execute until gate.check(request_id) reports approved.
                      Timeouts are applied lazily on every check/submit
                      (sweep), so nothing needs a background thread.

Idempotency: if a call carries an idempotency_key and the same key was
already decided, the cached decision is returned and the replay is audited
as a replay (no duplicate side effects downstream).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .approvals import ApprovalStore
from .audit import AuditLog
from .policy import ToolCall, Policy, evaluate


@dataclass
class GateDecision:
    verdict: str                 # allowed | denied | pending_approval
    call_id: str
    rule_name: str | None
    request_id: str | None = None
    note: str = ""
    replayed: bool = False


class Gate:
    def __init__(self, policy: Policy, store: ApprovalStore | None = None,
                 audit: AuditLog | None = None,
                 clock: Callable[[], float] | None = None):
        self.policy = policy
        self._clock = clock or time.time
        self.store = store or ApprovalStore(clock=self._clock,
                                            tier2_ttl_seconds=policy.tier2_ttl_seconds)
        self.audit = audit
        self._decisions: dict[str, GateDecision] = {}  # idempotency_key -> decision

    def _log(self, event: str, **fields) -> None:
        # Drain store events FIRST so the audit log stays chronological
        # (e.g. approval_requested lands before the decision that references it).
        pending = self.store.drain_events()
        for ev in pending:
            if self.audit is not None:
                self.audit.append("approval_" + ev["event"], request_id=ev["request_id"],
                                  call_id=ev["call_id"], tier=ev["tier"],
                                  detail=ev["detail"])
        if self.audit is not None:
            self.audit.append(event, **fields)

    def submit(self, call: ToolCall) -> GateDecision:
        self.store.sweep()
        key = call.idempotency_key
        if key is not None and key in self._decisions:
            cached = self._decisions[key]
            self._log("decision_replayed", call_id=call.call_id, tool=call.tool,
                      verdict=cached.verdict, idempotency_key=key)
            return GateDecision(cached.verdict, cached.call_id, cached.rule_name,
                                cached.request_id, cached.note, replayed=True)

        result = evaluate(self.policy, call)
        if result.action == "allow":
            d = GateDecision("allowed", call.call_id,
                             result.rule.name if result.rule else None,
                             note="policy allow")
        elif result.action == "deny":
            d = GateDecision("denied", call.call_id,
                             result.rule.name if result.rule else None,
                             note=(result.rule.reason if result.rule and result.rule.reason
                                   else "policy deny"))
        else:
            req = self.store.request(call, result.rule, result.ttl_seconds,
                                     default_on_timeout=result.on_timeout)
            d = GateDecision("pending_approval", call.call_id, req.rule_name,
                             request_id=req.id,
                             note=f"awaiting tier-{req.tier} approval (ttl {result.ttl_seconds}s)")
        if key is not None:
            self._decisions[key] = d
        self._log("decision", call_id=call.call_id, tool=call.tool, actor=call.actor,
                  verdict=d.verdict, rule=d.rule_name, request_id=d.request_id,
                  note=d.note)
        return d

    def check(self, request_id: str) -> GateDecision:
        """Re-check a pending request: applies timeouts, returns the outcome."""
        self.store.sweep()
        req = self.store.get(request_id)
        if req.status == "approved":
            d = GateDecision("allowed", req.call_id, req.rule_name,
                             request_id=req.id,
                             note=f"approved by {req.decided_by} (tier {req.tier})")
        elif req.status in ("rejected", "timed_out"):
            d = GateDecision("denied", req.call_id, req.rule_name,
                             request_id=req.id, note=req.decision_note)
        elif req.status == "pending":
            d = GateDecision("pending_approval", req.call_id, req.rule_name,
                             request_id=req.id,
                             note=f"still pending at tier {req.tier}")
        else:  # escalated is transient; sweep already moved it
            d = GateDecision("pending_approval", req.call_id, req.rule_name,
                             request_id=req.id, note="escalated")
        self._log("recheck", request_id=req.id, call_id=req.call_id,
                  verdict=d.verdict, note=d.note)
        return d

    def approve(self, request_id: str, approver: str, note: str = "") -> GateDecision:
        self.store.approve(request_id, approver, note)
        self._log("manual_approve", request_id=request_id, approver=approver, note=note)
        return self.check(request_id)

    def reject(self, request_id: str, approver: str, note: str = "") -> GateDecision:
        self.store.reject(request_id, approver, note)
        self._log("manual_reject", request_id=request_id, approver=approver, note=note)
        return self.check(request_id)
