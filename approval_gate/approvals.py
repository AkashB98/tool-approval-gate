"""Approval lifecycle: request -> pending -> approved|rejected|timed_out.

The store takes an injected clock (default: time.time) so timeouts and
escalations are fully deterministic in tests and evals — no sleeping.

Timeout semantics (per rule, `on_timeout`):
  deny      fail closed: the call is denied, audited as a timeout. (default)
  escalate  move the request to tier 2 with a fresh TTL (tier2_ttl_seconds).
            A tier-2 timeout always fails closed to deny.
  hold      the request stays pending forever; flagged in listings.

Request IDs are sequential (apr-0001, ...) — deterministic across runs
with the same input sequence. Idempotency: requesting approval for a call
that already has a live (pending or decided) request returns the existing
one instead of creating a duplicate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable

from .policy import ToolCall, Rule


@dataclass
class ApprovalRequest:
    id: str
    call_id: str
    tool: str
    args: dict
    actor: str
    rule_name: str
    tier: int = 1
    max_tiers: int = 1
    on_timeout: str = "deny"
    status: str = "pending"          # pending | approved | rejected | timed_out | escalated
    created_at: float = 0.0
    deadline: float = 0.0           # 0.0 means "no deadline" (hold)
    decided_at: float | None = None
    decided_by: str | None = None
    decision_note: str = ""
    history: list = field(default_factory=list)  # [{ts, event, detail}]

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_live(self) -> bool:
        return self.status in ("pending",)


class ApprovalStore:
    def __init__(self, clock: Callable[[], float] | None = None,
                 tier2_ttl_seconds: int = 600):
        self._clock = clock or time.time
        self.tier2_ttl_seconds = tier2_ttl_seconds
        self._requests: dict[str, ApprovalRequest] = {}
        self._by_call: dict[str, str] = {}   # call_id -> latest request id
        self._seq = 0
        self.events: list[dict] = []          # drained by Gate into the audit log

    def _now(self) -> float:
        return self._clock()

    def _emit(self, request: ApprovalRequest, event: str, detail: str = "") -> None:
        request.history.append({"ts": self._now(), "event": event, "detail": detail})
        self.events.append({"ts": self._now(), "request_id": request.id,
                            "call_id": request.call_id, "event": event,
                            "detail": detail, "tier": request.tier,
                            "status": request.status})

    def request(self, call: ToolCall, rule: Rule | None, ttl_seconds: int,
                default_on_timeout: str = "deny") -> ApprovalRequest:
        """Create (or return the live) approval request for this call+rule.

        rule may be None when the policy DEFAULT fired (no rule matched);
        the request is then labeled "(default)" and uses default_on_timeout.
        """
        existing_id = self._by_call.get(call.call_id)
        if existing_id is not None:
            existing = self._requests[existing_id]
            if existing.is_live:
                return existing
        self._seq += 1
        rule_name = rule.name if rule is not None else "(default)"
        max_tiers = max(1, rule.tiers) if rule is not None else 1
        on_timeout = rule.on_timeout if rule is not None else default_on_timeout
        req = ApprovalRequest(
            id=f"apr-{self._seq:04d}",
            call_id=call.call_id,
            tool=call.tool,
            args=dict(call.args),
            actor=call.actor,
            rule_name=rule_name,
            tier=1,
            max_tiers=max_tiers,
            on_timeout=on_timeout,
            created_at=self._now(),
            deadline=self._now() + ttl_seconds if ttl_seconds > 0 else 0.0,
        )
        self._requests[req.id] = req
        self._by_call[call.call_id] = req.id
        self._emit(req, "requested",
                   f"rule={rule_name} ttl={ttl_seconds}s on_timeout={on_timeout}")
        return req

    def get(self, request_id: str) -> ApprovalRequest:
        if request_id not in self._requests:
            raise KeyError(f"unknown approval request {request_id!r}")
        return self._requests[request_id]

    def approve(self, request_id: str, approver: str, note: str = "") -> ApprovalRequest:
        req = self.get(request_id)
        if not self._settleable(req):
            raise ValueError(f"request {request_id} is {req.status}, not pending")
        req.status = "approved"
        req.decided_at = self._now()
        req.decided_by = approver
        req.decision_note = note
        self._emit(req, "approved", f"by={approver} tier={req.tier} {note}".strip())
        return req

    def reject(self, request_id: str, approver: str, note: str = "") -> ApprovalRequest:
        req = self.get(request_id)
        if not self._settleable(req):
            raise ValueError(f"request {request_id} is {req.status}, not pending")
        req.status = "rejected"
        req.decided_at = self._now()
        req.decided_by = approver
        req.decision_note = note
        self._emit(req, "rejected", f"by={approver} tier={req.tier} {note}".strip())
        return req

    def _settleable(self, req: ApprovalRequest) -> bool:
        self._apply_timeout(req)
        return req.status == "pending"

    def _apply_timeout(self, req: ApprovalRequest) -> bool:
        """Apply timeout semantics to one request. Returns True if it fired."""
        if req.status != "pending" or req.deadline <= 0:
            return False
        if self._now() < req.deadline:
            return False
        if req.on_timeout == "hold":
            return False  # stays pending forever
        if req.on_timeout == "escalate" and req.tier < req.max_tiers:
            req.tier += 1
            req.deadline = self._now() + self.tier2_ttl_seconds
            req.status = "pending"  # still live, now at a higher tier
            self._emit(req, "escalated",
                       f"to tier {req.tier}; new ttl={self.tier2_ttl_seconds}s")
            return True
        # deny — fail closed (also the tier-2 timeout path for escalate)
        req.status = "timed_out"
        req.decided_at = self._now()
        req.decided_by = "system(timeout)"
        req.decision_note = f"no decision within TTL; on_timeout={req.on_timeout} -> deny"
        self._emit(req, "timed_out", req.decision_note)
        return True

    def sweep(self) -> list[ApprovalRequest]:
        """Apply timeout semantics to every pending request. Returns those that fired."""
        fired = []
        for req in self._requests.values():
            if self._apply_timeout(req):
                fired.append(req)
        return fired

    def pending(self, tier: int | None = None) -> list[ApprovalRequest]:
        self.sweep()
        out = [r for r in self._requests.values() if r.status == "pending"]
        if tier is not None:
            out = [r for r in out if r.tier == tier]
        return sorted(out, key=lambda r: r.created_at)

    def all_requests(self) -> list[ApprovalRequest]:
        return [self._requests[k] for k in sorted(self._requests)]

    def drain_events(self) -> list[dict]:
        evs = self.events
        self.events = []
        return evs
