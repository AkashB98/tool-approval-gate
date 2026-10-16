"""tool-approval-gate: human-in-the-loop policy engine for agent tool calls.

Every tool call an agent proposes is matched against an ordered policy:
allow / require_approval / deny. Approval requests carry a TTL; on timeout
the policy decides: deny (fail closed), escalate to a second approver tier,
or hold. Every decision lands in a hash-chained audit log.
"""

from .policy import ToolCall, Rule, Policy, load_policy, load_policy_file, evaluate, lint_policy
from .approvals import ApprovalStore, ApprovalRequest
from .audit import AuditLog
from .gate import Gate, GateDecision

__all__ = [
    "ToolCall", "Rule", "Policy", "load_policy", "load_policy_file",
    "evaluate", "lint_policy",
    "ApprovalStore", "ApprovalRequest", "AuditLog", "Gate", "GateDecision",
]
