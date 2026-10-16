# tool-approval-gate

A **human-in-the-loop policy engine** for agent tool calls — the trust layer
that sits between an agent's planner and its executor.

Every tool call an agent proposes is matched against an ordered policy:

- **allow** — execute immediately (read-only lookups, small refunds under a threshold)
- **require_approval** — park the call in an approval queue with a TTL; a human approves or rejects
- **deny** — never execute (prod deletes, exfiltration-shaped calls)

On approval timeout, the policy decides — not the agent: **deny** (fail closed),
**escalate** to a second approver tier with a fresh TTL, or **hold**. Every
decision lands in a **hash-chained audit log**, so a tampered history is
detectable (`audit --verify`).

## Why this exists (the hiring signal)

Every team shipping agents to customers — labs, fintechs, support orgs — hits
the same wall: the agent works, but nobody will let it touch production data
without a human in the loop. The red-teaming harness grades safety *under
attack*; the prompt-injection firewall *blocks attacks at runtime*; this gate
is the third leg: **even a perfectly-behaved agent can't move money, delete
rows, or ship inventory without a human saying so.** Policies are data, not
code — ops can tighten the rules without redeploying the agent.

Pairs with the sibling builds: lint the schemas first (`tool-schema-linter`),
pin behavior in CI (`tool-call-trace-replay`), validate outputs
(`structured-output-validator`), and gate the dangerous calls here.

## Quickstart

```bash
python3 approval_gate/cli.py demo        # end-to-end scenario, asserts inline
python3 approval_gate/cli.py check fixtures/policy.json
python3 approval_gate/cli.py simulate fixtures/policy.json fixtures/calls.jsonl
python3 approval_gate/cli.py serve --port 8471   # JSON API on 127.0.0.1
```

Approve from another terminal while the server runs:

```bash
python3 approval_gate/cli.py pending
python3 approval_gate/cli.py approve apr-0001 priya --note "customer confirmed"
python3 approval_gate/cli.py audit --verify
```

## Policy format

JSON. Rules are evaluated **first match wins**; nothing matching falls through
to `default_action` (fail-closed default: `require_approval`).

```json
{
  "name": "helios-home support agent policy",
  "default_action": "require_approval",
  "default_on_timeout": "deny",
  "tier2_ttl_seconds": 600,
  "rules": [
    {"name": "read-only tools", "tool": "helios.*", "action": "allow"},
    {"name": "large refunds need approval",
     "tool": "billing.refund", "args": {"amount": {"gt": 500}},
     "action": "require_approval", "ttl_seconds": 300, "on_timeout": "deny"},
    {"name": "high-value shipments escalate",
     "tool": "warehouse.ship_high_value", "args": {"qty": {"gte": 10}},
     "action": "require_approval", "ttl_seconds": 120,
     "on_timeout": "escalate", "tiers": 2}
  ]
}
```

- `tool` is a glob over the tool name (`db.*`, `*`).
- `args` maps **dot-paths** (`customer.id`, `items.0.sku`) to matcher specs; all
  must pass. Matchers: `eq ne regex glob gt gte lt lte in nin exists contains`.
- A matcher on a **missing** path never fires — except `{"exists": false}`.
  A rule about an argument that isn't there is a rule that shouldn't fire.
- `on_timeout`: `deny` (fail closed) · `escalate` (tier 2, fresh TTL; a tier-2
  timeout still fails closed — escalation is not a loophole) · `hold`.

`check` lints the policy statically: duplicate names, unknown actions,
`ttl_seconds <= 0`, `escalate` with `tiers: 1`, and **shadowed rules** —
a later rule provably unreachable because an earlier rule covers every call
it could match (error when the actions differ, warning when they're the same).
The subsumption check is deliberately conservative: it flags only what it can
prove, never what it merely suspects.

## API

| Method | Route | Purpose |
|---|---|---|
| POST | `/submit` | `{tool, args, actor?, idempotency_key?}` → verdict |
| POST | `/approve` · `/reject` | `{request_id, approver, note?}` → verdict |
| GET | `/pending[?tier=N]` | live approval requests (timeouts swept first) |
| GET | `/request/<id>` | one request, incl. history |
| GET | `/audit` · `/audit/verify` | records · hash-chain check |

`submit` with a repeated `idempotency_key` returns the cached decision and
audits the replay — no duplicate approval requests, no double side effects
downstream.

## Architecture

```
approval_gate/
  policy.py      ToolCall / Rule / Policy, matcher engine, evaluate(), lint_policy()
  approvals.py   ApprovalStore: requests, approve/reject, timeout sweep,
                 escalation, sequential IDs; injected clock (no sleeping in tests)
  audit.py       AuditLog: JSONL + sha256 hash chain, verify()
  gate.py        Gate: the single choke point — submit()/check()/approve()/reject(),
                 idempotency cache, chronological audit writes
  server.py      stdlib http.server JSON API (127.0.0.1 only; demo/ops surface)
  cli.py         demo | check | simulate | serve | pending | approve | reject | audit
  demo.py        scripted Helios Home scenario, fixed clock, asserts inline
```

Timeouts are applied **lazily** — every `submit`/`check`/listing sweeps first,
so there is no background thread and no clock skew between writers.

The audit chain is tamper-**evident**, not tamper-proof: anyone holding the
file can rewrite it, but they can't do it *undetectably* — `verify()`
recomputes every link. Honest scope for a demo-grade control.

## Tests & evals

```bash
python3 -m unittest discover -s tests          # 65 hermetic tests, stdlib only
python3 evals/run_evals.py                     # 11 golden evals
```

The golden evals pin exact behavior — verdicts, request IDs, approval tiers,
the lint fixture's finding codes, and the audit chain's md5. `eval_report.json`
is committed and byte-identical across runs (md5 `43421c2aa178c8026ca8ad7e30072291`).

## Dev-loop story

The tests caught real bugs during the build:

1. **The default-action crash.** When *no rule matched* and the default
   `require_approval` fired, `store.request()` dereferenced `rule.name` on
   `None` → `AttributeError`. The fix threads the default through properly:
   default-triggered requests are labeled `(default)` in the audit trail and
   inherit `default_on_timeout`. Fail-closed means the *default path* has to
   work, not just the rules.
2. **Audit chronology inversion.** The `decision` entry was written *before*
   the `approval_requested` entry it referenced. Fixed by draining store
   events before appending the decision — pinned by a test asserting
   `approval_requested` precedes `decision` in the log.
3. **A vacuous demo assert.** Step 7's escalation check read
   `assert ... or True` — always passing, testing nothing. Rewritten as a
   real assertion on the tier-2 note. Asserts that can't fail are comments
   with extra steps.

## Honest limits

- In-memory request store (audit log persists; pending requests don't survive
  a restart — by design for the demo surface; a production port would back
  the store with SQLite).
- Single-node, no auth on the API — it's an ops/demo surface on localhost.
- The linter's shadow analysis is sound but incomplete (exact/`*` tool
  patterns only); it never claims a rule is safe, only flags provable
  shadowing.

All fixtures are fictional (Helios Home/Cloud). Stdlib only. No network.
