"""Tiny stdlib JSON API for the approval gate.

    POST /submit   {tool, args, actor?, idempotency_key?} -> GateDecision
    POST /approve  {request_id, approver, note?}          -> GateDecision
    POST /reject   {request_id, approver, note?}          -> GateDecision
    GET  /pending[?tier=N]                                -> [ApprovalRequest]
    GET  /request/<id>                                    -> ApprovalRequest
    GET  /audit                                          -> [audit records]
    GET  /audit/verify                                   -> {ok, message}
    GET  /health                                         -> {ok: true}

State lives in memory (plus the audit JSONL file); this is a demo/ops
surface, not a production deployment — the README says so.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from .gate import Gate
from .policy import ToolCall


class _Handler(BaseHTTPRequestHandler):
    gate: Gate = None  # set by serve()

    def log_message(self, *a):
        pass

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def do_GET(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/health":
                return self._send(200, {"ok": True})
            if parsed.path == "/pending":
                tier = parse_qs(parsed.query).get("tier", [None])[0]
                tier = int(tier) if tier is not None else None
                reqs = self.gate.store.pending(tier=tier)
                return self._send(200, [r.to_dict() for r in reqs])
            if parsed.path.startswith("/request/"):
                rid = parsed.path[len("/request/"):]
                return self._send(200, self.gate.store.get(rid).to_dict())
            if parsed.path == "/audit/verify":
                ok, msg = self.gate.audit.verify()
                return self._send(200, {"ok": ok, "message": msg})
            if parsed.path == "/audit":
                return self._send(200, self.gate.audit.read_all())
            return self._send(404, {"error": "not found"})
        except KeyError as e:
            return self._send(404, {"error": str(e)})
        except Exception as e:  # noqa: BLE001 - demo surface
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        try:
            body = self._read_json()
            if self.path == "/submit":
                call = ToolCall(tool=body["tool"], args=body.get("args", {}),
                                actor=body.get("actor", "agent"),
                                idempotency_key=body.get("idempotency_key"))
                d = self.gate.submit(call)
                return self._send(200, d.__dict__)
            if self.path == "/approve":
                d = self.gate.approve(body["request_id"], body.get("approver", "?"),
                                      body.get("note", ""))
                return self._send(200, d.__dict__)
            if self.path == "/reject":
                d = self.gate.reject(body["request_id"], body.get("approver", "?"),
                                     body.get("note", ""))
                return self._send(200, d.__dict__)
            return self._send(404, {"error": "not found"})
        except (KeyError, ValueError) as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001 - demo surface
            return self._send(500, {"error": str(e)})


def serve(gate: Gate, port: int = 8471) -> None:
    _Handler.gate = gate
    httpd = HTTPServer(("127.0.0.1", port), _Handler)
    print(f"tool-approval-gate serving on http://127.0.0.1:{port}")
    httpd.serve_forever()
