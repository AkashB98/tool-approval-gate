"""Hash-chained JSONL audit log.

Every gate decision and every approval event is appended as one JSON line.
Each record carries the sha256 of the previous record's hash, so deleting
or editing a line breaks the chain — `verify()` recomputes it. This is
tamper-EVIDENCE, not tamper-PROOF (a writer holding the file can always
rewrite history); the README says so honestly.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Callable


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _hash(prev_hash: str, record: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(record)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str, clock: Callable[[], float] | None = None):
        self.path = path
        self._clock = clock or time.time
        self._seq = 0
        self._prev_hash = "0" * 64
        if os.path.exists(path):
            self._replay()

    def _replay(self) -> None:
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                self._seq = max(self._seq, rec["seq"])
                self._prev_hash = rec["hash"]

    def append(self, event: str, **fields) -> dict:
        self._seq += 1
        record = {"seq": self._seq, "ts": self._clock(), "event": event}
        record.update(fields)
        record["hash"] = _hash(self._prev_hash, record)
        self._prev_hash = record["hash"]
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(_canonical(record) + "\n")
        return record

    def read_all(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, message)."""
        prev = "0" * 64
        expected_seq = 0
        for rec in self.read_all():
            expected_seq += 1
            if rec["seq"] != expected_seq:
                return False, f"seq break at record {rec.get('seq')}"
            h = rec.pop("hash")
            if _hash(prev, rec) != h:
                return False, f"hash mismatch at seq {expected_seq}"
            rec["hash"] = h
            prev = h
        return True, f"chain valid: {expected_seq} records"
