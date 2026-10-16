"""Unit tests: audit log append, readback, chain verification, tamper evidence."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approval_gate.audit import AuditLog


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.path = tempfile.mktemp(suffix=".jsonl")
        self.clock_t = [1_000_000.0]
        self.log = AuditLog(self.path, clock=lambda: self.clock_t[0])

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_append_and_read(self):
        r1 = self.log.append("decision", verdict="allowed")
        r2 = self.log.append("decision", verdict="denied")
        self.assertEqual((r1["seq"], r2["seq"]), (1, 2))
        recs = self.log.read_all()
        self.assertEqual(len(recs), 2)
        self.assertNotEqual(recs[0]["hash"], recs[1]["hash"])

    def test_verify_clean(self):
        for i in range(5):
            self.clock_t[0] += 1
            self.log.append("decision", i=i)
        ok, msg = self.log.verify()
        self.assertTrue(ok, msg)
        self.assertIn("5 records", msg)

    def test_verify_detects_edit(self):
        self.log.append("decision", verdict="allowed")
        self.log.append("decision", verdict="denied")
        # tamper: flip a verdict in the file
        with open(self.path, encoding="utf-8") as f:
            lines = f.readlines()
        rec = json.loads(lines[1])
        rec["verdict"] = "allowed"
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self.path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        ok, msg = AuditLog(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("hash mismatch", msg)

    def test_verify_detects_deletion(self):
        for _ in range(3):
            self.log.append("decision")
        with open(self.path, encoding="utf-8") as f:
            lines = f.readlines()
        with open(self.path, "w", encoding="utf-8") as f:
            f.writelines([lines[0], lines[2]])  # drop seq 2
        ok, msg = AuditLog(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("seq break", msg)

    def test_replay_continues_chain(self):
        self.log.append("decision", verdict="allowed")
        log2 = AuditLog(self.path, clock=lambda: self.clock_t[0])
        r = log2.append("decision", verdict="denied")
        self.assertEqual(r["seq"], 2)
        ok, _ = log2.verify()
        self.assertTrue(ok)

    def test_empty_log_verifies(self):
        ok, msg = self.log.verify()
        self.assertTrue(ok)
        self.assertIn("0 records", msg)


if __name__ == "__main__":
    unittest.main()
