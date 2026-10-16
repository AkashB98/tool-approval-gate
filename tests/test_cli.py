"""Unit tests: CLI exit codes and simulate output."""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from approval_gate import cli as cli_mod

FIX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


class TestCLI(unittest.TestCase):
    def test_check_clean_policy_exit_0(self):
        self.assertEqual(cli_mod.main(["check", os.path.join(FIX, "policy.json")]), 0)

    def test_check_bad_policy_exit_2(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(["check", os.path.join(FIX, "lint_bad_policy.json")])
        self.assertEqual(code, 2)
        self.assertIn("LINT-001", buf.getvalue())

    def test_simulate_verdicts(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(["simulate", os.path.join(FIX, "policy.json"),
                                 os.path.join(FIX, "calls.jsonl")])
        self.assertEqual(code, 0)
        lines = buf.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 7)
        verdicts = [l.split()[0] for l in lines]
        self.assertEqual(verdicts, ["allowed", "pending_approval", "allowed", "denied",
                                    "pending_approval", "pending_approval",
                                    "pending_approval"])

    def test_demo_runs(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(["demo"])
        self.assertEqual(code, 0)
        self.assertIn("demo complete", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
