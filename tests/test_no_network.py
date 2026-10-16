"""No-network guard: the entire policy/approval/audit core must work with
sockets ripped out. (The demo's live localhost round-trip is opt-in and
lives in demo.py, not in the test suite.)"""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _NoSockets:
    def __init__(self, *a, **k):
        raise AssertionError("network access forbidden in hermetic tests")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestNoNetwork(unittest.TestCase):
    def test_core_flows_without_sockets(self):
        real_socket = socket.socket
        socket.socket = _NoSockets
        try:
            from approval_gate import demo
            demo.run()  # full end-to-end incl. audit verify, no network
        finally:
            socket.socket = real_socket


if __name__ == "__main__":
    unittest.main()
