"""
Unit Test Suite for Execution Gate Adapter (Agent vs Human semantics).
"""

import unittest
import json
import io
import sys
from checker.models import DependencyNode, PolicyResult
from checker.runner import ExecutionGateRunner


class TestExecutionGateRunner(unittest.TestCase):

    def setUp(self):
        self.dummy_nodes = [
            DependencyNode(name="pkg_a", version="1.0.0", risk_color="GREEN", is_young=False)
        ]

    def test_agent_mode_proceed(self):
        """Test agent mode with PROCEED verdict."""
        runner = ExecutionGateRunner(agent_mode=True, dry_run=True)
        policy_result = PolicyResult(
            verdict="PROCEED",
            reasons=["All green."],
            metrics={"total_count": 1, "green_pct": 1.0, "red_pct": 0.0, "yellow_pct": 0.0, "young_count": 0}
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            exit_code = runner.run(self.dummy_nodes, policy_result, "test_requirements.txt")
            output_str = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(exit_code, 0)
        data = json.loads(output_str)
        self.assertEqual(data["status"], "INSTALLED")
        self.assertEqual(data["mode"], "HUMAN_ON_THE_LOOP")
        self.assertEqual(data["verdict"], "PROCEED")
        self.assertIn("credentials_setup", data)

    def test_agent_mode_high_caution(self):
        """Test agent mode with HIGH_CAUTION verdict."""
        runner = ExecutionGateRunner(agent_mode=True, dry_run=True)
        policy_result = PolicyResult(
            verdict="HIGH_CAUTION",
            reasons=["1 young package."],
            affected_packages={"YOUNG": ["young_pkg@1.0.0 (3d old)"]},
            metrics={"total_count": 1, "young_count": 1}
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            exit_code = runner.run(self.dummy_nodes, policy_result, "test_requirements.txt")
            output_str = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(exit_code, 2)
        data = json.loads(output_str)
        self.assertEqual(data["status"], "REQUIRES_APPROVAL")
        self.assertEqual(data["mode"], "HUMAN_IN_THE_LOOP")
        self.assertEqual(data["choice"], ["APPROVE", "DECLINE"])
        self.assertEqual(data["verdict"], "HIGH_CAUTION")

    def test_agent_mode_not_advisable(self):
        """Test agent mode with NOT_ADVISABLE verdict."""
        runner = ExecutionGateRunner(agent_mode=True, dry_run=True)
        policy_result = PolicyResult(
            verdict="NOT_ADVISABLE",
            reasons=["35% RED."],
            affected_packages={"RED": ["bad_pkg@1.0.0"]},
            metrics={"total_count": 1, "red_pct": 0.35}
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            exit_code = runner.run(self.dummy_nodes, policy_result, "test_requirements.txt")
            output_str = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(exit_code, 3)
        data = json.loads(output_str)
        self.assertEqual(data["status"], "REQUIRES_APPROVAL")
        self.assertEqual(data["mode"], "HUMAN_IN_THE_LOOP")
        self.assertEqual(data["verdict"], "NOT_ADVISABLE")


if __name__ == "__main__":
    unittest.main()
