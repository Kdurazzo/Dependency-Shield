"""
Unit Test Suite for Deterministic Policy Engine Acceptance Matrix.
"""

import unittest
from checker.models import DependencyNode, Vulnerability
from checker.policy_engine import PolicyEngine


class TestPolicyEngine(unittest.TestCase):

    def _make_node(self, name: str, risk_color: str, is_young: bool = False, age_days: int = 30) -> DependencyNode:
        return DependencyNode(
            name=name,
            version="1.0.0",
            ecosystem="PyPI",
            risk_color=risk_color,
            is_young=is_young,
            age_days=age_days
        )

    def test_all_green_proceed(self):
        """Scenario 1: 100% Green, >= 15 days -> PROCEED"""
        nodes = [self._make_node(f"pkg_{i}", "GREEN", is_young=False, age_days=30) for i in range(10)]
        result = PolicyEngine.evaluate(nodes)
        self.assertEqual(result.verdict, "PROCEED")
        self.assertEqual(result.metrics["green_pct"], 1.0)
        self.assertEqual(result.metrics["young_count"], 0)

    def test_yellow_proceed_with_caution(self):
        """Scenario 2: 10% Yellow, 0% Red, >= 15 days -> PROCEED_WITH_CAUTION"""
        # 1 Yellow out of 10 packages = 10% Yellow
        nodes = [self._make_node("vuln_pkg", "YELLOW", is_young=False, age_days=45)]
        nodes += [self._make_node(f"clean_{i}", "GREEN", is_young=False, age_days=60) for i in range(9)]
        result = PolicyEngine.evaluate(nodes)
        self.assertEqual(result.verdict, "PROCEED_WITH_CAUTION")
        self.assertEqual(result.metrics["yellow_pct"], 0.1)
        self.assertEqual(result.metrics["red_pct"], 0.0)

    def test_young_package_high_caution(self):
        """Scenario 3: 0% Yellow, 0% Red, but 1 package 5 days old -> HIGH_CAUTION"""
        nodes = [self._make_node("young_pkg", "GREEN", is_young=True, age_days=5)]
        nodes += [self._make_node(f"old_{i}", "GREEN", is_young=False, age_days=100) for i in range(9)]
        result = PolicyEngine.evaluate(nodes)
        self.assertEqual(result.verdict, "HIGH_CAUTION")
        self.assertEqual(result.metrics["young_count"], 1)

    def test_red_threshold_not_advisable(self):
        """Scenario 4: 35% Red -> NOT_ADVISABLE (even if young package exists)"""
        # 7 Red out of 20 = 35% Red, plus 1 young package
        nodes = [self._make_node(f"red_{i}", "RED", is_young=False, age_days=40) for i in range(7)]
        nodes += [self._make_node("young_pkg", "GREEN", is_young=True, age_days=3)]
        nodes += [self._make_node(f"clean_{i}", "GREEN", is_young=False, age_days=50) for i in range(12)]
        result = PolicyEngine.evaluate(nodes)
        # Priority 1 (NOT_ADVISABLE) must short-circuit over Priority 2 (HIGH_CAUTION)
        self.assertEqual(result.verdict, "NOT_ADVISABLE")
        self.assertGreater(result.metrics["red_pct"], 0.30)

    def test_combined_risk_not_advisable(self):
        """Scenario 5: 20% Red + 35% Yellow (55% total) -> NOT_ADVISABLE"""
        # 4 Red (20%) + 7 Yellow (35%) out of 20 = 55% combined risk
        nodes = [self._make_node(f"red_{i}", "RED", is_young=False, age_days=30) for i in range(4)]
        nodes += [self._make_node(f"yellow_{i}", "YELLOW", is_young=False, age_days=30) for i in range(7)]
        nodes += [self._make_node(f"green_{i}", "GREEN", is_young=False, age_days=30) for i in range(9)]
        result = PolicyEngine.evaluate(nodes)
        self.assertEqual(result.verdict, "NOT_ADVISABLE")
        self.assertEqual(result.metrics["combined_risk_pct"], 0.55)


if __name__ == "__main__":
    unittest.main()
