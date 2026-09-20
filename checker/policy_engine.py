"""
Deterministic Policy Engine implementing the 4-Tier Decision Matrix.
Order of Precedence: NOT_ADVISABLE -> HIGH_CAUTION -> PROCEED_WITH_CAUTION -> PROCEED.
"""

from typing import List, Dict, Any
from checker.models import DependencyNode, PolicyResult


class PolicyEngine:
    """Evaluates a set of enriched dependency nodes against deterministic safety policies."""

    @staticmethod
    def evaluate(nodes: List[DependencyNode]) -> PolicyResult:
        if not nodes:
            return PolicyResult(
                verdict="PROCEED",
                reasons=["No dependencies declared or discovered."],
                affected_packages={"RED": [], "YELLOW": [], "GREEN": [], "YOUNG": []},
                metrics={
                    "total_count": 0,
                    "red_count": 0,
                    "yellow_count": 0,
                    "green_count": 0,
                    "young_count": 0,
                    "red_pct": 0.0,
                    "yellow_pct": 0.0,
                    "green_pct": 1.0,
                    "combined_risk_pct": 0.0,
                }
            )

        total = len(nodes)
        red_pkgs = [n for n in nodes if n.risk_color == "RED"]
        yellow_pkgs = [n for n in nodes if n.risk_color == "YELLOW"]
        green_pkgs = [n for n in nodes if n.risk_color == "GREEN"]
        young_pkgs = [n for n in nodes if n.is_young]

        red_count = len(red_pkgs)
        yellow_count = len(yellow_pkgs)
        green_count = len(green_pkgs)
        young_count = len(young_pkgs)

        red_pct = red_count / total
        yellow_pct = yellow_count / total
        green_pct = green_count / total
        combined_risk_pct = (red_count + yellow_count) / total

        metrics: Dict[str, Any] = {
            "total_count": total,
            "red_count": red_count,
            "yellow_count": yellow_count,
            "green_count": green_count,
            "young_count": young_count,
            "red_pct": round(red_pct, 4),
            "yellow_pct": round(yellow_pct, 4),
            "green_pct": round(green_pct, 4),
            "combined_risk_pct": round(combined_risk_pct, 4),
        }

        affected_packages = {
            "RED": [f"{n.name}@{n.version}" for n in red_pkgs],
            "YELLOW": [f"{n.name}@{n.version}" for n in yellow_pkgs],
            "GREEN": [f"{n.name}@{n.version}" for n in green_pkgs],
            "YOUNG": [f"{n.name}@{n.version} ({n.age_days}d old)" if n.age_days is not None else f"{n.name}@{n.version}" for n in young_pkgs],
        }

        reasons: List[str] = []

        # ==============================================================================
        # PRIORITY 1 (Highest): NOT_ADVISABLE
        # Trigger Criteria: Red > 30% OR (Red + Yellow) > 50%
        # ==============================================================================
        if red_pct > 0.30 or combined_risk_pct > 0.50:
            if red_pct > 0.30:
                reasons.append(f"High/Critical risk packages exceed threshold: {red_pct * 100:.1f}% RED (limit 30.0%).")
            if combined_risk_pct > 0.50:
                reasons.append(f"Combined risk (RED + YELLOW) exceeds safety threshold: {combined_risk_pct * 100:.1f}% (limit 50.0%).")
            reasons.append(f"Affected high-risk packages ({len(red_pkgs)}): {', '.join(affected_packages['RED']) or 'None'}.")
            if yellow_pkgs:
                reasons.append(f"Affected moderate-risk packages ({len(yellow_pkgs)}): {', '.join(affected_packages['YELLOW'])}.")
            return PolicyResult(
                verdict="NOT_ADVISABLE",
                reasons=reasons,
                affected_packages=affected_packages,
                metrics=metrics
            )

        # ==============================================================================
        # PRIORITY 2: HIGH_CAUTION
        # Trigger Criteria: At least 1 dependency has is_young == True (< 15 days)
        # ==============================================================================
        if young_count > 0:
            reasons.append(f"Detected {young_count} recently published package(s) (< 15 days old). Possible supply chain tamper risk.")
            reasons.append(f"Young packages: {', '.join(affected_packages['YOUNG'])}.")
            if red_pkgs:
                reasons.append(f"High risk packages present: {', '.join(affected_packages['RED'])}.")
            if yellow_pkgs:
                reasons.append(f"Moderate risk packages present: {', '.join(affected_packages['YELLOW'])}.")
            return PolicyResult(
                verdict="HIGH_CAUTION",
                reasons=reasons,
                affected_packages=affected_packages,
                metrics=metrics
            )

        # ==============================================================================
        # PRIORITY 3: PROCEED_WITH_CAUTION
        # Trigger Criteria: Red == 0 and Yellow > 0 (and combined <= 50%)
        # ==============================================================================
        if red_count == 0 and yellow_count > 0:
            reasons.append(f"Moderate risk vulnerabilities detected in {yellow_count} package(s) ({yellow_pct * 100:.1f}% of dependencies).")
            reasons.append(f"Affected moderate-risk packages: {', '.join(affected_packages['YELLOW'])}.")
            reasons.append("No critical or high severity vulnerabilities (0.0% RED).")
            return PolicyResult(
                verdict="PROCEED_WITH_CAUTION",
                reasons=reasons,
                affected_packages=affected_packages,
                metrics=metrics
            )

        # ==============================================================================
        # PRIORITY 4 (Lowest): PROCEED
        # Trigger Criteria: Green == 100% and all packages >= 15 days old
        # ==============================================================================
        reasons.append(f"All {total} dependencies verified 100% GREEN.")
        reasons.append("Zero known advisories and all packages verified >= 15 days old.")
        return PolicyResult(
            verdict="PROCEED",
            reasons=reasons,
            affected_packages=affected_packages,
            metrics=metrics
        )
