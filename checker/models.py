"""
Core Data Entities and Standard Interfaces for DepShield Graph Risk Engine.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class Vulnerability:
    """Represents an advisory, CVE, or GHSA security finding."""
    id: str
    aliases: List[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float = 0.0
    is_kev: bool = False          # Known Exploited Vulnerability flag
    is_malicious: bool = False    # Malicious package / malware advisory flag

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "aliases": self.aliases,
            "summary": self.summary,
            "details": self.details,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "is_kev": self.is_kev,
            "is_malicious": self.is_malicious,
        }


@dataclass
class DependencyNode:
    """Standard Node Interface for packages in the dependency graph."""
    name: str
    version: str
    ecosystem: str = "PyPI"                      # "PyPI" or "npm"
    published_at: Optional[datetime] = None      # Release timestamp from registry
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_color: str = "GREEN"                    # "GREEN" | "YELLOW" | "RED"
    is_young: bool = False                       # True if age < 15 days, else False
    age_days: Optional[int] = None
    latest_version: Optional[str] = None
    is_outdated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "risk_color": self.risk_color,
            "is_young": self.is_young,
            "age_days": self.age_days,
            "latest_version": self.latest_version,
            "is_outdated": self.is_outdated,
        }


@dataclass
class PolicyResult:
    """Evaluation verdict and metrics produced by the Deterministic Policy Engine."""
    verdict: str                  # "NOT_ADVISABLE" | "HIGH_CAUTION" | "PROCEED_WITH_CAUTION" | "PROCEED"
    reasons: List[str] = field(default_factory=list)
    affected_packages: Dict[str, List[str]] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reasons": self.reasons,
            "affected_packages": self.affected_packages,
            "metrics": self.metrics,
        }
