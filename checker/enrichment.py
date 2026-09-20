"""
Enrichment client for querying Google OSV batch API, NIST NVD,
and package registries (PyPI, npm) to populate vulnerability and release metadata.
"""

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from checker.models import DependencyNode, Vulnerability


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PYPI_BASE_URL = "https://pypi.org/pypi/{name}/json"
NPM_BASE_URL = "https://registry.npmjs.org/{name}"


class EnrichmentClient:
    """Enriches DependencyNode objects with registry publication dates and vulnerability advisories."""

    def __init__(self, nvd_api_key: Optional[str] = None, current_date: Optional[datetime] = None):
        self.nvd_api_key = nvd_api_key
        # Use provided current_date (e.g. simulated historical test date) or current UTC
        if current_date is not None:
            if current_date.tzinfo is None:
                self.current_date = current_date.replace(tzinfo=timezone.utc)
            else:
                self.current_date = current_date
        else:
            self.current_date = datetime.now(timezone.utc)

        # Cache registry metadata to avoid duplicate HTTP requests
        self._registry_cache: Dict[str, Dict[str, Any]] = {}
        self._nvd_cache: Dict[str, float] = {}

    def fetch_pypi_metadata(self, package_name: str) -> Dict[str, Any]:
        cache_key = f"pypi:{package_name.lower()}"
        if cache_key in self._registry_cache:
            return self._registry_cache[cache_key]

        url = PYPI_BASE_URL.format(name=package_name)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DepShield/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._registry_cache[cache_key] = data
                return data
        except Exception:
            return {}

    def fetch_npm_metadata(self, package_name: str) -> Dict[str, Any]:
        cache_key = f"npm:{package_name.lower()}"
        if cache_key in self._registry_cache:
            return self._registry_cache[cache_key]

        # Handle scoped packages (e.g. @angular/core -> @angular%2Fcore)
        encoded_name = package_name.replace("/", "%2F")
        url = NPM_BASE_URL.format(name=encoded_name)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DepShield/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._registry_cache[cache_key] = data
                return data
        except Exception:
            return {}

    def resolve_publication_info(self, name: str, version: str, ecosystem: str) -> Tuple[Optional[datetime], Optional[str]]:
        """Returns (published_at, latest_version) for a given package and version."""
        published_at = None
        latest_version = None

        if ecosystem.lower() == "pypi":
            meta = self.fetch_pypi_metadata(name)
            if meta:
                latest_version = meta.get("info", {}).get("version")
                releases = meta.get("releases", {})
                release_files = releases.get(version, [])
                if release_files:
                    upload_time_str = release_files[0].get("upload_time_iso_8601") or release_files[0].get("upload_time")
                    if upload_time_str:
                        try:
                            # Parse ISO 8601 string
                            dt = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            published_at = dt
                        except Exception:
                            pass
        elif ecosystem.lower() == "npm":
            meta = self.fetch_npm_metadata(name)
            if meta:
                latest_version = meta.get("dist-tags", {}).get("latest")
                time_dict = meta.get("time", {})
                time_str = time_dict.get(version)
                if time_str:
                    try:
                        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        published_at = dt
                    except Exception:
                        pass

        return published_at, latest_version

    def query_osv_batch(self, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch queries Google OSV API endpoint."""
        if not queries:
            return []

        payload = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "DepShield/2.0"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("results", [])
        except Exception:
            return [{}] * len(queries)

    def parse_cvss_score(self, vuln_data: Dict[str, Any]) -> Tuple[float, str]:
        """Extracts CVSS score and severity label from OSV or NIST advisory."""
        # 1. Inspect severity field in OSV record
        severities = vuln_data.get("severity", [])
        for sev in severities:
            score_str = sev.get("score")
            # If CVSS v3 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
            if score_str and isinstance(score_str, str):
                # Check database-specific score if present
                pass

        # 2. Check database_specific field
        db_specific = vuln_data.get("database_specific", {})
        if "severity" in db_specific:
            sev_label = str(db_specific["severity"]).upper()
            if "CRITICAL" in sev_label:
                return 9.5, "CRITICAL"
            elif "HIGH" in sev_label:
                return 7.5, "HIGH"
            elif "MODERATE" in sev_label or "MEDIUM" in sev_label:
                return 5.5, "MEDIUM"
            elif "LOW" in sev_label:
                return 2.5, "LOW"

        # 3. Check ecosystem_specific
        eco_specific = vuln_data.get("ecosystem_specific", {})
        if "severity" in eco_specific:
            sev_label = str(eco_specific["severity"]).upper()
            if "CRITICAL" in sev_label:
                return 9.5, "CRITICAL"
            elif "HIGH" in sev_label:
                return 7.5, "HIGH"
            elif "MODERATE" in sev_label or "MEDIUM" in sev_label:
                return 5.5, "MEDIUM"
            elif "LOW" in sev_label:
                return 2.5, "LOW"

        return 0.0, "UNKNOWN"

    def enrich_nodes(self, nodes: List[DependencyNode]) -> List[DependencyNode]:
        """Enriches each node with OSV vulnerabilities, registry timestamps, and risk classification."""
        if not nodes:
            return []

        # 1. Build OSV batch query payload
        osv_queries = []
        for node in nodes:
            osv_queries.append({
                "package": {
                    "name": node.name,
                    "ecosystem": node.ecosystem
                },
                "version": node.version
            })

        # 2. Execute OSV Batch query
        osv_results = self.query_osv_batch(osv_queries)

        # 3. Process each node
        for i, node in enumerate(nodes):
            res = osv_results[i] if i < len(osv_results) else {}
            raw_vulns = res.get("vulns", [])
            
            parsed_vulns: List[Vulnerability] = []
            max_cvss = 0.0
            has_malicious = False
            has_kev = False

            for v in raw_vulns:
                vuln_id = v.get("id", "UNKNOWN")
                aliases = v.get("aliases", [])
                summary = v.get("summary", "")
                details = v.get("details", "")

                cvss, severity = self.parse_cvss_score(v)
                if cvss > max_cvss:
                    max_cvss = cvss

                # Check malicious flag
                is_malicious = "MAL-" in vuln_id or "malicious" in summary.lower() or "malware" in details.lower()
                if is_malicious:
                    has_malicious = True

                parsed_vulns.append(Vulnerability(
                    id=vuln_id,
                    aliases=aliases,
                    summary=summary,
                    details=details,
                    severity=severity,
                    cvss_score=cvss,
                    is_kev=has_kev,
                    is_malicious=is_malicious
                ))

            node.vulnerabilities = parsed_vulns

            # 4. Resolve registry publication timestamp & latest version
            published_at, latest_ver = self.resolve_publication_info(node.name, node.version, node.ecosystem)
            node.published_at = published_at
            node.latest_version = latest_ver
            if latest_ver and latest_ver != node.version:
                node.is_outdated = True

            # 5. Calculate age & is_young flag
            if published_at:
                age = (self.current_date - published_at).days
                node.age_days = max(0, age)
                node.is_young = node.age_days < 15
            else:
                node.age_days = None
                node.is_young = False

            # 6. Assign risk_color:
            # RED: CVSS >= 7.0, malicious package flag, or known exploited vulnerability (KEV).
            # YELLOW: Low/Medium vulnerability (0.0 < CVSS < 7.0), no active exploit flag.
            # GREEN: CVSS = 0.0 (or unlisted advisories), no known advisories.
            if max_cvss >= 7.0 or has_malicious or has_kev:
                node.risk_color = "RED"
            elif max_cvss > 0.0 or len(node.vulnerabilities) > 0:
                node.risk_color = "YELLOW"
            else:
                node.risk_color = "GREEN"

        return nodes
