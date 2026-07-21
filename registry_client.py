import json
import urllib.request
import urllib.error
from datetime import datetime

# ==============================================================================
# MODULE: REGISTRY CLIENT
# ==============================================================================
# Implements registry network connections using standard libraries.
# Contains no external dependencies to prevent secondary supply chain threats.

class RegistryClient:
    """Client for querying package registries (PyPI, npm) and security databases (OSV)."""

    def __init__(self, nvd_api_key=None):
        import os
        self.nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY")

    # ==========================================================================
    # INTERNAL NETWORK HELPER
    # ==========================================================================
    @staticmethod
    def _get_json(url, data=None, headers=None, method='GET'):
        """
        Helper to make HTTP requests and parse JSON responses.
        Handles GET requests and POST requests (with json request bodies).
        """
        if headers is None:
            headers = {}
        
        req_data = None
        # If data is provided, it indicates a POST/PUT request.
        # We serialize the dictionary payload to UTF-8 encoded JSON bytes.
        if data is not None:
            req_data = json.dumps(data).encode('utf-8')
            headers['Content-Type'] = 'application/json'

        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        try:
            # Set a standard timeout of 10 seconds to avoid blocking indefinitely.
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            # If the database returns 404 (package not found), handle it gracefully
            if e.code == 404:
                return None
            raise
        except Exception:
            # Catch network dropouts or timeouts
            return None

    # ==========================================================================
    # PYPI REGISTRY QUERY (PYTHON)
    # ==========================================================================
    def get_pypi_package(self, name, version=None):
        """
        Fetch package metadata from PyPI registry.
        
        If version is specified, queries version-specific endpoint:
          - URL: https://pypi.org/pypi/{name}/{version}/json
          - Key file list is located in the top-level 'urls' array.
        Otherwise, queries latest package endpoint:
          - URL: https://pypi.org/pypi/{name}/json
          - Key file list is inside the 'releases' dictionary keyed by version.
        """
        if version:
            url = f"https://pypi.org/pypi/{name}/{version}/json"
        else:
            url = f"https://pypi.org/pypi/{name}/json"
        
        data = self._get_json(url)
        if not data:
            return None

        # Extract general package metadata
        info = data.get("info", {})
        latest_version = info.get("version")
        target_version = version or latest_version

        # Retrieve the release files list
        # PyPI version-specific endpoint puts file uploads in 'urls'
        version_releases = data.get("urls", [])
        # General package endpoint puts them in 'releases' under the version key
        if not version_releases:
            releases = data.get("releases", {})
            version_releases = releases.get(target_version, [])

        # Get release date (using the first file upload's timestamp) and integrity hashes
        release_date = None
        hashes = []
        for rel in version_releases:
            if not release_date:
                upload_time = rel.get("upload_time_iso_8601")
                if upload_time:
                    try:
                        # Parse ISO 8601 string (excluding microseconds and 'Z')
                        release_date = datetime.strptime(upload_time.split('.')[0].rstrip('Z'), "%Y-%m-%dT%H:%M:%S")
                    except ValueError:
                        pass
            
            # Extract MD5 and SHA-256 digests provided by PyPI.
            digests = rel.get("digests", {})
            if digests:
                hashes.append({
                    "filename": rel.get("filename"),
                    "sha256": digests.get("sha256"),
                    "md5": digests.get("md5"),
                    "url": rel.get("url")
                })

        return {
            "name": name,
            "version": target_version,
            "latest_version": latest_version,
            "release_date": release_date,
            "hashes": hashes,
            "ecosystem": "PyPI",
            "requires_dist": info.get("requires_dist") or []
        }

    # ==========================================================================
    # NPM REGISTRY QUERY (NODE.JS)
    # ==========================================================================
    def get_npm_package(self, name, version=None):
        """
        Fetch package metadata from npm registry.
        
        URL: https://registry.npmjs.org/{name}
        Returns a JSON document containing a 'time' dict with all release dates,
        and a 'versions' dict containing dependencies, hashes, and download urls.
        """
        # Scoped package names (like '@babel/core') contain a forward slash.
        # This slash must be URL-encoded as '%2F' for the registry lookup.
        encoded_name = name.replace("/", "%2F")
        url = f"https://registry.npmjs.org/{encoded_name}"
        
        data = self._get_json(url)
        if not data:
            return None

        time_data = data.get("time", {})
        versions_data = data.get("versions", {})

        # Resolve package version. If unpinned, fetch latest version from dist-tags.
        target_version = version
        if not target_version:
            target_version = data.get("dist-tags", {}).get("latest")

        if not target_version or target_version not in versions_data:
            if versions_data:
                target_version = list(versions_data.keys())[-1]
            else:
                return None

        # Extract tarball and checksum info.
        version_info = versions_data.get(target_version, {})
        dist = version_info.get("dist", {})

        # Parse release timestamp.
        release_date = None
        upload_time = time_data.get(target_version)
        if upload_time:
            try:
                release_date = datetime.strptime(upload_time.split('.')[0].rstrip('Z'), "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass

        # npm provides SHA-1 (shasum) and integrity (base64 SHA-512) digests.
        hashes = []
        shasum = dist.get("shasum")
        integrity = dist.get("integrity")
        tarball = dist.get("tarball")
        
        hashes.append({
            "filename": f"{name.split('/')[-1]}-{target_version}.tgz",
            "sha1": shasum,
            "integrity": integrity,
            "url": tarball
        })

        return {
            "name": name,
            "version": target_version,
            "latest_version": data.get("dist-tags", {}).get("latest"),
            "release_date": release_date,
            "hashes": hashes,
            "ecosystem": "npm",
            "dependencies": version_info.get("dependencies") or {}
        }

    # ==========================================================================
    # GOOGLE OSV VULNERABILITY DATABASE QUERY
    # ==========================================================================
    def query_osv_vulnerabilities(self, name, version, ecosystem):
        """
        Query Google's OSV database for known package vulnerabilities.
        
        API endpoint: https://api.osv.dev/v1/query
        Method: POST (JSON payload containing package, ecosystem, and version)
        """
        url = "https://api.osv.dev/v1/query"
        payload = {
            "package": {
                "name": name,
                "ecosystem": ecosystem
            },
            "version": version
        }
        
        result = self._get_json(url, data=payload, method='POST')
        if not result or "vulns" not in result:
            return []

        # Parse security advisories list.
        vulns = []
        for vuln in result.get("vulns", []):
            vulns.append({
                "id": vuln.get("id"),
                "summary": vuln.get("summary", "No summary provided"),
                "details": vuln.get("details", ""),
                "aliases": vuln.get("aliases", []),
                "modified": vuln.get("modified")
            })
        return vulns

    # ==========================================================================
    # NIST NVD REST API V2.0 CVE QUERY
    # ==========================================================================
    def get_nvd_cve(self, cve_id):
        """
        Query the official NIST NVD API v2.0 for a specific CVE ID.
        
        Retrieves CVSS base score, severity, and official descriptions.
        """
        import urllib.parse
        import os
        
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        headers = {}
        api_key = self.nvd_api_key
        if api_key:
            headers["apiKey"] = api_key
            
        try:
            result = self._get_json(url, headers=headers)
            if not result or "vulnerabilities" not in result:
                return None
                
            for item in result.get("vulnerabilities", []):
                cve = item.get("cve", {})
                
                # Fetch NVD description text
                descriptions = cve.get("descriptions", [])
                desc_val = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        desc_val = desc.get("value", "")
                        break
                        
                # Extract CVSS severity metric (v3.1 or v3.0)
                cvss_score = "N/A"
                metrics = cve.get("metrics", {})
                cvss_data = None
                for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss_data = metrics[metric_key][0].get("cvssData", {})
                        break
                if cvss_data:
                    cvss_score = f"{cvss_data.get('baseScore')} ({cvss_data.get('baseSeverity')})"
                
                return {
                    "id": cve_id,
                    "description": desc_val,
                    "cvss": cvss_score,
                    "modified": cve.get("lastModified")
                }
        except Exception:
            pass
        return None


