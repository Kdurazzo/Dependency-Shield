import os
import hashlib
import importlib.metadata
import json
from datetime import datetime, timezone
from registry_client import RegistryClient

# ==============================================================================
# MODULE: DEPENDENCY CHECKER ENGINE
# ==============================================================================
# Contains the core validation logic: checking what packages are installed locally,
# analyzing publication dates, and verifying archive hashes.

class DependencyChecker:
    """Core logic for auditing dependencies against registries, local installs, and vulnerabilities."""

    def __init__(self, current_date=None, nvd_api_key=None):
        self.client = RegistryClient(nvd_api_key=nvd_api_key)
        
        # Simulated run date config (useful for historical testing and validation).
        # Translates 'YYYY-MM-DD' strings to naive datetime objects.
        if current_date:
            if isinstance(current_date, str):
                self.current_date = datetime.strptime(current_date.split('T')[0], "%Y-%m-%d")
            else:
                self.current_date = current_date
        else:
            self.current_date = datetime.now()

    # ==========================================================================
    # LOCAL INSTALL ENVIRONMENT INSPECTIONS
    # ==========================================================================
    def get_installed_pypi_version(self, package_name):
        """
        Queries the active Python environment to find the installed version.
        
        Normalizes names (lowercase, hyphens vs underscores) to align matching.
        """
        normalized_name = package_name.lower().replace('_', '-')
        
        try:
            # Loop through all packages currently installed in the Python environment
            for dist in importlib.metadata.distributions():
                dist_name = dist.metadata['Name']
                # Perform normalized comparison
                if dist_name and dist_name.lower().replace('_', '-') == normalized_name:
                    return dist.version
        except Exception:
            pass
        return None

    def get_installed_npm_version(self, package_name, base_dir):
        """
        Inspects node_modules in the project folder to identify installed version.
        
        Avoids shell execution to remain fast, secure, and cross-platform.
        """
        # Form path to local node_modules
        node_modules_path = os.path.join(base_dir, "node_modules")
        if not os.path.exists(node_modules_path):
            return None
        
        # Read the installed dependency's package.json
        pkg_json_path = os.path.join(node_modules_path, package_name, "package.json")
        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get("version")
            except Exception:
                pass
        return None

    # ==========================================================================
    # CHECKSUM CALCULATION & INTEGRITY VERIFICATION
    # ==========================================================================
    @staticmethod
    def calculate_file_hashes(file_path):
        """
        Calculates MD5, SHA1, and SHA256 hashes of a local file.
        
        Reads files in 64KB blocks to keep memory footprint low when processing
        large archives.
        """
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                # Read 64KB blocks iteratively
                for byte_block in iter(lambda: f.read(65536), b""):
                    md5_hash.update(byte_block)
                    sha1_hash.update(byte_block)
                    sha256_hash.update(byte_block)
            return {
                "md5": md5_hash.hexdigest(),
                "sha1": sha1_hash.hexdigest(),
                "sha256": sha256_hash.hexdigest()
            }
        except Exception as e:
            raise IOError(f"Failed to read file {file_path} for hash calculation: {e}")

    def verify_local_file(self, file_path, package_name, version, ecosystem):
        """
        Verifies local archive integrity by comparing computed hashes with those
        published on the registry.
        """
        if not os.path.exists(file_path):
            return {
                "verified": False,
                "reason": f"File does not exist: {file_path}",
                "computed_hashes": None,
                "expected_hashes": None
            }

        # Calculate hashes for the local file
        computed = self.calculate_file_hashes(file_path)
        
        # Query official registry to get expected hashes
        if ecosystem == "PyPI":
            registry_info = self.client.get_pypi_package(package_name, version)
        else:
            registry_info = self.client.get_npm_package(package_name, version)

        if not registry_info or not registry_info.get("hashes"):
            return {
                "verified": False,
                "reason": f"Could not retrieve registry hash metadata for {package_name}@{version}",
                "computed_hashes": computed,
                "expected_hashes": None
            }

        expected_hashes = registry_info["hashes"]
        match_found = False
        
        # Cross-reference calculated hashes with registry files list
        for expected in expected_hashes:
            # PyPI comparison: matches sha256 or md5 digests
            if ecosystem == "PyPI":
                reg_sha256 = expected.get("sha256")
                reg_md5 = expected.get("md5")
                
                if reg_sha256 and reg_sha256 == computed["sha256"]:
                    match_found = True
                    break
                elif reg_md5 and reg_md5 == computed["md5"]:
                    match_found = True
                    break
                    
            # npm comparison: matches sha1 (shasum) or base64 integrity hash (sha512)
            elif ecosystem == "npm":
                reg_sha1 = expected.get("sha1")
                reg_integrity = expected.get("integrity")
                
                if reg_sha1 and reg_sha1 == computed["sha1"]:
                    match_found = True
                    break
                elif reg_integrity:
                    # Calculate SHA-512 for the local file (npm packages usually specify SHA-512 integrity)
                    sha512_hash = hashlib.sha512()
                    try:
                        with open(file_path, "rb") as f:
                            for byte_block in iter(lambda: f.read(65536), b""):
                                sha512_hash.update(byte_block)
                        
                        import base64
                        # Encode SHA-512 digest to base64
                        computed_sha512_b64 = base64.b64encode(sha512_hash.digest()).decode('utf-8')
                        expected_sha512_b64 = reg_integrity.replace("sha512-", "")
                        
                        if computed_sha512_b64 == expected_sha512_b64:
                            match_found = True
                            break
                    except Exception:
                        pass
        
        if match_found:
            return {
                "verified": True,
                "reason": "Checksum verified against registry",
                "computed_hashes": computed,
                "expected_hashes": expected_hashes
            }
        else:
            return {
                "verified": False,
                "reason": "Checksum mismatch! Computed hashes do not match registry records.",
                "computed_hashes": computed,
                "expected_hashes": expected_hashes
            }

    # ==========================================================================
    # AUDIT PIPELINE FOR A SINGLE PACKAGE
    # ==========================================================================
    def check_package(self, name, version=None, ecosystem="PyPI", base_dir=".", local_file=None):
        """
        Coordinates full security assessment for a single package.
        """
        # 1. Fetch package metadata from registry
        if ecosystem == "PyPI":
            reg_info = self.client.get_pypi_package(name, version)
        else:
            reg_info = self.client.get_npm_package(name, version)

        if not reg_info:
            return {
                "name": name,
                "requested_version": version,
                "error": "Not found in registry",
                "ecosystem": ecosystem
            }

        resolved_version = reg_info["version"]
        latest_version = reg_info["latest_version"]

        # 2. Check installation version status
        installed_version = None
        if ecosystem == "PyPI":
            installed_version = self.get_installed_pypi_version(name)
        else:
            installed_version = self.get_installed_npm_version(name, base_dir)

        # 3. Release date age check.
        # High release freshness (< 10 days old) represents a typosquatting or immediate hijack window.
        release_date = reg_info.get("release_date")
        age_days = None
        is_recent = False
        if release_date:
            # Strip timezone info to compare naive dates safely
            naive_release = release_date.replace(tzinfo=None)
            delta = self.current_date - naive_release
            age_days = delta.days
            is_recent = age_days < 10

        # 4. OSV database vulnerability lookup
        vulnerabilities = []
        try:
            vulnerabilities = self.client.query_osv_vulnerabilities(name, resolved_version, ecosystem)
        except Exception:
            pass

        # 4b. Enrich CVEs with official NIST NVD severity metrics and descriptions
        for vuln in vulnerabilities:
            cve_ids = []
            if vuln["id"].upper().startswith("CVE-"):
                cve_ids.append(vuln["id"])
            for alias in vuln.get("aliases", []):
                if alias.upper().startswith("CVE-"):
                    cve_ids.append(alias)
            
            if cve_ids:
                try:
                    # Query NVD for the primary CVE identifier
                    nvd_data = self.client.get_nvd_cve(cve_ids[0])
                    if nvd_data:
                        # Prepend CVSS score to summary
                        vuln["summary"] = f"[{nvd_data['cvss']}] {vuln['summary']}"
                        if nvd_data.get("description"):
                            # Append NVD authoritative description
                            vuln["details"] = vuln["details"] + f"\n\n[NIST NVD Description]\n{nvd_data['description']}"
                except Exception:
                    pass

        # 5. Local file checksum check (if archive file argument is provided)
        file_verification = None
        if local_file:
            file_verification = self.verify_local_file(local_file, name, resolved_version, ecosystem)

        return {
            "name": name,
            "requested_version": version,
            "resolved_version": resolved_version,
            "latest_version": latest_version,
            "installed_version": installed_version,
            "release_date": release_date.strftime("%Y-%m-%d") if release_date else "Unknown",
            "age_days": age_days,
            "is_recent": is_recent,
            "vulnerabilities": vulnerabilities,
            "file_verification": file_verification,
            "ecosystem": ecosystem,
            "hashes": reg_info.get("hashes", []),
            "requires_dist": reg_info.get("requires_dist", []),
            "dependencies": reg_info.get("dependencies", {})
        }
