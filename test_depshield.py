import unittest
import os
import sys
import tempfile
import json
from datetime import datetime, timezone
import hashlib

# Import DepShield modules
from parsers import ManifestParser
from checker import DependencyChecker
from registry_client import RegistryClient
from depshield import extract_pkg_info_from_filename

# ==============================================================================
# TEST SUITE: DEPSHIELD UNIT & INTEGRITY TESTS
# ==============================================================================
# Utilizes built-in unittest framework. Checks parsers, helper logics, and
# live connections to registry APIs.

class TestDepShield(unittest.TestCase):

    def setUp(self):
        # Set up a temporary directory to write scratch manifest files for testing
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        # Clean up temporary directory structure after each test run
        self.temp_dir.cleanup()

    # ==========================================================================
    # TEST: FILENAME PARSER
    # ==========================================================================
    def test_extract_pkg_info_from_filename(self):
        """Checks parsing of package archives names for multiple environments."""
        # Python wheel packaging standard
        self.assertEqual(
            extract_pkg_info_from_filename("requests-2.31.0-py3-none-any.whl"),
            ("requests", "2.31.0")
        )
        # npm package tarball standard
        self.assertEqual(
            extract_pkg_info_from_filename("lodash-4.17.21.tgz"),
            ("lodash", "4.17.21")
        )
        # Scoped npm package representation in file system
        self.assertEqual(
            extract_pkg_info_from_filename("@types-lodash-4.17.21.tgz"),
            ("@types/lodash", "4.17.21")
        )

    # ==========================================================================
    # TEST: PIP REQUIREMENTS PARSER
    # ==========================================================================
    def test_parse_requirements_txt(self):
        """Verifies requirements.txt formatting support (comments, extras, unpinned)."""
        req_path = os.path.join(self.temp_dir.name, "requirements.txt")
        with open(req_path, "w", encoding="utf-8") as f:
            f.write("# This is a comment\n")
            f.write("requests==2.31.0\n")         # exact pin
            f.write("urllib3>=1.26.5\n")           # inequality constraint
            f.write("django[argon2]==4.2.1\n")     # package with extras
            f.write("   # Indented comment\n")
            f.write("gunicorn\n")                  # unpinned

        packages = ManifestParser.parse_requirements_txt(req_path)
        self.assertEqual(len(packages), 4)
        
        # requests (exact version should parse out)
        self.assertEqual(packages[0]["name"], "requests")
        self.assertEqual(packages[0]["version"], "2.31.0")
        
        # urllib3 (non-exact operator: version set to None, raw recorded)
        self.assertEqual(packages[1]["name"], "urllib3")
        self.assertIsNone(packages[1]["version"])
        
        # django (stripped extras successfully)
        self.assertEqual(packages[2]["name"], "django")
        self.assertEqual(packages[2]["version"], "4.2.1")
        
        # gunicorn (no version specified)
        self.assertEqual(packages[3]["name"], "gunicorn")
        self.assertIsNone(packages[3]["version"])

    # ==========================================================================
    # TEST: NPM PACKAGE.JSON PARSER
    # ==========================================================================
    def test_parse_package_json(self):
        """Verifies parsing of standard npm package.json structure."""
        pkg_path = os.path.join(self.temp_dir.name, "package.json")
        data = {
            "name": "test-app",
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "~4.18.2"
            },
            "devDependencies": {
                "jest": "29.5.0",
                "typescript": "*"
            }
        }
        with open(pkg_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        packages = ManifestParser.parse_package_json(pkg_path)
        self.assertEqual(len(packages), 4)
        
        names = [p["name"] for p in packages]
        self.assertIn("lodash", names)
        self.assertIn("express", names)
        self.assertIn("jest", names)
        self.assertIn("typescript", names)
        
        # typescript version is '*' -> mapped to None
        typescript_pkg = next(p for p in packages if p["name"] == "typescript")
        self.assertIsNone(typescript_pkg["version"])

        # jest is exactly pinned -> clean version extracted
        jest_pkg = next(p for p in packages if p["name"] == "jest")
        self.assertEqual(jest_pkg["version"], "29.5.0")

    # ==========================================================================
    # TEST: NPM LOCKFILE PARSER
    # ==========================================================================
    def test_parse_package_lock_json(self):
        """Verifies parsing exact versions and integrity hashes from npm lockfiles."""
        lock_path = os.path.join(self.temp_dir.name, "package-lock.json")
        data = {
            "name": "test-app",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {
                        "lodash": "^4.17.21"
                    }
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDEe57becT518CdBcGyeRSG7YeLXgcM5yS1qWZ6ffn0o6tLESgF7I8TzcyCFg8ESr2I5SobwymQXcLFQU25g=="
                }
            }
        }
        with open(lock_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        packages = ManifestParser.parse_package_lock_json(lock_path)
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["name"], "lodash")
        self.assertEqual(packages[0]["version"], "4.17.21")
        self.assertEqual(packages[0]["integrity"], "sha512-v2kDEe57becT518CdBcGyeRSG7YeLXgcM5yS1qWZ6ffn0o6tLESgF7I8TzcyCFg8ESr2I5SobwymQXcLFQU25g==")

    # ==========================================================================
    # TEST: BINARY FILE SIGNATURE GENERATION
    # ==========================================================================
    def test_hash_calculation_and_verify(self):
        """Verifies standard stream hash calculations (MD5, SHA256)."""
        dummy_file = os.path.join(self.temp_dir.name, "dummy-1.0.0.whl")
        content = b"fake wheel package content"
        with open(dummy_file, "wb") as f:
            f.write(content)

        hashes = DependencyChecker.calculate_file_hashes(dummy_file)
        self.assertEqual(hashes["md5"], hashlib.md5(content).hexdigest())
        self.assertEqual(hashes["sha256"], hashlib.sha256(content).hexdigest())

    # ==========================================================================
    # TEST: LIVE NETWORK RESOLUTIONS
    # ==========================================================================
    def test_live_registry_lookup_pypi(self):
        """Verifies connection to PyPI and JSON structure decoding."""
        client = RegistryClient()
        data = client.get_pypi_package("requests", "2.31.0")
        
        self.assertIsNotNone(data)
        self.assertEqual(data["name"], "requests")
        self.assertEqual(data["version"], "2.31.0")
        self.assertIsNotNone(data["release_date"])
        self.assertTrue(len(data["hashes"]) > 0)

    def test_live_registry_lookup_npm(self):
        """Verifies connection to npm registry and JSON structure decoding."""
        client = RegistryClient()
        data = client.get_npm_package("lodash", "4.17.21")
        
        self.assertIsNotNone(data)
        self.assertEqual(data["name"], "lodash")
        self.assertEqual(data["version"], "4.17.21")
        self.assertIsNotNone(data["release_date"])
        self.assertTrue(len(data["hashes"]) > 0)

    def test_live_vulnerability_query(self):
        """Verifies connection to Google OSV database and response processing."""
        client = RegistryClient()
        # Querying an older version of lodash with known CVEs
        vulns = client.query_osv_vulnerabilities("lodash", "4.17.20", "npm")
        self.assertTrue(len(vulns) > 0)
        
        # Verify vulnerability details are parsed
        self.assertIsNotNone(vulns[0]["id"])
        self.assertIsNotNone(vulns[0]["summary"])

    def test_live_nvd_query(self):
        """Verifies direct live connection to NIST NVD REST API."""
        client = RegistryClient()
        # Querying NVD for a specific known CVE
        data = client.get_nvd_cve("CVE-2021-23337")
        self.assertIsNotNone(data)
        self.assertEqual(data["id"], "CVE-2021-23337")
        self.assertIsNotNone(data["description"])
        self.assertIsNotNone(data["cvss"])

    # ==========================================================================
    # TEST: RELEASE DATE FILTER
    # ==========================================================================
    def test_age_highlighting(self):
        """Checks if checker correctly highlights releases less than 10 days old."""
        # Simulated run date set to 2026-06-16
        checker = DependencyChecker(current_date="2026-06-16")
        
        # Mock registry database client (returns release from 6 days prior)
        class MockRegistryClient:
            def get_pypi_package(self, name, version=None):
                return {
                    "name": name,
                    "version": "1.0.0",
                    "latest_version": "1.0.0",
                    "release_date": datetime(2026, 6, 10),
                    "hashes": [],
                    "ecosystem": "PyPI"
                }
            def query_osv_vulnerabilities(self, name, version, ecosystem):
                return []

        checker.client = MockRegistryClient()
        res = checker.check_package("test-package", "1.0.0", "PyPI")
        
        self.assertEqual(res["age_days"], 6)
        self.assertTrue(res["is_recent"])

        # Mock older release date (returns release from 46 days prior)
        class MockOlderRegistryClient:
            def get_pypi_package(self, name, version=None):
                return {
                    "name": name,
                    "version": "1.0.0",
                    "latest_version": "1.0.0",
                    "release_date": datetime(2026, 5, 1),
                    "hashes": [],
                    "ecosystem": "PyPI"
                }
            def query_osv_vulnerabilities(self, name, version, ecosystem):
                return []

        checker.client = MockOlderRegistryClient()
        res = checker.check_package("test-package", "1.0.0", "PyPI")
        
        self.assertEqual(res["age_days"], 46)
        self.assertFalse(res["is_recent"])

    # ==========================================================================
    # TEST: FLAT REPORT BUILDER (API LAYER)
    # ==========================================================================
    def test_build_flat_report(self):
        """Verifies that flat security report formats package lists and summaries correctly."""
        from web_server import build_flat_report
        
        checker = DependencyChecker(current_date="2026-06-16")
        # Mock client to return controlled values
        class MockRegistryClient:
            def get_pypi_package(self, name, version=None):
                return {
                    "name": name,
                    "version": "1.0.0",
                    "latest_version": "1.0.0",
                    "release_date": datetime(2026, 6, 12), # 4 days old -> recent!
                    "hashes": [],
                    "ecosystem": "PyPI",
                    "requires_dist": []
                }
            def query_osv_vulnerabilities(self, name, version, ecosystem):
                return [{
                    "id": "CVE-TEST",
                    "summary": "Mock vulnerability",
                    "details": "Mock details"
                }]

        checker.client = MockRegistryClient()
        report = build_flat_report([{"name": "test-pkg", "version": "1.0.0", "ecosystem": "PyPI"}], checker, max_depth=1)
        
        self.assertEqual(report["total_packages"], 1)
        self.assertEqual(report["vulnerabilities_count"], 1)
        self.assertEqual(report["recent_packages_count"], 1)
        self.assertEqual(report["risk_level"], "HIGH")
        self.assertEqual(len(report["packages"]), 1)
        self.assertEqual(report["packages"][0]["name"], "test-pkg")
        self.assertEqual(report["packages"][0]["risk"], "high")

if __name__ == "__main__":
    unittest.main()
