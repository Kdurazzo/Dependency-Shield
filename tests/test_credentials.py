"""
Unit Tests for DepShield Credentials & Google Login System.
Validates unauthenticated baseline and dual-mode Gemini authentication.
"""

import os
import unittest
from unittest.mock import patch

from checker.credentials import (
    get_gemini_auth,
    check_credentials_status,
    render_credentials_banner,
    get_google_token,
    get_gemini_key,
)
from checker.report_generator import GeminiReportGenerator
from checker.models import DependencyNode, PolicyResult


class TestCredentialsSystem(unittest.TestCase):

    def setUp(self):
        self.original_env = os.environ.copy()
        for k in ["GOOGLE_ACCESS_TOKEN", "GOOGLE_OAUTH_TOKEN", "GOOGLE_LOGGED_IN", "GEMINI_API_KEY", "GOOGLE_API_KEY", "NVD_API_KEY", "GOOGLE_USER_EMAIL"]:
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_unauthenticated_baseline(self):
        """DepShield must always report unauthenticated mode when no credentials are provided."""
        auth_type, auth_val = get_gemini_auth()
        self.assertIsNone(auth_type)
        self.assertIsNone(auth_val)

        status = check_credentials_status()
        self.assertTrue(status["unauthenticated_mode"])
        self.assertFalse(status["gemini_configured"])
        self.assertFalse(status["google_logged_in"])
        self.assertFalse(status["enhanced_features_available"])
        self.assertTrue(status["osv_configured"])  # OSV is always active

        banner = render_credentials_banner()
        self.assertIn("CORE AUDITS ACTIVE", banner)
        self.assertIn("WITHOUT logging in", banner)

    def test_google_token_auth(self):
        """When GOOGLE_ACCESS_TOKEN is provided, resolves auth as 'token'."""
        os.environ["GOOGLE_ACCESS_TOKEN"] = "ya29.sample-google-oauth-token"
        os.environ["GOOGLE_USER_EMAIL"] = "dev@example.com"

        auth_type, auth_val = get_gemini_auth()
        self.assertEqual(auth_type, "token")
        self.assertEqual(auth_val, "ya29.sample-google-oauth-token")

        status = check_credentials_status()
        self.assertTrue(status["google_logged_in"])
        self.assertTrue(status["enhanced_features_available"])
        self.assertEqual(status["user_email"], "dev@example.com")
        self.assertFalse(status["unauthenticated_mode"])

        banner = render_credentials_banner()
        self.assertIn("LOGGED IN via Google", banner)
        self.assertIn("dev@example.com", banner)

    def test_api_key_auth(self):
        """When GEMINI_API_KEY is provided, resolves auth as 'key'."""
        os.environ["GEMINI_API_KEY"] = "AIzaSyFakeTestKey12345"

        auth_type, auth_val = get_gemini_auth()
        self.assertEqual(auth_type, "key")
        self.assertEqual(auth_val, "AIzaSyFakeTestKey12345")

        status = check_credentials_status()
        self.assertFalse(status["google_logged_in"])
        self.assertTrue(status["gemini_configured"])
        self.assertTrue(status["enhanced_features_available"])

        banner = render_credentials_banner()
        self.assertIn("CONFIGURED via API Key", banner)

    def test_google_session_auth(self):
        """When user confirms active Google login session, resolves auth as 'google_session'."""
        os.environ["GOOGLE_LOGGED_IN"] = "true"
        os.environ["GOOGLE_USER_EMAIL"] = "developer@example.com"

        auth_type, auth_val = get_gemini_auth()
        self.assertEqual(auth_type, "google_session")
        self.assertEqual(auth_val, "developer@example.com")

        status = check_credentials_status()
        self.assertTrue(status["google_logged_in"])
        self.assertTrue(status["enhanced_features_available"])
        self.assertEqual(status["user_email"], "developer@example.com")

        gen = GeminiReportGenerator()
        res = PolicyResult(verdict="NOT_ADVISABLE", reasons=["High Red count"], metrics={"total_count": 1, "red_count": 1, "red_pct": 1.0})
        node = DependencyNode(name="requests", version="2.25.1", ecosystem="PyPI", risk_color="RED", is_young=False)
        report = gen.generate_report([node], res, "manifest.txt")
        self.assertIn("DepShield Security & Executive Advisory Report", report)
        self.assertIn("developer@example.com", report)
        self.assertIn("Enhanced Advisory Active", report)

    def test_token_precedence_over_key(self):
        """Google Login token takes precedence over API key when both exist."""
        os.environ["GOOGLE_ACCESS_TOKEN"] = "ya29.token-precedence"
        os.environ["GEMINI_API_KEY"] = "AIzaSyKeyFallback"

        auth_type, auth_val = get_gemini_auth()
        self.assertEqual(auth_type, "token")
        self.assertEqual(auth_val, "ya29.token-precedence")

    def test_report_generator_unauthenticated_fallback(self):
        """Report generator in unauthenticated mode outputs full report without throwing."""
        gen = GeminiReportGenerator()
        res = PolicyResult(verdict="PROCEED", reasons=["All dependencies clean"], metrics={"total_count": 1, "green_count": 1, "green_pct": 1.0})
        node = DependencyNode(name="requests", version="2.31.0", ecosystem="PyPI", risk_color="GREEN", is_young=False)

        report = gen.generate_report([node], res, "requirements.txt")
        self.assertIn("# DepShield Security & Advisory Report: requirements.txt", report)
        self.assertIn("Standard Audit Mode", report)
        self.assertIn("PROCEED", report)
        self.assertIn("| `requests` | `2.31.0` | PyPI | **GREEN** |", report)
        self.assertIn("depshield.py --login", report)


if __name__ == "__main__":
    unittest.main()
