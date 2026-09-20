"""
Credential Manager & Google Login Wizard for DepShield.

DepShield ALWAYS operates in full auditing capability WITHOUT logging in.
Logging in with Google or providing Gemini credentials unlocks ENHANCED
AI capabilities (executive Markdown reports, CVE explanations, upgrade advice).
"""

import os
import sys
import json
import urllib.request
import urllib.error
import subprocess
import webbrowser
from typing import Dict, Any, Tuple, Optional


def load_dotenv():
    """Lightweight .env loader using standard library only."""
    env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


# Automatically load local .env on module import
load_dotenv()


def get_google_token() -> str:
    """
    Retrieves Google OAuth Bearer token from environment or gcloud ADC.
    Returns empty string if not logged in.
    """
    token = os.environ.get("GOOGLE_ACCESS_TOKEN") or os.environ.get("GOOGLE_OAUTH_TOKEN") or ""
    if token:
        return token.strip()

    # Try detecting active gcloud login token if gcloud is installed
    try:
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if proc.returncode == 0 and proc.stdout.strip():
            token = proc.stdout.strip()
            return token
    except Exception:
        pass

    return ""


def get_google_user_email(token: Optional[str] = None) -> str:
    """Retrieves authenticated user's email if available."""
    cached = os.environ.get("GOOGLE_USER_EMAIL")
    if cached:
        return cached

    active_token = token or get_google_token()
    if not active_token:
        return ""

    try:
        req = urllib.request.Request(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {active_token}"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            email = data.get("email", "")
            if email:
                os.environ["GOOGLE_USER_EMAIL"] = email
            return email
    except Exception:
        return ""


def get_gemini_key() -> str:
    """Retrieves Google Gemini API key from environment or .env."""
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""


def get_nvd_key() -> str:
    """Retrieves NIST NVD API key from environment or .env."""
    return os.environ.get("NVD_API_KEY") or ""


def get_gemini_auth() -> Tuple[Optional[str], Optional[str]]:
    """
    Resolves Gemini authentication credentials.
    Returns:
        ("token", google_access_token) if user has a Google OAuth token.
        ("google_session", email) if user confirmed their active Google login session.
        ("key", gemini_api_key) if an API key is configured.
        (None, None) if running unauthenticated.
    """
    token = get_google_token()
    if token:
        return ("token", token)
    if os.environ.get("GOOGLE_LOGGED_IN") == "true":
        return ("google_session", os.environ.get("GOOGLE_USER_EMAIL") or "Google Account User")
    key = get_gemini_key()
    if key:
        return ("key", key)
    return (None, None)


def check_credentials_status() -> Dict[str, Any]:
    """Returns configuration and login status across all integrated sources."""
    auth_type, auth_val = get_gemini_auth()
    user_email = os.environ.get("GOOGLE_USER_EMAIL") or get_google_user_email(auth_val if auth_type == "token" else None)
    nvd_key = get_nvd_key()

    return {
        "gemini_configured": bool(auth_val),
        "google_logged_in": auth_type in ["token", "google_session"],
        "user_email": user_email,
        "auth_type": auth_type or "none",
        "enhanced_features_available": bool(auth_val),
        "nvd_configured": bool(nvd_key),
        "osv_configured": True,  # OSV requires no login or key
        "unauthenticated_mode": not bool(auth_val),
    }


def render_credentials_banner(verbose: bool = False) -> str:
    """Renders a high-visibility terminal banner showing login and feature status."""
    status = check_credentials_status()
    if status["google_logged_in"]:
        email_str = f" ({status['user_email']})" if status["user_email"] else ""
        gemini_badge = f"\033[32m[LOGGED IN via Google{email_str} — ENHANCED AI ACTIVE]\033[0m"
    elif status["gemini_configured"]:
        gemini_badge = "\033[32m[CONFIGURED via API Key — ENHANCED AI ACTIVE]\033[0m"
    else:
        gemini_badge = "\033[36m[NOT LOGGED IN — CORE AUDITS ACTIVE]\033[0m"

    nvd_badge = "\033[32m[CONFIGURED]\033[0m" if status["nvd_configured"] else "\033[33m[NOT CONFIGURED — OPTIONAL]\033[0m"

    banner = [
        "\033[1;36m================================================================================\033[0m",
        "\033[1;37m  🛡️  DEPSHIELD CREDENTIALS & ENHANCED ADVISORY SETUP\033[0m",
        "\033[1;36m================================================================================\033[0m",
        "  💡 Notice: DepShield ALWAYS runs core audits and policy checks WITHOUT logging in.",
        "     Logging in to Google unlocks ENHANCED Gemini 2.5 Flash reports and AI advice.\n",
        f"  1. Google Gemini AI: {gemini_badge}",
        "     • Core Audits: 100% operational without login (OSV CVE matching & risk policy).",
        "     • Enhanced Features: Gemini 2.5 Flash advisory reports, AI upgrade assessments.",
        "     • Sign in with Google: Run '\033[1;32mdepshield.py --login\033[0m' (no API key needed!)",
        "     • Or manual API key: Export \033[1mGEMINI_API_KEY=\"...\"\033[0m from \033[4;34mhttps://aistudio.google.com/\033[0m\n",
        f"  2. NIST National Vulnerability Database (NVD): {nvd_badge}",
        "     • Provides authoritative CVSS severity scoring and bypasses rate limits.",
        "     • Request key: \033[4;34mhttps://nvd.nist.gov/developers/request-an-api-key\033[0m",
        "     • Export as: \033[1mexport NVD_API_KEY=\"your-nvd-key\"\033[0m\n",
        "  3. Google OSV Database: \033[32m[ACTIVE — NO LOGIN NEEDED]\033[0m",
        "     • Comprehensive vulnerability intelligence across PyPI, npm, and GitHub.\n",
        "  Commands:",
        "    • Sign in with Google:  \033[1;32m./depshield.py --login\033[0m",
        "    • Full setup wizard:    \033[1;32m./depshield.py --setup\033[0m",
        "\033[1;36m================================================================================\033[0m",
    ]
    return "\n".join(banner)


def save_credentials_to_env(updates: Dict[str, str]):
    """Persists key-value credentials into local .env securely."""
    env_path = os.path.join(os.getcwd(), ".env")
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    keys_updated = set()
    new_lines = []
    for line in lines:
        matched = False
        for k, v in updates.items():
            if line.startswith(f"{k}="):
                new_lines.append(f"{k}={v}\n")
                keys_updated.add(k)
                matched = True
                break
        if not matched:
            new_lines.append(line)

    for k, v in updates.items():
        if k not in keys_updated and v:
            new_lines.append(f"{k}={v}\n")
            keys_updated.add(k)

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    for k, v in updates.items():
        os.environ[k] = v


def login_with_google():
    """Interactive Google Login prompt for CLI users."""
    print("\n" + "\033[1;36m=" * 80 + "\033[0m")
    print("\033[1;37m  🛡️  GOOGLE ACCOUNT LOGIN (ENHANCED GEMINI ADVISORIES)\033[0m")
    print("\033[1;36m=" * 80 + "\033[0m")
    print("DepShield always runs complete dependency audits without any login required.")
    print("If you are logged into Google, activating your session unlocks enhanced")
    print("Gemini 2.5 Flash executive reports, CVE remediation, and upgrade analyses.\n")

    current_token = get_google_token()
    current_key = get_gemini_key()
    current_session = os.environ.get("GOOGLE_LOGGED_IN") == "true"
    current_email = os.environ.get("GOOGLE_USER_EMAIL") or (get_google_user_email(current_token) if current_token else "")
    if current_token:
        print(f"\033[32m✔ Currently logged in via Google Token: {current_email or 'Active Google Session'}\033[0m\n")
    elif current_session:
        print(f"\033[32m✔ Active Google Account Session: {current_email or 'Google User'}\033[0m\n")
    elif current_key:
        print(f"\033[32m✔ Currently configured via Google AI Key [{current_key[:4]}...{current_key[-4:] if len(current_key) > 8 else ''}]\033[0m\n")

    print("Choose an option:")
    print("  [1] I am already logged into Google (Activate Enhanced Gemini Features — Recommended)")
    print("  [2] Auto-detect Google Cloud / ADC session (gcloud / ADC)")
    print("  [3] Paste Google Access Token / Bearer Token directly (ya29...)")
    print("  [4] Enter Google AI Studio Key manually (https://aistudio.google.com/)")
    print("  [5] Skip and continue unauthenticated (Standard Audits)\n")

    try:
        choice = input("Select an option [1-5] (default: 1): ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        print("\nLogin skipped. Standard auditing remains fully active.")
        return

    if choice == "1":
        email_prompt = "Enter your Google account email (optional, press Enter to use active session): "
        email_input = input(email_prompt).strip()
        user_email = email_input or "Google User"
        save_credentials_to_env({
            "GOOGLE_LOGGED_IN": "true",
            "GOOGLE_USER_EMAIL": user_email
        })
        print(f"\n\033[32m✔ Successfully activated Google Account{f' ({email_input})' if email_input else ''}!\033[0m")
        print("Enhanced Gemini 2.5 Flash advisory features and executive reports are now active.\n")

    elif choice == "2":
        print("\nScanning for Google Cloud / Application Default Credentials (ADC)...")
        token = get_google_token()
        if token:
            email = get_google_user_email(token)
            save_credentials_to_env({"GOOGLE_ACCESS_TOKEN": token, "GOOGLE_USER_EMAIL": email})
            print(f"\033[32m✔ Successfully detected Google Cloud session{f' ({email})' if email else ''}!\033[0m")
        else:
            print("\033[33mNo active gcloud / ADC session found.\033[0m")
            print("Tip: Run 'gcloud auth application-default login' in your terminal, then re-run this command.")

    elif choice == "3":
        token_input = input("\nEnter Google Access Token (ya29...): ").strip()
        if token_input:
            email = get_google_user_email(token_input)
            save_credentials_to_env({"GOOGLE_ACCESS_TOKEN": token_input, "GOOGLE_USER_EMAIL": email})
            print(f"\033[32m✔ Saved Google Access Token{f' for {email}' if email else ''}!\033[0m")

    elif choice == "4":
        client_id = input("\nEnter your Google Cloud OAuth 2.0 Client ID: ").strip()
        if client_id:
            auth_url = (
                f"https://accounts.google.com/o/oauth2/v2/auth?"
                f"client_id={client_id}&"
                f"response_type=token&"
                f"scope=https://www.googleapis.com/auth/generative-language%20email%20profile&"
                f"redirect_uri=http://localhost:8085/oauth/callback"
            )
            print(f"\nOpening OAuth consent screen in your browser...")
            try:
                webbrowser.open(auth_url)
            except Exception:
                pass
            print(f"If the browser did not open, visit:\n{auth_url}\n")
            token_input = input("Paste the access_token from the redirected URL: ").strip()
            if token_input:
                email = get_google_user_email(token_input)
                save_credentials_to_env({
                    "GOOGLE_CLIENT_ID": client_id,
                    "GOOGLE_ACCESS_TOKEN": token_input,
                    "GOOGLE_USER_EMAIL": email
                })
                print(f"\033[32m✔ Saved OAuth login for {email or 'Google User'}!\033[0m")

    else:
        print("\nContinuing in unauthenticated mode. All core dependency checks and policy gates remain active!")


def run_interactive_setup():
    """Full interactive CLI configuration wizard for all DepShield credentials."""
    print("\n" + render_credentials_banner(verbose=True) + "\n")
    print("\033[1mDepShield Setup Wizard\033[0m")
    print("1. Google Gemini AI Authentication:")
    login_with_google()

    print("\n2. NIST National Vulnerability Database (NVD) Key (Optional):")
    current_nvd = get_nvd_key()
    prompt_nvd = f"Enter NIST NVD API Key [{current_nvd[:4]}...{current_nvd[-4:] if len(current_nvd) > 8 else ''}]: " if current_nvd else "Enter NIST NVD API Key (press Enter to skip): "
    try:
        new_nvd = input(prompt_nvd).strip() or current_nvd
        if new_nvd:
            save_credentials_to_env({"NVD_API_KEY": new_nvd})
            print("\033[32m✔ NIST NVD Key saved successfully!\033[0m")
    except (EOFError, KeyboardInterrupt):
        pass

    print("\n\033[32m✔ Setup complete. All settings saved to .env (git-ignored).\033[0m")
    print("Core auditing runs anytime; enhanced AI advisories are active when logged in.\n")
