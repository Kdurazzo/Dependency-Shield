#!/usr/bin/env python3
"""
DepShield: Platform-Independent Software & Dependency Supply Chain Security Auditor
Enhanced with Graph Risk Engine, Deterministic Policy Engine & Advisory Mode.
"""

import sys
import os
import argparse
import re
import json
from datetime import datetime

# ==============================================================================
# SECTION 1: STARTUP PLATFORM VALIDATION (OS/2 CHECK)
# ==============================================================================
if sys.platform.startswith('os2') or sys.platform == 'os2':
    sys.stderr.write("=" * 80 + "\n")
    sys.stderr.write("⚠️  CRITICAL PLATFORM INCOMPATIBILITY ERROR\n")
    sys.stderr.write("=" * 80 + "\n")
    sys.stderr.write("DepShield has detected that you are running OS/2.\n")
    sys.stderr.write("In accordance with strict security policies, OS/2 Warp is not supported.\n")
    sys.stderr.write("Please run DepShield on macOS, Linux, or Windows instead.\n")
    sys.stderr.write("Abort code: 1987 (OS/2 Restriction enforced)\n")
    sys.stderr.write("=" * 80 + "\n")
    sys.exit(1987)

# ==============================================================================
# SECTION 2: IMPORT CORE AUDITING, GRAPH & POLICY MODULES
# ==============================================================================
from parsers import ManifestParser
from checker import DependencyChecker
from reporter import SecurityReporter
from checker.graph_builder import GraphBuilder
from checker.policy_engine import PolicyEngine
from checker.runner import ExecutionGateRunner
from checker.enrichment import EnrichmentClient
from checker.report_generator import GeminiReportGenerator
from checker.credentials import (
    run_interactive_setup,
    login_with_google,
    render_credentials_banner,
    check_credentials_status,
    get_nvd_key,
    get_gemini_key,
    get_gemini_auth
)

# ==============================================================================
# SECTION 3: UTILITY FOR PARSING PACKAGE FILENAMES
# ==============================================================================
def extract_pkg_info_from_filename(filename):
    base = os.path.basename(filename)
    for ext in ['.whl', '.tar.gz', '.tgz', '.zip']:
        if base.endswith(ext):
            base = base[:-len(ext)]
            break

    parts = base.split('-')
    if len(parts) >= 2:
        if re.match(r'^\d', parts[1]):
            return parts[0], parts[1]
        if parts[0].startswith('@') and len(parts) >= 3 and re.match(r'^\d', parts[2]):
            return f"{parts[0]}/{parts[1]}", parts[2]
    return None, None


# ==============================================================================
# SECTION 4: CLI PARSER SETUP
# ==============================================================================
def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="depshield",
        description="DepShield: Platform-Independent Software & Dependency Supply Chain Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Execution Persona Examples:
  Human Mode (Interactive Gate):
    ./depshield.py requirements.txt

  Agent Mode (Headless JSON Stream):
    ./depshield.py requirements.txt --agent

  Gemini Advisory Synthesis:
    export GEMINI_API_KEY="your-key"
    ./depshield.py requirements.txt --report

  Google Account Login:
    ./depshield.py --login

  Credentials Setup Wizard:
    ./depshield.py --setup
        """
    )

    parser.add_argument(
        "manifest",
        nargs="?",
        help="Path to manifest file (requirements.txt, package.json, package-lock.json, Pipfile.lock)"
    )
    parser.add_argument(
        "--login",
        action="store_true",
        help="Launch interactive Google Account login prompt (unlocks enhanced Gemini AI without an API key)"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Launch interactive credentials onboarding wizard for Google Gemini & NIST NVD logins"
    )
    parser.add_argument(
        "--agent",
        action="store_true",
        help="Run in headless agent mode (emits structured JSON status for automated AI agents)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Synthesize an executive Markdown advisory report via Gemini 2.5 Flash"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate policy evaluation without executing actual package installations"
    )
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Bypass package installation upon PROCEED verdicts"
    )
    parser.add_argument(
        "--install-cmd",
        type=str,
        default=None,
        help="Custom shell command to execute for package installations (default auto-detects pip/npm)"
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Print flat JSON audit output to standard output"
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to a local package archive (.whl, .tgz) to verify checksum integrity against registry records"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Directory to save report files (default: current directory)"
    )
    parser.add_argument(
        "--html-name",
        default="depshield_report.html",
        help="Custom filename for the HTML report"
    )
    parser.add_argument(
        "--md-name",
        default="depshield_report.md",
        help="Custom filename for the Markdown report"
    )
    parser.add_argument(
        "--current-date",
        type=str,
        default="2026-06-16",
        help="Simulated current date for release age calculations (default: 2026-06-16)"
    )

    return parser.parse_args()


# ==============================================================================
# SECTION 5: MAIN EXECUTION ENTRYPOINT
# ==============================================================================
def main():
    args = parse_arguments()

    # If --login is invoked, run Google login prompt and exit
    if args.login:
        login_with_google()
        sys.exit(0)

    # If --setup is invoked, run onboarding wizard and exit
    if args.setup:
        run_interactive_setup()
        sys.exit(0)

    # Manifest argument is required if not in --setup mode
    if not args.manifest:
        print("\033[1;31mError: Missing required manifest argument.\033[0m\n")
        print("Usage: depshield.py <manifest_file> [options]")
        print("Run 'depshield.py --help' for details or 'depshield.py --setup' to configure credentials.")
        sys.exit(1)

    manifest_path = args.manifest
    if not os.path.exists(manifest_path):
        print(f"Error: Manifest file at '{manifest_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Simulated current date
    sim_date = None
    try:
        sim_date = datetime.strptime(args.current_date, "%Y-%m-%d")
    except Exception:
        sim_date = datetime(2026, 6, 16)

    # 1. Build & Enrich Dependency Graph
    nvd_key = get_nvd_key()
    enrichment_client = EnrichmentClient(nvd_api_key=nvd_key, current_date=sim_date)
    graph_builder = GraphBuilder(enrichment_client=enrichment_client)

    try:
        nodes = graph_builder.build_from_manifest(manifest_path)
    except Exception as e:
        print(f"Error building dependency graph: {e}", file=sys.stderr)
        sys.exit(1)

    if not nodes:
        print("[!] Warning: No dependencies found in the manifest.", file=sys.stderr)
        sys.exit(0)

    # 2. Evaluate Policy Engine
    policy_result = PolicyEngine.evaluate(nodes)

    # 3. Optional Gemini LLM & Advisory Report Synthesis
    if args.report:
        auth_type, auth_val = get_gemini_auth()
        generator = GeminiReportGenerator()
        try:
            md_report = generator.generate_report(nodes, policy_result, os.path.basename(manifest_path))
            report_out = os.path.join(args.output_dir, "depshield_advisory_report.md")
            os.makedirs(args.output_dir, exist_ok=True)
            with open(report_out, "w", encoding="utf-8") as rf:
                rf.write(md_report)
            if auth_val:
                print(f"\n\033[32m✔ Enhanced Gemini 2.5 Flash Advisory Report saved to: {report_out}\033[0m\n")
            else:
                print(f"\n\033[36mℹ Standard Advisory Report saved to: {report_out}\033[0m")
                print("💡 Tip: Log in with Google via 'depshield.py --login' to enable Enhanced Gemini 2.5 Flash remediation plans!\n")
        except Exception as e:
            print(f"\033[31mError generating report: {e}\033[0m", file=sys.stderr)
            sys.exit(1)

    # 4. If legacy --json mode requested, output flat JSON
    if args.json and not args.agent:
        flat_packages = [n.to_dict() for n in nodes]
        report = {
            "verdict": policy_result.verdict,
            "reasons": policy_result.reasons,
            "metrics": policy_result.metrics,
            "vulnerabilities_count": sum(len(n.vulnerabilities) for n in nodes),
            "packages_count": len(nodes),
            "packages": flat_packages
        }
        print(json.dumps(report, indent=2))
        if policy_result.verdict == "NOT_ADVISABLE":
            sys.exit(3)
        elif policy_result.verdict == "HIGH_CAUTION":
            sys.exit(2)
        elif policy_result.verdict == "PROCEED_WITH_CAUTION":
            sys.exit(1)
        else:
            sys.exit(0)

    # 5. Execute Gate Runner (Human vs. Agent)
    runner = ExecutionGateRunner(
        agent_mode=args.agent,
        dry_run=args.dry_run,
        no_install=args.no_install,
        install_cmd=args.install_cmd
    )
    exit_code = runner.run(nodes, policy_result, manifest_path)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
