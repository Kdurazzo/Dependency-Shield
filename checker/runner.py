"""
Execution Gate Adapter: Human vs Agent Personas (Human-in-the-loop vs Human-on-the-loop).
"""

import os
import sys
import json
import subprocess
from typing import List, Dict, Any, Optional

from checker.models import DependencyNode, PolicyResult
from checker.credentials import check_credentials_status, render_credentials_banner


class ExecutionGateRunner:
    """Executes policy gates according to Agent vs Human execution semantics."""

    def __init__(
        self,
        agent_mode: bool = False,
        dry_run: bool = False,
        no_install: bool = False,
        install_cmd: Optional[str] = None
    ):
        self.agent_mode = agent_mode or os.environ.get("CI", "").lower() in ["1", "true"] or os.environ.get("HEADLESS", "").lower() in ["1", "true"]
        self.dry_run = dry_run
        self.no_install = no_install
        self.install_cmd = install_cmd

    def _determine_install_cmd(self, manifest_path: str) -> Optional[List[str]]:
        if self.install_cmd:
            return self.install_cmd.split()
        fn = os.path.basename(manifest_path).lower()
        if fn == "requirements.txt" or "requirements" in fn:
            return [sys.executable, "-m", "pip", "install", "-r", manifest_path]
        elif fn == "pipfile.lock":
            return ["pipenv", "sync"]
        elif fn == "package.json" or fn == "package-lock.json":
            return ["npm", "install"]
        return None

    def execute_install(self, manifest_path: str) -> bool:
        cmd = self._determine_install_cmd(manifest_path)
        if not cmd:
            return True
        if self.dry_run or self.no_install:
            return True
        try:
            res = subprocess.run(cmd, check=True)
            return res.returncode == 0
        except Exception:
            return False

    def run(self, nodes: List[DependencyNode], policy_result: PolicyResult, manifest_path: str) -> int:
        """Runs the execution gate and returns appropriate process exit code."""
        verdict = policy_result.verdict
        cred_status = check_credentials_status()

        # ==============================================================================
        # AGENT EXECUTION PERSONA
        # ==============================================================================
        if self.agent_mode:
            if verdict == "PROCEED":
                installed = False
                if not self.no_install and not self.dry_run:
                    installed = self.execute_install(manifest_path)
                else:
                    installed = True

                output = {
                    "status": "INSTALLED",
                    "mode": "HUMAN_ON_THE_LOOP",
                    "verdict": verdict,
                    "reasons": policy_result.reasons,
                    "metrics": policy_result.metrics,
                    "packages_count": len(nodes),
                    "installed": installed,
                    "credentials_setup": {
                        "gemini_configured": cred_status["gemini_configured"],
                        "nvd_configured": cred_status["nvd_configured"],
                        "setup_instructions": "Run 'depshield.py --setup' or export GEMINI_API_KEY/NVD_API_KEY"
                    }
                }
                sys.stdout.write(json.dumps(output, indent=2) + "\n")
                return 0
            else:
                # All caution and not-advisable states halt execution in agent mode
                output = {
                    "status": "REQUIRES_APPROVAL",
                    "mode": "HUMAN_IN_THE_LOOP",
                    "choice": ["APPROVE", "DECLINE"],
                    "verdict": verdict,
                    "reasons": policy_result.reasons,
                    "affected_packages": policy_result.affected_packages,
                    "metrics": policy_result.metrics,
                    "credentials_setup": {
                        "gemini_configured": cred_status["gemini_configured"],
                        "nvd_configured": cred_status["nvd_configured"],
                        "setup_instructions": "Run 'depshield.py --setup' or export GEMINI_API_KEY/NVD_API_KEY"
                    }
                }
                sys.stdout.write(json.dumps(output, indent=2) + "\n")
                if verdict == "NOT_ADVISABLE":
                    return 3
                elif verdict == "HIGH_CAUTION":
                    return 2
                else:
                    return 1

        # ==============================================================================
        # HUMAN EXECUTION PERSONA
        # ==============================================================================
        # Check credentials and display prompt banner if unconfigured
        if not cred_status["gemini_configured"] or not cred_status["nvd_configured"]:
            print(render_credentials_banner(verbose=False))
            print()

        print("\033[1;37m" + "=" * 80 + "\033[0m")
        print(f"\033[1m  DEPSHIELD DEPENDENCY AUDIT & POLICY EVALUATION\033[0m")
        print("\033[1;37m" + "=" * 80 + "\033[0m")
        print(f"  Target Manifest:  \033[1m{manifest_path}\033[0m")
        print(f"  Total Packages:   {policy_result.metrics['total_count']}")
        print(f"  Red (High/Crit):  {policy_result.metrics['red_count']} ({policy_result.metrics['red_pct'] * 100:.1f}%)")
        print(f"  Yellow (Medium):  {policy_result.metrics['yellow_count']} ({policy_result.metrics['yellow_pct'] * 100:.1f}%)")
        print(f"  Green (Clean):    {policy_result.metrics['green_count']} ({policy_result.metrics['green_pct'] * 100:.1f}%)")
        print(f"  Young (<15 days): {policy_result.metrics['young_count']}")
        print("\033[1;37m" + "-" * 80 + "\033[0m")

        if verdict == "NOT_ADVISABLE":
            print("\033[1;41;37m  ⛔ VERDICT: NOT ADVISABLE - INSTALL BLOCKED  \033[0m\n")
            for r in policy_result.reasons:
                print(f"  \033[31m• {r}\033[0m")
            print("\n\033[1;31mInstallation is strongly discouraged due to high critical risk.\033[0m")
            try:
                confirm = input("\nDo you wish to override and force installation anyway? [y/N]: ").strip().lower()
                if confirm in ["y", "yes"]:
                    print("\033[33mProceeding with override install...\033[0m")
                    self.execute_install(manifest_path)
                    return 0
            except (KeyboardInterrupt, EOFError):
                pass
            return 3

        elif verdict == "HIGH_CAUTION":
            print("\033[1;43;30m  ⚠️  VERDICT: HIGH CAUTION - YOUNG PACKAGES DETECTED  \033[0m\n")
            for r in policy_result.reasons:
                print(f"  \033[33m• {r}\033[0m")
            print("\n\033[33mRecently published packages may pose supply chain or typosquatting risks.\033[0m")
            try:
                confirm = input("\nApprove or decline installation? [y/N]: ").strip().lower()
                if confirm in ["y", "yes"]:
                    print("\033[32mInstallation approved by user.\033[0m")
                    self.execute_install(manifest_path)
                    return 0
            except (KeyboardInterrupt, EOFError):
                pass
            return 2

        elif verdict == "PROCEED_WITH_CAUTION":
            print("\033[1;43;30m  ⚡ VERDICT: PROCEED WITH CAUTION - MODERATE RISKS  \033[0m\n")
            for r in policy_result.reasons:
                print(f"  \033[33m• {r}\033[0m")
            try:
                confirm = input("\nApprove installation with moderate risks? [y/N]: ").strip().lower()
                if confirm in ["y", "yes"]:
                    print("\033[32mInstallation approved by user.\033[0m")
                    self.execute_install(manifest_path)
                    return 0
            except (KeyboardInterrupt, EOFError):
                pass
            return 1

        else:  # PROCEED
            print("\033[1;42;37m  ✔ VERDICT: PROCEED - ALL DEPENDENCIES SAFE  \033[0m\n")
            for r in policy_result.reasons:
                print(f"  \033[32m• {r}\033[0m")
            print(f"\n\033[32mSafe to install. Auto-installing dependencies (Human-on-the-loop)...\033[0m")
            if not self.no_install and not self.dry_run:
                self.execute_install(manifest_path)
            print("\033[32mCompleted.\033[0m")
            return 0
