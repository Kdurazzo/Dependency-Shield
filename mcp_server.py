#!/usr/bin/env python3
import sys
import json
import os
import urllib.request
import urllib.parse
from parsers import ManifestParser
from checker import DependencyChecker
from web_server import build_flat_report
from checker.credentials import get_gemini_auth

# ==============================================================================
# SECTION 1: MCP JSON-RPC PROTOCOL HANDLERS
# ==============================================================================
def send_response(resp):
    """Sends a JSON-RPC response back to the client via stdout and flushes."""
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def handle_analyze_upgrade(args):
    """Handles upgrade risk analysis using Gemini AI or structured semver assessment."""
    pkg_name = args.get("package_name") or args.get("name")
    resolved_ver = args.get("resolved_version") or args.get("version", "N/A")
    latest_ver = args.get("latest_version", "N/A")
    ecosystem = args.get("ecosystem", "PyPI")
    google_token = args.get("google_access_token") or os.environ.get("GOOGLE_ACCESS_TOKEN")
    gemini_key = args.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY")
    if not google_token and not gemini_key:
        auth_type, auth_val = get_gemini_auth()
        if auth_type == "token":
            google_token = auth_val
        elif auth_type == "key":
            gemini_key = auth_val

    if not pkg_name:
        return {
            "isError": True,
            "content": [{"type": "text", "text": "Error: 'package_name' argument is required."}]
        }

    # If Google Login token or Gemini API Key is provided, use Gemini 2.5 Flash
    if google_token or gemini_key:
        if google_token:
            gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
            headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {google_token}'}
        else:
            gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
            headers = {'Content-Type': 'application/json'}

        prompt = (
            f"Analyze the breaking changes, risk level, and mitigation steps when upgrading "
            f"the {ecosystem} package '{pkg_name}' from version '{resolved_ver}' to the latest version '{latest_ver}'.\n\n"
            f"Provide a concise, professional risk assessment and a step-by-step upgrade strategy. "
            f"Format your response in clean Markdown with appropriate headers."
        )
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }]
        }
        try:
            req_data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                gemini_url,
                data=req_data,
                headers=headers,
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                res_data = json.loads(response.read().decode('utf-8'))
                text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                return {
                    "content": [{"type": "text", "text": text}]
                }
        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Gemini API request failed: {str(e)}"}]
            }

    # Fallback to structured semver risk assessment if no Gemini key is configured
    assessment = [
        f"### Upgrade Analysis for `{pkg_name}` ({ecosystem})",
        f"- **Current Resolved Version:** `{resolved_ver}`",
        f"- **Target Latest Version:** `{latest_ver}`",
        "",
        "#### SemVer Change Classification:",
    ]
    try:
        cur_parts = [int(p) for p in resolved_ver.split('.')[:3] if p.isdigit()]
        lat_parts = [int(p) for p in latest_ver.split('.')[:3] if p.isdigit()]
        if cur_parts and lat_parts:
            if lat_parts[0] > cur_parts[0]:
                assessment.append("> [!WARNING]\n> **MAJOR VERSION JUMP**: Breaking API changes, signature deprecations, or removed features are highly likely. Full regression testing is required.")
            elif len(lat_parts) > 1 and len(cur_parts) > 1 and lat_parts[1] > cur_parts[1]:
                assessment.append("> [!NOTE]\n> **MINOR VERSION BUMP**: Backward-compatible feature additions or performance updates. Backward compatibility is expected.")
            else:
                assessment.append("> [!TIP]\n> **PATCH VERSION BUMP**: Security bug fixes and non-breaking patches.")
    except Exception:
        assessment.append("- Unable to parse semver comparison numerically.")

    assessment.extend([
        "",
        "#### Recommended Migration Checklist:",
        "1. Check the official package release notes / changelog for breaking changes.",
        "2. Run local integration and unit tests before merging dependencies.",
        "3. Verify transitive dependencies against known CVEs using `audit_package`.",
        "",
        "*Tip: Configure `GEMINI_API_KEY` to enable deep AI-powered upgrade synthesis.*"
    ])

    return {
        "content": [{"type": "text", "text": "\n".join(assessment)}]
    }

def handle_tool_call(name, args):
    """Router for executing registered MCP tools."""
    if name == "audit_manifest":
        path = args.get("path")
        max_depth = args.get("max_depth", 3)
        
        if not path:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Error: 'path' argument is required."}]
            }
            
        if not os.path.exists(path):
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Error: Manifest file at '{path}' does not exist."}]
            }
            
        filename = os.path.basename(path)
        packages = []
        try:
            lower_fn = filename.lower()
            if lower_fn == "requirements.txt" or "requirements" in lower_fn:
                packages = ManifestParser.parse_requirements_txt(path)
            elif lower_fn == "package.json":
                packages = ManifestParser.parse_package_json(path)
            elif lower_fn == "package-lock.json":
                packages = ManifestParser.parse_package_lock_json(path)
            elif lower_fn.endswith(".json"):
                if "lock" in lower_fn:
                    packages = ManifestParser.parse_package_lock_json(path)
                else:
                    packages = ManifestParser.parse_package_json(path)
            else:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Error: Unsupported manifest name format '{filename}'. Must be requirements.txt, package.json, or package-lock.json."}]
                }
        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Error parsing manifest: {str(e)}"}]
            }
            
        if not packages:
            return {
                "content": [{"type": "text", "text": "No dependencies found in the manifest."}]
            }
            
        nvd_api_key = args.get("nvd_api_key") or os.environ.get("NVD_API_KEY")
        checker = DependencyChecker(nvd_api_key=nvd_api_key)
        try:
            report = build_flat_report(packages, checker, max_depth=max_depth)
            return {
                "content": [{"type": "text", "text": json.dumps(report, indent=2)}]
            }
        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Error auditing dependencies: {str(e)}"}]
            }
            
    elif name == "audit_package":
        pkg_name = args.get("name")
        version = args.get("version")
        ecosystem = args.get("ecosystem", "PyPI")
        max_depth = args.get("max_depth", 3)
        
        if not pkg_name:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Error: 'name' argument is required."}]
            }
            
        if ecosystem not in ["PyPI", "npm"]:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Error: 'ecosystem' must be either 'PyPI' or 'npm'."}]
            }
            
        nvd_api_key = args.get("nvd_api_key") or os.environ.get("NVD_API_KEY")
        checker = DependencyChecker(nvd_api_key=nvd_api_key)
        try:
            report = build_flat_report([{"name": pkg_name, "version": version, "ecosystem": ecosystem}], checker, max_depth=max_depth)
            return {
                "content": [{"type": "text", "text": json.dumps(report, indent=2)}]
            }
        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Error auditing package: {str(e)}"}]
            }

    elif name == "analyze_upgrade":
        return handle_analyze_upgrade(args)
            
    else:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error: Tool '{name}' not found."}]
        }

# ==============================================================================
# SECTION 2: MAIN PROTOCOL IO LOOP
# ==============================================================================
def main():
    # Loop over standard input lines
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
            
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})
        
        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "depshield-mcp-server",
                        "version": "1.0.0"
                    }
                }
            }
            send_response(resp)
            
        elif method == "notifications/initialized":
            continue
            
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "audit_manifest",
                            "description": (
                                "Audits a software dependency manifest file (requirements.txt, package.json, or package-lock.json) "
                                "recursively for known CVE vulnerabilities, package release age, and registry checksum integrity.\n\n"
                                "--- INVOCATION ORDER & USE CASE ---\n"
                                "ORDER: Invoke FIRST (Step 1) in your security analysis workflow.\n"
                                "WHY: Provides a project-wide bill-of-materials security snapshot. It scans all direct dependencies "
                                "and resolves transitive dependencies up to max_depth.\n"
                                "WHAT TO DO NEXT: Inspect the returned JSON report. Identify packages with 'vulnerable': true or "
                                "high severity scores. For any identified package, proceed to Step 2 ('audit_package') or Step 3 ('analyze_upgrade')."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Absolute path to the manifest file inside the workspace (e.g. /path/to/requirements.txt)"
                                    },
                                    "max_depth": {
                                        "type": "number",
                                        "description": "Maximum recursion depth for transitive dependencies (default: 3). Use 1 for direct-only."
                                    },
                                    "nvd_api_key": {
                                        "type": "string",
                                        "description": "Optional NIST NVD API key to avoid rate limiting when fetching CVSS scores."
                                    }
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "audit_package",
                            "description": (
                                "Audits an individual package from PyPI or npm recursively for security advisories, release age, and checksums.\n\n"
                                "--- INVOCATION ORDER & USE CASE ---\n"
                                "ORDER: Invoke SECOND (Step 2) for deep-dive investigation or pre-installation vetting.\n"
                                "WHY: Use when you want to isolate a specific suspicious dependency uncovered in Step 1, or when evaluating "
                                "a candidate package before adding it to your manifest. Returns exact CVE identifiers, CVSS scores, and summaries.\n"
                                "WHAT TO DO NEXT: If the package contains vulnerabilities or is significantly outdated, invoke 'analyze_upgrade' (Step 3)."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "name": {
                                        "type": "string",
                                        "description": "Package name (e.g., 'requests', 'lodash', 'minimatch')"
                                    },
                                    "version": {
                                        "type": "string",
                                        "description": "Optional specific version to check (e.g. '2.25.1'). Defaults to latest version."
                                    },
                                    "ecosystem": {
                                        "type": "string",
                                        "enum": ["PyPI", "npm"],
                                        "description": "Target ecosystem: 'PyPI' for Python or 'npm' for Node.js (defaults to PyPI)."
                                    },
                                    "max_depth": {
                                        "type": "number",
                                        "description": "Maximum depth to resolve transitive dependencies (default: 3)."
                                    },
                                    "nvd_api_key": {
                                        "type": "string",
                                        "description": "Optional NIST NVD API key."
                                    }
                                },
                                "required": ["name"]
                            }
                        },
                        {
                            "name": "analyze_upgrade",
                            "description": (
                                "Synthesizes migration risks, breaking changes, and a step-by-step remediation plan when upgrading an outdated or vulnerable package.\n\n"
                                "--- INVOCATION ORDER & USE CASE ---\n"
                                "ORDER: Invoke THIRD (Step 3) after identifying vulnerable or outdated packages.\n"
                                "WHY: Prevents breaking changes and build failures when upgrading dependencies. Evaluates major/minor semver jumps "
                                "and leverages Gemini AI (if GEMINI_API_KEY is configured) or semantic heuristic models to propose safe upgrade paths.\n"
                                "WHAT TO DO NEXT: Follow the returned migration checklist to safely update the version pin in requirements.txt or package.json."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "package_name": {
                                        "type": "string",
                                        "description": "Name of the package to analyze (e.g. 'minimatch', 'urllib3')"
                                    },
                                    "resolved_version": {
                                        "type": "string",
                                        "description": "Currently installed or pinned version (e.g. '3.0.0')"
                                    },
                                    "latest_version": {
                                        "type": "string",
                                        "description": "Target upgrade version (e.g. '10.2.5')"
                                    },
                                    "ecosystem": {
                                        "type": "string",
                                        "enum": ["PyPI", "npm"],
                                        "description": "Ecosystem of the package (PyPI or npm, defaults to PyPI)."
                                    },
                                    "gemini_api_key": {
                                        "type": "string",
                                        "description": "Optional Google Gemini API key for AI upgrade synthesis. Falls back to GEMINI_API_KEY env var."
                                    }
                                },
                                "required": ["package_name", "resolved_version", "latest_version"]
                            }
                        }
                    ]
                }
            }
            send_response(resp)
            
        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            
            result = handle_tool_call(tool_name, args)
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }
            send_response(resp)
            
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method {method} not found"
                }
            }
            send_response(resp)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
