#!/usr/bin/env python3
import sys
import json
import os
from parsers import ManifestParser
from checker import DependencyChecker
from web_server import build_flat_report

# ==============================================================================
# SECTION 1: MCP JSON-RPC PROTOCOL HANDLERS
# ==============================================================================
def send_response(resp):
    """Sends a JSON-RPC response back to the client via stdout and flushes."""
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

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
            
        checker = DependencyChecker()
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
            
        checker = DependencyChecker()
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
                            "description": "Reads and audits a software dependency manifest file (requirements.txt, package.json, or package-lock.json) recursively for security vulnerabilities, release age, and registry checksums.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Absolute path to the manifest file inside the workspace"
                                    },
                                    "max_depth": {
                                        "type": "number",
                                        "description": "Maximum depth to resolve transitive dependencies (default: 3)"
                                    }
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "audit_package",
                            "description": "Audits a single package from PyPI or npm recursively for security advisories, release age, and registry checksums.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "name": {
                                        "type": "string",
                                        "description": "Package name (e.g., requests, lodash)"
                                    },
                                    "version": {
                                        "type": "string",
                                        "description": "Optional specific version to check (defaults to latest)"
                                    },
                                    "ecosystem": {
                                        "type": "string",
                                        "enum": ["PyPI", "npm"],
                                        "description": "Target ecosystem (PyPI or npm, defaults to PyPI)"
                                    },
                                    "max_depth": {
                                        "type": "number",
                                        "description": "Maximum depth to resolve transitive dependencies (default: 3)"
                                    }
                                },
                                "required": ["name"]
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
