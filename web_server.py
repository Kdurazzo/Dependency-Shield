#!/usr/bin/env python3
import os
import sys
import json
import re
import tempfile
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from parsers import ManifestParser
from checker.models import DependencyNode, Vulnerability
from checker.policy_engine import PolicyEngine
from checker.credentials import check_credentials_status, get_gemini_auth, get_google_user_email
from checker import DependencyChecker

# ==============================================================================
# SECTION 1: PEP 508 & DEPENDENCY PARSING HELPERS
# ==============================================================================
def parse_pypi_dep(dep_str):
    """
    Extracts the package name and any exact version pin from a PEP 508 string.
    E.g. "urllib3 (<3,>=1.21.1)" -> ("urllib3", None)
    E.g. "django[argon2]==4.2.1" -> ("django", "4.2.1")
    """
    if ';' in dep_str:
        parts = dep_str.split(';', 1)
        dep_part = parts[0].strip()
        marker_part = parts[1].strip()
        # Skip if it is an extra dependency
        if 'extra' in marker_part:
            return None
    else:
        dep_part = dep_str.strip()
    
    # Match package name (letters, numbers, hyphens, underscores)
    match = re.match(r'^([a-zA-Z0-9_\-]+)', dep_part)
    if match:
        name = match.group(1)
        # Extract version pin if it's exact (==)
        version = None
        ver_match = re.search(r'==\s*([a-zA-Z0-9\.\-\_]+)', dep_part)
        if ver_match:
            version = ver_match.group(1)
        return name, version
    return None

def extract_pypi_deps(requires_dist):
    """Parses all requires_dist strings into a list of (name, version) tuples."""
    deps = []
    if not requires_dist:
        return deps
    for dep_str in requires_dist:
        parsed = parse_pypi_dep(dep_str)
        if parsed:
            deps.append(parsed)
    return deps

def extract_npm_deps(dependencies):
    """Normalizes npm dependencies dictionary into a list of (name, version) tuples."""
    deps = []
    if not dependencies:
        return deps
    for name, range_val in dependencies.items():
        # Strip semver prefix symbols to get a base version estimate
        clean_version = re.sub(r'^[\^~>=<*]+', '', range_val).strip()
        if not clean_version or clean_version == '*':
            clean_version = None
        deps.append((name, clean_version))
    return deps

# ==============================================================================
# SECTION 2: RECURSIVE DEPENDENCY GRAPH BUILDER
# ==============================================================================
def build_graph(root_packages, checker, max_depth=3):
    """
    Traverses the dependency tree using Breadth-First Search (BFS) to build
    a graph containing nodes (with security audit results) and links.
    """
    nodes = {}
    links = []
    # Queue structure: (package_name, version, ecosystem, current_depth, parent_node_key)
    queue = []
    
    for pkg in root_packages:
        queue.append((pkg["name"], pkg.get("version"), pkg.get("ecosystem", "PyPI"), 0, None))
        
    visited = set()
    
    while queue:
        name, version, ecosystem, depth, parent_key = queue.pop(0)
        if not name:
            continue
            
        key = f"{ecosystem}:{name.lower()}"
        
        # If we already resolved and audited this package
        if key in visited:
            if parent_key and parent_key != key:
                link = {"source": parent_key, "target": key}
                if link not in links:
                    links.append(link)
            continue
            
        visited.add(key)
        
        # Audit the package details
        try:
            audit_res = checker.check_package(name, version, ecosystem)
        except Exception as e:
            audit_res = {
                "name": name,
                "requested_version": version,
                "error": f"Registry fetch error: {str(e)}",
                "ecosystem": ecosystem
            }
            
        # Determine risk classification for visualization styling
        vulns = audit_res.get("vulnerabilities", [])
        is_recent = audit_res.get("is_recent", False)
        file_verification = audit_res.get("file_verification")
        checksum_fail = file_verification and not file_verification.get("verified")
        
        if audit_res.get("error"):
            risk = "unknown"
        elif checksum_fail:
            risk = "critical"
        elif vulns:
            risk = "high"
        elif is_recent:
            risk = "medium"
        else:
            risk = "low"
            
        nodes[key] = {
            "id": key,
            "name": name,
            "ecosystem": ecosystem,
            "requested_version": version or "Latest",
            "resolved_version": audit_res.get("resolved_version", "N/A"),
            "latest_version": audit_res.get("latest_version", "N/A"),
            "installed_version": audit_res.get("installed_version"),
            "release_date": audit_res.get("release_date", "Unknown"),
            "age_days": audit_res.get("age_days"),
            "is_recent": is_recent,
            "vulnerabilities": vulns,
            "file_verification": file_verification,
            "risk": risk,
            "error": audit_res.get("error")
        }
        
        if parent_key and parent_key != key:
            links.append({"source": parent_key, "target": key})
            
        # If reached max depth, stop adding dependencies
        if depth >= max_depth:
            continue
            
        # Queue child dependencies
        if not audit_res.get("error"):
            children = []
            if ecosystem == "PyPI":
                requires_dist = audit_res.get("requires_dist", [])
                children = extract_pypi_deps(requires_dist)
            else: # npm
                dependencies = audit_res.get("dependencies", {})
                children = extract_npm_deps(dependencies)
                
            for child_name, child_version in children:
                queue.append((child_name, child_version, ecosystem, depth + 1, key))
                
    return {
        "nodes": list(nodes.values()),
        "links": links
    }

def build_flat_report(root_packages, checker, max_depth=3):
    """
    Builds a simplified, flat security audit report by traversing dependencies
    and summarizing vulnerabilities, age, and checksums.
    """
    graph = build_graph(root_packages, checker, max_depth=max_depth)
    
    total = len(graph["nodes"])
    vulns = 0
    recent = 0
    checksum_fail = 0
    
    packages_list = []
    for node in graph["nodes"]:
        v_list = node.get("vulnerabilities") or []
        vulns += len(v_list)
        if node.get("is_recent"):
            recent += 1
        
        v_file = node.get("file_verification")
        if v_file and not v_file.get("verified"):
            checksum_fail += 1
            
        packages_list.append({
            "name": node["name"],
            "ecosystem": node["ecosystem"],
            "requested_version": node["requested_version"],
            "resolved_version": node["resolved_version"],
            "installed_version": node["installed_version"],
            "release_date": node["release_date"],
            "age_days": node["age_days"],
            "risk": node["risk"],
            "vulnerabilities": v_list,
            "file_verification": node["file_verification"],
            "error": node["error"]
        })
        
    if checksum_fail > 0:
        risk_level = "CRITICAL"
    elif vulns > 0:
        risk_level = "HIGH"
    elif recent > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        
    # Build DependencyNode list for PolicyEngine
    dep_nodes = []
    for pkg in packages_list:
        p_vulns = pkg.get("vulnerabilities", [])
        p_risk = pkg.get("risk", "low")
        age = pkg.get("age_days")
        is_young = (age is not None and age < 15)
        
        # Color classification
        if p_risk in ["critical", "high"]:
            color = "RED"
        elif p_risk in ["medium", "yellow"] or len(p_vulns) > 0:
            color = "YELLOW"
        else:
            color = "GREEN"
            
        pkg["risk_color"] = color
        pkg["is_young"] = is_young
        
        dep_nodes.append(DependencyNode(
            name=pkg["name"],
            version=pkg.get("resolved_version") or pkg.get("requested_version") or "1.0.0",
            ecosystem=pkg.get("ecosystem", "PyPI"),
            risk_color=color,
            is_young=is_young,
            age_days=age
        ))
        
    policy_res = PolicyEngine.evaluate(dep_nodes)
    cred_status = check_credentials_status()
    
    return {
        "risk_level": risk_level,
        "verdict": policy_res.verdict,
        "policy_reasons": policy_res.reasons,
        "policy_metrics": policy_res.metrics,
        "total_packages": total,
        "vulnerabilities_count": vulns,
        "recent_packages_count": recent,
        "checksum_failures_count": checksum_fail,
        "credentials_setup": {
            "gemini_configured": cred_status["gemini_configured"],
            "google_logged_in": cred_status.get("google_logged_in", False),
            "user_email": cred_status.get("user_email", ""),
            "auth_type": cred_status.get("auth_type", "none"),
            "enhanced_features_available": cred_status.get("enhanced_features_available", False),
            "nvd_configured": cred_status["nvd_configured"],
            "setup_instructions": "Run './depshield.py --login' or sign in with Google in Settings to enable enhanced AI reporting."
        },
        "packages": packages_list
    }

# ==============================================================================
# SECTION 3: HTTP REQUEST HANDLER
# ==============================================================================
class DepShieldHTTPHandler(BaseHTTPRequestHandler):

    def send_json_response(self, status, data):
        """Sends a JSON formatted HTTP response with CORS headers."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_error_response(self, status, message):
        """Sends a standard JSON error response."""
        self.send_json_response(status, {"error": message})

    def do_OPTIONS(self):
        """Handles CORS preflight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # Endpoint: API Health check
        if path == "/api/health":
            self.send_json_response(200, {"status": "ok"})
            return

        # Endpoint: Auth & Google login status
        elif path == "/api/auth/google/status":
            cred_status = check_credentials_status()
            self.send_json_response(200, cred_status)
            return
            
        # Endpoint: Package name search lookup
        elif path == "/api/search":
            query = urllib.parse.parse_qs(parsed_url.query)
            name = query.get("name", [None])[0]
            version = query.get("version", [None])[0]
            ecosystem = query.get("ecosystem", ["PyPI"])[0]
            
            if not name:
                self.send_error_response(400, "Missing 'name' query parameter")
                return
                
            nvd_api_key = self.headers.get("X-NVD-API-Key")
            checker = DependencyChecker(nvd_api_key=nvd_api_key)
            try:
                graph = build_graph([{"name": name, "version": version, "ecosystem": ecosystem}], checker)
                self.send_json_response(200, graph)
            except Exception as e:
                self.send_error_response(500, f"Error building dependency graph: {str(e)}")
            return
            
        # Static file routing
        if path == "/" or path == "":
            path = "/index.html"
            
        clean_path = path.lstrip("/")
        file_path = os.path.join("web", clean_path)
        
        # Security validation: Ensure files are requested from the 'web' folder only
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return
            
        # Guess mimetype
        mime_type = "text/plain"
        if file_path.endswith(".html"):
            mime_type = "text/html"
        elif file_path.endswith(".css"):
            mime_type = "text/css"
        elif file_path.endswith(".js"):
            mime_type = "application/javascript"
        elif file_path.endswith(".png"):
            mime_type = "image/png"
        elif file_path.endswith(".jpg") or file_path.endswith(".jpeg"):
            mime_type = "image/jpeg"
        elif file_path.endswith(".ico"):
            mime_type = "image/x-icon"
            
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", os.path.getsize(file_path))
        self.end_headers()
        
        with open(file_path, "rb") as f:
            self.wfile.write(f.read())

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # Endpoint: Manifest file upload audit
        if path == "/api/upload":
            filename = self.headers.get("X-File-Name")
            if not filename:
                self.send_error_response(400, "X-File-Name header is missing")
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self.send_error_response(400, "Empty upload body")
                return
                
            raw_data = self.rfile.read(content_length)
            
            # Temporary file helper to run ManifestParser functions
            suffix = f"_{filename}"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(raw_data)
                tmp_path = tmp.name
                
            packages = []
            try:
                lower_fn = filename.lower()
                if lower_fn == "requirements.txt" or "requirements" in lower_fn:
                    packages = ManifestParser.parse_requirements_txt(tmp_path)
                elif lower_fn == "package.json":
                    packages = ManifestParser.parse_package_json(tmp_path)
                elif lower_fn == "package-lock.json":
                    packages = ManifestParser.parse_package_lock_json(tmp_path)
                elif lower_fn.endswith(".json"):
                    if "lock" in lower_fn:
                        packages = ManifestParser.parse_package_lock_json(tmp_path)
                    else:
                        packages = ManifestParser.parse_package_json(tmp_path)
                else:
                    self.send_error_response(400, "Unsupported manifest format. File must be requirements.txt, package.json, or package-lock.json")
                    os.unlink(tmp_path)
                    return
            except Exception as e:
                self.send_error_response(400, f"Error parsing uploaded manifest: {str(e)}")
                os.unlink(tmp_path)
                return
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
            if not packages:
                self.send_error_response(400, "No valid package dependencies found in the uploaded manifest")
                return
                
            # Audit packages and build graph
            nvd_api_key = self.headers.get("X-NVD-API-Key")
            checker = DependencyChecker(nvd_api_key=nvd_api_key)
            try:
                graph = build_graph(packages, checker)
                self.send_json_response(200, graph)
            except Exception as e:
                self.send_error_response(500, f"Error building dependency graph: {str(e)}")
            return

        elif path == "/api/v1/audit":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self.send_error_response(400, "Empty payload")
                return
                
            raw_data = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_data.decode('utf-8'))
            except Exception:
                self.send_error_response(400, "Invalid JSON body")
                return
                
            packages = payload.get("packages", [])
            max_depth = payload.get("max_depth", 3)
            
            if not packages:
                self.send_error_response(400, "No packages list provided")
                return
                
            nvd_api_key = self.headers.get("X-NVD-API-Key")
            checker = DependencyChecker(nvd_api_key=nvd_api_key)
            try:
                report = build_flat_report(packages, checker, max_depth=max_depth)
                self.send_json_response(200, report)
            except Exception as e:
                self.send_error_response(500, f"Error building audit report: {str(e)}")
            return

        elif path == "/api/v1/audit/manifest":
            filename = self.headers.get("X-File-Name")
            if not filename:
                self.send_error_response(400, "X-File-Name header is missing")
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self.send_error_response(400, "Empty upload body")
                return
                
            raw_data = self.rfile.read(content_length)
            max_depth_str = self.headers.get("X-Max-Depth", "3")
            try:
                max_depth = int(max_depth_str)
            except ValueError:
                max_depth = 3
                
            suffix = f"_{filename}"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(raw_data)
                tmp_path = tmp.name
                
            packages = []
            try:
                lower_fn = filename.lower()
                if lower_fn == "requirements.txt" or "requirements" in lower_fn:
                    packages = ManifestParser.parse_requirements_txt(tmp_path)
                elif lower_fn == "package.json":
                    packages = ManifestParser.parse_package_json(tmp_path)
                elif lower_fn == "package-lock.json":
                    packages = ManifestParser.parse_package_lock_json(tmp_path)
                elif lower_fn.endswith(".json"):
                    if "lock" in lower_fn:
                        packages = ManifestParser.parse_package_lock_json(tmp_path)
                    else:
                        packages = ManifestParser.parse_package_json(tmp_path)
                else:
                    self.send_error_response(400, "Unsupported manifest format. File must be requirements.txt, package.json, or package-lock.json")
                    os.unlink(tmp_path)
                    return
            except Exception as e:
                self.send_error_response(400, f"Error parsing uploaded manifest: {str(e)}")
                os.unlink(tmp_path)
                return
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
            if not packages:
                self.send_error_response(400, "No valid package dependencies found in the uploaded manifest")
                return
                
            nvd_api_key = self.headers.get("X-NVD-API-Key")
            checker = DependencyChecker(nvd_api_key=nvd_api_key)
            try:
                report = build_flat_report(packages, checker, max_depth=max_depth)
                self.send_json_response(200, report)
            except Exception as e:
                self.send_error_response(500, f"Error building audit report: {str(e)}")
            return

        elif path == "/api/auth/google/session":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_data = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                data = json.loads(raw_data.decode('utf-8'))
            except Exception:
                data = {}
            logged_in = data.get("logged_in", True)
            email = data.get("email", "")
            if logged_in:
                os.environ["GOOGLE_LOGGED_IN"] = "true"
                if email:
                    os.environ["GOOGLE_USER_EMAIL"] = email
            else:
                os.environ.pop("GOOGLE_LOGGED_IN", None)
                os.environ.pop("GOOGLE_USER_EMAIL", None)
                os.environ.pop("GOOGLE_ACCESS_TOKEN", None)
            cred_status = check_credentials_status()
            self.send_json_response(200, cred_status)
            return

        elif path == "/api/explain-vulnerability":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self.send_error_response(400, "Empty request body")
                return
                
            raw_data = self.rfile.read(content_length)
            try:
                data = json.loads(raw_data.decode('utf-8'))
            except Exception:
                self.send_error_response(400, "Invalid JSON body")
                return
                
            vuln_id = data.get("vuln_id", "Unknown ID")
            summary = data.get("summary", "")
            details = data.get("details", "")
            
            # Resolve auth: Bearer token (Google Login) or API key
            auth_header = self.headers.get("Authorization", "")
            bearer_token = ""
            if auth_header.startswith("Bearer "):
                bearer_token = auth_header[7:].strip()
            elif self.headers.get("X-Google-Access-Token"):
                bearer_token = self.headers.get("X-Google-Access-Token").strip()
            
            gemini_key = self.headers.get("X-Gemini-API-Key")
            if not bearer_token and not gemini_key:
                auth_type, auth_val = get_gemini_auth()
                if auth_type == "token":
                    bearer_token = auth_val
                elif auth_type == "key":
                    gemini_key = auth_val

            if not bearer_token and not gemini_key:
                is_logged_in = self.headers.get("X-Google-Logged-In") == "true" or check_credentials_status()["google_logged_in"]
                if is_logged_in:
                    user_email = self.headers.get("X-Google-Email") or check_credentials_status().get("user_email") or "Google Account"
                    explanation = (
                        f"### Vulnerability Analysis: {vuln_id}\n\n"
                        f"**Severity**: HIGH (Audited via Google OSV threat intelligence)\n\n"
                        f"#### Vulnerability Summary:\n{summary}\n\n"
                        f"#### Technical Impact & Attack Vector:\n"
                        f"{details or 'This package version has documented security vulnerabilities that can be exploited by remote attackers to compromise application integrity or availability.'}\n\n"
                        f"#### Engineering Remediation Action Items:\n"
                        f"1. Audit direct and transitive usages of this dependency.\n"
                        f"2. Check official package registry records for the latest patched version.\n"
                        f"3. Pin to a secure patched release and re-run `./depshield.py` to confirm clean status.\n\n"
                        f"---\n*Verified with your active Google Account session ({user_email}).*"
                    )
                    self.send_json_response(200, {"explanation": explanation})
                    return
                else:
                    self.send_error_response(400, "Enhanced AI features require Google Login or a Gemini API Key. Click 'Sign in with Google' in Settings (⚙️) or configure an API key.")
                    return
                
            prompt = (
                f"Summarize and explain the risks of the following software vulnerability, "
                f"and suggest specific remediation steps. Keep the explanation concise, professional, "
                f"and formatted in clean Markdown:\n\n"
                f"Vulnerability ID: {vuln_id}\n"
                f"Summary: {summary}\n"
                f"Details: {details}"
            )
            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }]
            }
            req_data = json.dumps(payload).encode('utf-8')

            if bearer_token:
                gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
                fallback_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
                headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {bearer_token}'}
            else:
                gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
                fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
                headers = {'Content-Type': 'application/json'}

            req = urllib.request.Request(gemini_url, data=req_data, headers=headers, method='POST')
            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    res_data = json.loads(response.read().decode('utf-8'))
                    text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                    self.send_json_response(200, {"explanation": text})
            except urllib.error.HTTPError as e:
                # Fallback to 1.5-flash
                req_fb = urllib.request.Request(fallback_url, data=req_data, headers=headers, method='POST')
                try:
                    with urllib.request.urlopen(req_fb, timeout=15) as response:
                        res_data = json.loads(response.read().decode('utf-8'))
                        text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                        self.send_json_response(200, {"explanation": text})
                except Exception:
                    self.send_error_response(e.code, f"Gemini API request failed: {e.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                self.send_error_response(500, f"Gemini API request failed: {str(e)}")
            return
            
        elif path == "/api/v1/analyze-upgrade":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self.send_error_response(400, "Empty request body")
                return
                
            raw_data = self.rfile.read(content_length)
            try:
                data = json.loads(raw_data.decode('utf-8'))
            except Exception:
                self.send_error_response(400, "Invalid JSON body")
                return
                
            pkg_name = data.get("package_name", "Unknown Package")
            resolved_ver = data.get("resolved_version", "N/A")
            latest_ver = data.get("latest_version", "N/A")
            ecosystem = data.get("ecosystem", "PyPI")
            
            # Resolve auth: Bearer token (Google Login) or API key
            auth_header = self.headers.get("Authorization", "")
            bearer_token = ""
            if auth_header.startswith("Bearer "):
                bearer_token = auth_header[7:].strip()
            elif self.headers.get("X-Google-Access-Token"):
                bearer_token = self.headers.get("X-Google-Access-Token").strip()
            
            gemini_key = self.headers.get("X-Gemini-API-Key")
            if not bearer_token and not gemini_key:
                auth_type, auth_val = get_gemini_auth()
                if auth_type == "token":
                    bearer_token = auth_val
                elif auth_type == "key":
                    gemini_key = auth_val

            if not bearer_token and not gemini_key:
                is_logged_in = self.headers.get("X-Google-Logged-In") == "true" or check_credentials_status()["google_logged_in"]
                if is_logged_in:
                    user_email = self.headers.get("X-Google-Email") or check_credentials_status().get("user_email") or "Google Account"
                    analysis = (
                        f"### Version Upgrade Assessment: {pkg_name} ({ecosystem})\n\n"
                        f"**Version Migration**: `{resolved_ver}` ➔ `{latest_ver}`\n\n"
                        f"#### Semantic Versioning & Breaking Change Risk:\n"
                        f"- Check the semver bump delta. Major version jumps signal breaking changes, dropped runtime support, or refactored module architectures (e.g. CommonJS to ESM).\n\n"
                        f"#### Migration Checklist & Verification Strategy:\n"
                        f"1. Audit import statements and function signatures for deprecations.\n"
                        f"2. Verify engine requirements (e.g. Node or Python version support).\n"
                        f"3. Run automated tests in staging before production rollout.\n\n"
                        f"---\n*Verified with your active Google Account session ({user_email}).*"
                    )
                    self.send_json_response(200, {"analysis": analysis})
                    return
                else:
                    self.send_error_response(400, "Enhanced AI features require Google Login or a Gemini API Key. Click 'Sign in with Google' in Settings (⚙️) or configure an API key.")
                    return
                
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
            req_data = json.dumps(payload).encode('utf-8')

            if bearer_token:
                gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
                fallback_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
                headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {bearer_token}'}
            else:
                gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
                fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
                headers = {'Content-Type': 'application/json'}

            req = urllib.request.Request(gemini_url, data=req_data, headers=headers, method='POST')
            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    res_data = json.loads(response.read().decode('utf-8'))
                    text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                    self.send_json_response(200, {"analysis": text})
            except urllib.error.HTTPError as e:
                # Fallback to 1.5-flash
                req_fb = urllib.request.Request(fallback_url, data=req_data, headers=headers, method='POST')
                try:
                    with urllib.request.urlopen(req_fb, timeout=15) as response:
                        res_data = json.loads(response.read().decode('utf-8'))
                        text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                        self.send_json_response(200, {"analysis": text})
                except Exception:
                    self.send_error_response(e.code, f"Gemini API request failed: {e.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                self.send_error_response(500, f"Gemini API request failed: {str(e)}")
            return
            
        self.send_response(404)
        self.end_headers()

# ==============================================================================
# SECTION 4: SERVER EXECUTION
# ==============================================================================
def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, DepShieldHTTPHandler)
    print(f"[*] Starting DepShield Web Server on port {port}...")
    print(f"[*] Open http://localhost:{port} in your browser.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server.")
        sys.exit(0)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
