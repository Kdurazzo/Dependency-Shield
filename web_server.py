#!/usr/bin/env python3
import os
import sys
import json
import re
import tempfile
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from parsers import ManifestParser
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
            
            gemini_key = self.headers.get("X-Gemini-API-Key")
            if not gemini_key:
                self.send_error_response(400, "Gemini API Key is missing. Please configure it in Settings (⚙️) at the top of the page.")
                return
                
            gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
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
            req = urllib.request.Request(
                gemini_url,
                data=req_data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    res_data = json.loads(response.read().decode('utf-8'))
                    text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                    self.send_json_response(200, {"explanation": text})
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
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
