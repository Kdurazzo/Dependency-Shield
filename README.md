# DepShield User Guide
### *Platform-Independent Software & Dependency Supply Chain Security Auditor*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

DepShield is a lightweight, zero-dependency security auditor designed to check software dependency manifests *prior to installation*. It audits package metadata, validates local versions, validates archive checksums, checks publication ages, queries vulnerability databases, and features an interactive web visualization dashboard with Gemini AI vulnerability remediation and upgrade planning.

---

## 💻 Platform Compatibility
* **Supported Platforms**: macOS, Linux, Windows.
* **Strict Exclusions**: OS/2 (Execution will immediately abort with exit code `1987` if OS/2 is detected).

---

## ⚙️ Prerequisites
* **Python 3.8+** must be installed.
* **Zero Dependencies**: DepShield relies entirely on Python's standard libraries (`urllib`, `hashlib`, `json`, `importlib.metadata`). No external packages or libraries (like `requests` or `pytest`) are required to audit, ensuring the auditing tool itself remains clean and secure.

---

## 🛡️ Vulnerability Data Sources
DepShield aggregates advisory information from two secure, reliable feeds:
1. **Google OSV (Open Source Vulnerabilities) Database**: High-performance JSON endpoint matching open-source ecosystems (PyPI, npm) and resolving specific package names/versions.
2. **NIST NVD (National Vulnerability Database) REST API v2.0**: Official US Government CVE repository. DepShield queries NVD using matched CVE-IDs to retrieve official **CVSS severity scores** (e.g. `[7.5 (HIGH)]`) and authoritative descriptions.
   * *NVD API Key*: NIST recommends using an API key to avoid strict rate limiting. Set your key in the `NVD_API_KEY` environment variable prior to execution.

---

## 🚀 Installation & Quick Start

1. Navigate to the project directory:
   ```bash
   cd Dependency-Checker
   ```
2. Make the CLI script executable:
   ```bash
   chmod +x depshield.py
   ```
3. Run a test audit on a sample python manifest:
   ```bash
   export NVD_API_KEY="your-api-key"
   ./depshield.py test_requirements.txt -o ./reports
   ```

---

## 🛠️ CLI Commands & Usage Syntax

```bash
./depshield.py <manifest_file> [options]
```

### 1. Positionals
* `manifest_file` *(Required)*: Path to the package manifest file.
  * Supported manifest filenames:
    * `requirements.txt` (Python/pip package list)
    * `package.json` (Node.js/npm dependencies list)
    * `package-lock.json` (Node.js pinned lockfile)

### 2. Options
* `-j`, `--json`: Print audit results as a flat JSON report directly to standard output instead of creating report files. Ideal for CI/CD pipeline scripting.
* `-f`, `--file <path>`: Path to a local package archive (e.g. `.whl`, `.tgz`, `.zip`) to verify checksum integrity against registry records.
* `-o`, `--output-dir <path>`: Directory where Markdown and HTML audit reports will be saved (default: `.`).
* `--html-name <filename>`: Custom filename for the HTML report (default: `depshield_report.html`).
* `--md-name <filename>`: Custom filename for the Markdown report (default: `depshield_report.md`).
* `--current-date <YYYY-MM-DD>`: Simulated current date used to compute release ages (default: `2026-06-16`). Useful for testing historical package lists.

---

## 🐳 Containerized Standalone CLI Execution
If you do not have Python installed on your host system, run audits inside a zero-host-dependency Docker container using our launcher utility scripts.

### macOS/Linux:
```bash
./run_cli.sh test_requirements.txt -o ./reports
```

### Windows:
```cmd
run_cli.bat test_requirements.txt -o .\reports
```

---

## 🖥️ Interactive Web Dashboard
DepShield includes a premium Glassmorphism-style dashboard running entirely on standard Python server handlers. 

### Starting the Server
Start the local server (defaults to port `8080`):
```bash
python3 web_server.py
```
Or run via Docker Compose:
```bash
docker-compose up
```
Open [http://localhost:8080](http://localhost:8080) in your browser.

### Key Web Features:
- **D3 Force-Directed Link Graph:** Interactive, draggable visual dependency graph. Vulnerable nodes glow orange/red; tampered checksum packages flash.
- **Dynamic API Key Config (⚙️):** Paste your personal NVD database key or Gemini AI key through the Settings panel. Keys are stored safely in `localStorage` and never hardcoded.
- **Gemini AI Explainer Drawer:** Click any vulnerable package node to open detail advisories, then click `Explain with Gemini AI` to generate custom remediation and risk analyses.
- **Gemini AI Upgrade Advisor:** Displays warnings when package resolved versions are outdated compared to the registry latest release (e.g. `minimatch 3.0.0` vs. `10.2.5`). Click `Analyze Upgrade with Gemini` to check for upgrade risks and migration paths.

---

## 🔌 Programmatic REST API Layer
Other applications, CI/CD tools, or backend scripts can query the web server programmatically:

### 1. `POST /api/v1/audit`
Pass a flat JSON list of packages to audit:
- **Body JSON:**
  ```json
  {
    "packages": [
      {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
    ],
    "max_depth": 3
  }
  ```
- **Response JSON:** Returns a summarized flat audit log containing `risk_level`, `vulnerabilities_count`, and a `packages` metadata array.

### 2. `POST /api/v1/audit/manifest`
Submit a raw manifest text body. Include the `X-File-Name` header (e.g., `X-File-Name: requirements.txt`) to define the parser format.

### 3. `POST /api/v1/v1/analyze-upgrade`
Consult Gemini regarding version upgrades.
- **Body JSON:**
  ```json
  {
    "package_name": "minimatch",
    "resolved_version": "3.0.0",
    "latest_version": "10.2.5",
    "ecosystem": "npm"
  }
  ```
- **Response JSON:** `{"analysis": "Markdown string explaining risks and upgrade path"}`

---

## 🤖 Model Context Protocol (MCP) Server Setup
To configure AI coding assistants (like Gemini, Claude, or cursor-agent) to perform dependency audits in your active workspace, point them to our stdin/stdout JSON-RPC server.

Add this entry to your agent config file:
```json
{
  "mcpServers": {
    "depshield": {
      "command": "python3",
      "args": ["/path/to/Dependency-Checker/mcp_server.py"]
    }
  }
}
```

### Exposed MCP Tools & Recommended Invocation Order:
1. **`audit_manifest(path, max_depth)`** *(Step 1 - Project Discovery)*: Audits local manifest files recursively across the workspace for CVEs, release age, and checksum tampering.
2. **`audit_package(name, version, ecosystem, max_depth)`** *(Step 2 - Deep Dive)*: Deep-dive vulnerability and integrity inspection on an individual dependency.
3. **`analyze_upgrade(package_name, resolved_version, latest_version, ecosystem)`** *(Step 3 - Safe Migration)*: Evaluates breaking change risks, semver deprecations, and upgrade plans via Gemini AI.

*See the full [MCP Agent Integration Guide](docs/MCP_GUIDE.md) for workflow diagrams, schema specifications, and Claude/Cursor recipes.*

---

## 📊 Understanding Risk Levels & Exit Codes

DepShield evaluates package risks and exits with a shell code indicating the severity level:

| Exit Code | Risk Level | Description | Action Item |
| :---: | :---: | :---: | :---: |
| `0` | **LOW** / **MEDIUM** | Standard scan completed. No active threats or checksum failures found. | Safe to install. (Review warnings if any releases are <10 days old). |
| `2` | **HIGH** | Resolved versions contain known CVEs or GitHub security advisories. | **HOLD DEPLOYMENT**. Upgrade packages to a patched release. |
| `3` | **CRITICAL** | Integrity failure. A checked file's hash does not match registry records. | **ABORT INSTALLATION**. A mismatch indicates tampering or cache corruption. |

---

## 🧪 Running Automated Tests
The package includes a comprehensive unit testing suite using Python's standard `unittest` framework:
```bash
python3 test_depshield.py
```
This suite automatically tests requirements parsing, npm package.json/lockfile reading, file hash calculations, REST API handlers, and validates live connection handlers to upstream endpoints.

---

## 🐳 Modular Docker Infrastructure & Factory Reset

DepShield includes a complete multi-container Docker environment modeled after the [LiteGraph Docker architecture](https://github.com/litegraphdb/litegraph/tree/main/docker):

- **Backend Service** (`depshield-backend` on port `8000`): Dedicated Python API service.
- **Dashboard Service** (`depshield-dashboard` on port `8080`): Alpine Nginx reverse proxy hosting the Glassmorphism frontend and routing `/api/*` to the backend.
- **Persisted Directories**: Pre-configured `docker/data/`, `docker/reports/`, and `docker/logs/` volumes.
- **Factory Reset System** (`docker/factory/`): Run `./reset.sh` (macOS/Linux) or `reset.bat` (Windows) to restore the environment to clean-install state.

Quick start:
```bash
cd docker
docker compose up -d
```
*Detailed documentation: [Docker User Guide](docker/README.md).*

---

## 📮 Postman Collection & REST API Reference

For third-party integrators and QA teams:
- **Postman Collection v2.1**: [`postman/DepShield_API.postman_collection.json`](postman/DepShield_API.postman_collection.json). Fully documented with variable support (`baseUrl`, `nvdApiKey`, `geminiApiKey`) and saved example responses for every endpoint.
- **Comprehensive API Reference**: [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md). Full surface area specification with cURL, Python, and fetch usage examples across all endpoints.

---

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for full details.
