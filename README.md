# DepShield User Guide
### *Platform-Independent Software & Dependency Supply Chain Security Auditor*

DepShield is a lightweight, zero-dependency command-line utility designed to check software dependency manifests *prior to installation*. It audits package metadata, matches installed local versions, validates archive checksums, checks publication ages, and queries vulnerability databases to safeguard environments against open-source supply chain attacks.

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

## 🛠️ Commands & Usage Syntax

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
* `-f`, `--file <path>`: Path to a local package archive (e.g. `.whl`, `.tgz`, `.zip`) to verify checksum integrity against registry records.
* `-o`, `--output-dir <path>`: Directory where Markdown and HTML audit reports will be saved (default: `.`).
* `--html-name <filename>`: Custom filename for the HTML report (default: `depshield_report.html`).
* `--md-name <filename>`: Custom filename for the Markdown report (default: `depshield_report.md`).
* `--current-date <YYYY-MM-DD>`: Simulated current date used to compute release ages (default: `2026-06-16`). Useful for testing historical package lists or reproducible pipeline builds.

---

## 💡 Example CLI Executions

### Example A: Basic Manifest Scan
Audit all packages listed in a Node.js manifest and check for vulnerabilities:
```bash
./depshield.py test_package.json -o ./reports
```

### Example B: Local Archive Integrity Verification
Validate that a downloaded package archive matches the official hashes reported by the upstream registry before installing it:
```bash
./depshield.py test_package.json -f lodash-4.17.21.tgz -o ./reports
```
*DepShield will automatically extract the package name and version from the file path, compute its SHA1, SHA256, and SHA512 hashes, and verify them against npm registry records.*

### Example C: Simulating Run Dates
Audit a Python manifest relative to a historical or target date:
```bash
./depshield.py test_requirements.txt --current-date 2026-06-16 -o ./reports
```

---

## 📊 Understanding Risk Levels & Exit Codes

DepShield evaluates package risks and exits with a shell code indicating the severity level:

| Exit Code | Risk Level | Description | Action Item |
| :---: | :---: | :---: | :---: |
| `0` | **LOW** / **MEDIUM** | Standard scan completed. No active threats or checksum failures found. | Safe to install. (Review warnings if any releases are <10 days old). |
| `2` | **HIGH** | Resolved versions contain known CVEs or GitHub security advisories. | **HOLD DEPLOYMENT**. Upgrade packages to a patched release. |
| `3` | **CRITICAL** | Integrity failure. A checked file's hash does not match registry records. | **ABORT INSTALLATION**. A mismatch indicates tampering or cache corruption. |

---

## 📝 Generated Audit Reports

DepShield produces two administrative documents in the designated `--output-dir`:

1. **Markdown Report (`depshield_report.md`)**:
   * Designed for terminal output rendering, GitHub PR integrations, or build log outputs.
   * Employs GitHub-style alert callouts (`[!WARNING]`, `[!CAUTION]`).
   * Incorporates CVSS scores from NIST NVD.
2. **HTML Dashboard (`depshield_report.html`)**:
   * A premium, self-contained interactive webpage.
   * Utilizes modern dark-mode layouts, glassmorphic card panels, pulsing alarm animations for security failures, and expandable CVE detail cards.

---

## 🧪 Running Automated Tests
The package includes a comprehensive unit testing suite using Python's standard `unittest` framework:
```bash
python3 test_depshield.py
```
This suite automatically tests requirements parsing, npm package.json/lockfile reading, file hash calculations, and validates live connection handlers to the PyPI, npm, OSV, and NIST NVD REST API endpoints.
