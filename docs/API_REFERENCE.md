# DepShield REST API Integration Reference

This document provides a comprehensive command and usage specification for third-party clients, CI/CD pipelines, and external applications integrating with **DepShield** ([Dependency-Checker](https://github.com/Kdurazzo/Dependency-Checker)).

---

## 🌐 Base URLs & Architecture

DepShield services can be accessed either directly via the backend API or through the reverse-proxying dashboard container:

| Environment | Base URL | Protocol | Description |
| :--- | :--- | :--- | :--- |
| **Direct Backend Engine** | `http://localhost:8000` | HTTP | Native Python REST and graph audit engine. Recommended for machine-to-machine, automated CI/CD runners, and backend services. |
| **Dashboard Reverse Proxy** | `http://localhost:8080` | HTTP | Alpine Nginx container serving the interactive frontend and routing all `/api/*` requests directly to backend. |

---

## 🔑 Authentication & Request Headers

DepShield operates in zero-trust isolation without requiring proprietary tokens. Third-party authentication keys are passed per-request:

| Header | Required | Type | Description |
| :--- | :--- | :--- | :--- |
| `Content-Type` | Dependent | String | Set to `application/json` for JSON endpoints or `text/plain` for raw manifest submissions. |
| `Authorization` | Optional | String | `Bearer <google_access_token>`. If you have access to Google Gemini, signing in with your Google account is sufficient to unlock all AI capabilities with no API key needed! |
| `X-Google-Logged-In` | Optional | String | Set to `true` to indicate an active browser or environment Google account session. Unlocks Gemini AI features immediately without manual keys. |
| `X-Google-Email` | Optional | String | User's Google Account email identifier associated with the active session (e.g. `developer@example.com`). |
| `X-Gemini-API-Key` | Optional | String | Google AI Studio Gemini API Key ([Get one here](https://aistudio.google.com/)). Alternative to Google Login. |
| `X-NVD-API-Key` | Optional | String | NIST NVD REST API Key ([Request one here](https://nvd.nist.gov/developers/request-an-api-key)). Bypasses NIST IP rate limits (5 requests/30s without key vs 50 requests/30s with key). |
| `X-File-Name` | Conditional | String | Required when posting raw manifests to `/api/upload` or `/api/v1/audit/manifest` (e.g. `requirements.txt`, `package.json`, `package-lock.json`). |

---

## 📚 API Surface Area & Endpoints

### 1. Health Check

#### `GET /api/health`
Quick liveness and readiness probe for orchestration platforms (Kubernetes, Docker, Nomad) and monitoring agents.

##### Request:
```bash
curl -X GET http://localhost:8000/api/health
```

##### Python:
```python
import urllib.request
import json

with urllib.request.urlopen("http://localhost:8000/api/health") as resp:
    data = json.loads(resp.read().decode())
    print(data)  # {"status": "ok"}
```

##### Response (`200 OK`):
```json
{
  "status": "ok"
}
```

---

### 2. Search Package Dependency Graph

#### `GET /api/search`
Searches for a specific package in the PyPI or npm ecosystem, builds a dependency graph resolving direct and transitive dependencies up to recursion limits, and returns a D3 force-directed graph node-and-link model.

##### Query Parameters:
| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `name` | String | **Yes** | - | Package name (e.g., `requests`, `lodash`, `django`). |
| `version` | String | No | Latest | Specific version string (e.g., `4.17.20`). If omitted, resolves to latest release. |
| `ecosystem` | String | No | `PyPI` | Target package repository: `PyPI` or `npm`. |

##### Request:
```bash
curl -X GET "http://localhost:8000/api/search?name=lodash&version=4.17.20&ecosystem=npm" \
  -H "X-NVD-API-Key: your-nvd-api-key"
```

##### Response (`200 OK`):
```json
{
  "nodes": [
    {
      "id": "lodash@4.17.20",
      "name": "lodash",
      "version": "4.17.20",
      "ecosystem": "npm",
      "vulnerable": true,
      "tampered": false,
      "age_days": 1380,
      "is_outdated": true,
      "latest_version": "4.17.21",
      "vulnerabilities": [
        {
          "id": "GHSA-35jh-r3h4-6jhm",
          "aliases": ["CVE-2021-23337"],
          "summary": "Command Injection in lodash",
          "severity": "HIGH",
          "cvss_score": 7.3
        }
      ]
    }
  ],
  "links": []
}
```

---

### 3. Upload Manifest (Graph Representation)

#### `POST /api/upload`
Accepts a raw dependency manifest string and parses all declared packages into an interactive graph model suitable for visual dashboard renderers.

##### Headers:
- `Content-Type: text/plain`
- `X-File-Name: requirements.txt` (or `package.json`, `package-lock.json`)
- `X-NVD-API-Key: <optional>`

##### Request:
```bash
curl -X POST http://localhost:8000/api/upload \
  -H "Content-Type: text/plain" \
  -H "X-File-Name: requirements.txt" \
  --data-binary $'requests==2.25.1\nurllib3==1.26.4\n'
```

##### Response (`200 OK`):
```json
{
  "nodes": [
    {
      "id": "requests@2.25.1",
      "name": "requests",
      "version": "2.25.1",
      "ecosystem": "PyPI",
      "vulnerable": true,
      "tampered": false,
      "vulnerabilities": [
        {
          "id": "GHSA-j8r2-6x86-q33q",
          "aliases": ["CVE-2023-32681"],
          "summary": "Unintended leak of Proxy-Authorization header in requests",
          "severity": "MEDIUM",
          "cvss_score": 6.1
        }
      ]
    },
    {
      "id": "urllib3@1.26.4",
      "name": "urllib3",
      "version": "1.26.4",
      "ecosystem": "PyPI",
      "vulnerable": false,
      "tampered": false
    }
  ],
  "links": [
    {
      "source": "requests@2.25.1",
      "target": "urllib3@1.26.4"
    }
  ]
}
```

---

### 4. Batch Package Audit (JSON)

#### `POST /api/v1/audit`
Programmatic entry point for CI/CD scanners and automated security gates. Accepts an explicit array of packages, audits them against Google OSV and NIST NVD, resolves transitive dependencies, and returns a flat JSON report with risk categorization.

##### Request Body Schema:
```json
{
  "packages": [
    {
      "name": "string (required)",
      "version": "string (optional)",
      "ecosystem": "PyPI | npm (required)"
    }
  ],
  "max_depth": 3
}
```

##### Request:
```bash
curl -X POST http://localhost:8000/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{
    "packages": [
      {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
      {"name": "urllib3", "version": "1.26.4", "ecosystem": "PyPI"}
    ],
    "max_depth": 2
  }'
```

##### Response (`200 OK`):
```json
{
  "risk_level": "HIGH",
  "verdict": "NOT_ADVISABLE",
  "policy_reasons": [
    "High/Critical risk packages exceed threshold: 50.0% RED (limit 30.0%).",
    "Combined risk (RED + YELLOW) exceeds safety threshold: 50.0% (limit 50.0%).",
    "Affected high-risk packages (1): lodash@4.17.20."
  ],
  "policy_metrics": {
    "total_count": 2,
    "red_count": 1,
    "yellow_count": 0,
    "green_count": 1,
    "young_count": 0,
    "red_pct": 0.5,
    "yellow_pct": 0.0,
    "green_pct": 0.5,
    "combined_risk_pct": 0.5
  },
  "total_packages": 2,
  "vulnerabilities_count": 1,
  "recent_packages_count": 0,
  "checksum_failures_count": 0,
  "credentials_setup": {
    "gemini_configured": false,
    "nvd_configured": false,
    "setup_instructions": "Run 'depshield.py --setup' to configure personal credentials"
  },
  "packages": [
    {
      "name": "lodash",
      "ecosystem": "npm",
      "requested_version": "4.17.20",
      "resolved_version": "4.17.20",
      "release_date": "2020-08-13",
      "age_days": 2228,
      "risk": "high",
      "risk_color": "RED",
      "is_young": false,
      "vulnerabilities": [
        {
          "id": "GHSA-35jh-r3h4-6jhm",
          "aliases": ["CVE-2021-23337"],
          "summary": "[7.2 (HIGH)] Command Injection in lodash",
          "severity": "HIGH",
          "cvss_score": 7.2
        }
      ]
    },
    {
      "name": "urllib3",
      "ecosystem": "PyPI",
      "requested_version": "1.26.4",
      "resolved_version": "1.26.4",
      "release_date": "2021-03-15",
      "age_days": 1950,
      "risk": "low",
      "risk_color": "GREEN",
      "is_young": false,
      "vulnerabilities": []
    }
  ]
}
```

---

### 5. Audit Raw Manifest File

#### `POST /api/v1/audit/manifest`
Submits raw manifest file text and outputs the flat JSON bill-of-materials security report.

##### Request:
```bash
curl -X POST http://localhost:8000/api/v1/audit/manifest \
  -H "Content-Type: text/plain" \
  -H "X-File-Name: requirements.txt" \
  --data-binary $'requests==2.25.1\nflask==1.1.2\n'
```

##### Response (`200 OK`):
```json
{
  "risk_level": "HIGH",
  "verdict": "NOT_ADVISABLE",
  "policy_reasons": [
    "High/Critical risk packages exceed threshold: 50.0% RED (limit 30.0%).",
    "Combined risk (RED + YELLOW) exceeds safety threshold: 50.0% (limit 50.0%).",
    "Affected high-risk packages (1): requests@2.25.1."
  ],
  "policy_metrics": {
    "total_count": 2,
    "red_count": 1,
    "yellow_count": 0,
    "green_count": 1,
    "young_count": 0,
    "red_pct": 0.5,
    "yellow_pct": 0.0,
    "green_pct": 0.5,
    "combined_risk_pct": 0.5
  },
  "total_packages": 2,
  "vulnerabilities_count": 1,
  "recent_packages_count": 0,
  "checksum_failures_count": 0,
  "credentials_setup": {
    "gemini_configured": false,
    "nvd_configured": false,
    "setup_instructions": "Run 'depshield.py --setup' to configure personal credentials"
  },
  "packages": [ ... ]
}
```

---

### 6. Analyze Version Upgrade with Gemini AI

#### `POST /api/v1/analyze-upgrade`
Consults Google Gemini AI to evaluate breaking changes, API signature removals, and runtime migration risks when upgrading a package between versions.

##### Headers:
- `Content-Type: application/json`
- `X-Gemini-API-Key: your-gemini-api-key` *(Required)*

##### Request Body Schema:
```json
{
  "package_name": "minimatch",
  "resolved_version": "3.0.0",
  "latest_version": "10.2.5",
  "ecosystem": "npm"
}
```

##### Request:
```bash
curl -X POST http://localhost:8000/api/v1/analyze-upgrade \
  -H "Content-Type: application/json" \
  -H "X-Gemini-API-Key: $GEMINI_API_KEY" \
  -d '{
    "package_name": "minimatch",
    "resolved_version": "3.0.0",
    "latest_version": "10.2.5",
    "ecosystem": "npm"
  }'
```

##### Response (`200 OK`):
```json
{
  "analysis": "### Minimatch Upgrade Risk Assessment (v3.0.0 -> v10.2.5)\n\n**Risk Level:** HIGH\n\n#### Breaking Changes:\n1. **Engine Compatibility**: Minimatch v10 dropped support for Node.js < 18.\n2. **Module System**: Package was refactored from CommonJS exports to pure ECMAScript Modules (ESM).\n3. **Pattern Matching Strictness**: Glob star handling now strictly validates directory boundary matching.\n\n#### Step-by-Step Upgrade Checklist:\n1. Verify Node.js runtime is >= v18.\n2. Audit usages of `minimatch.filter` for signature changes.\n3. Run integration tests in staging prior to production deployment."
}
```

---

### 7. Explain Vulnerability with Gemini AI

#### `POST /api/explain-vulnerability`
Generates an executive advisory and code remediation summary for a CVE using Google Gemini AI.

##### Headers:
- `Content-Type: application/json`
- `X-Gemini-API-Key: your-gemini-api-key` *(Required)*

##### Request Body Schema:
```json
{
  "vuln_id": "CVE-2021-23337",
  "summary": "Command Injection in lodash via template function",
  "details": "The package lodash prior to 4.17.21 is vulnerable to Command Injection via template."
}
```

##### Request:
```bash
curl -X POST http://localhost:8000/api/explain-vulnerability \
  -H "Content-Type: application/json" \
  -H "X-Gemini-API-Key: $GEMINI_API_KEY" \
  -d '{
    "vuln_id": "CVE-2021-23337",
    "summary": "Command Injection in lodash via template function",
    "details": "The package lodash prior to 4.17.21 is vulnerable to Command Injection."
  }'
```

##### Response (`200 OK`):
```json
{
  "explanation": "### Vulnerability Analysis: CVE-2021-23337\n\n**Severity:** HIGH (CVSS 7.3)\n\n#### Description:\nAn attacker can execute arbitrary operating system commands if untrusted user input is passed directly into `lodash.template` without sanitization.\n\n#### Remediation:\nUpgrade `lodash` to version `4.17.21` or later where the template compilation sandbox has been hardened."
}
```

---

### 8. Get Authentication & Credential Status

#### `GET /api/auth/google/status`
Returns configuration and login status across all integrated sources (Google Account, Gemini AI, NIST NVD, and Google OSV).

##### Request:
```bash
curl -X GET http://localhost:8000/api/auth/google/status
```

##### Response (`200 OK`):
```json
{
  "gemini_configured": true,
  "google_logged_in": true,
  "user_email": "developer@example.com",
  "auth_type": "google_session",
  "enhanced_features_available": true,
  "nvd_configured": false,
  "osv_configured": true,
  "unauthenticated_mode": false
}
```

---

### 9. Synchronize Google Session State

#### `POST /api/auth/google/session`
Synchronizes the active Google Account login session state between client frontends and the backend environment.

##### Request Body Schema:
```json
{
  "logged_in": true,
  "email": "developer@example.com"
}
```

##### Request:
```bash
curl -X POST http://localhost:8000/api/auth/google/session \
  -H "Content-Type: application/json" \
  -d '{
    "logged_in": true,
    "email": "developer@example.com"
  }'
```

##### Response (`200 OK`):
```json
{
  "gemini_configured": true,
  "google_logged_in": true,
  "user_email": "developer@example.com",
  "auth_type": "google_session",
  "enhanced_features_available": true,
  "nvd_configured": false,
  "osv_configured": true,
  "unauthenticated_mode": false
}
```

---

## 📮 Postman Collection

A fully documented Postman Collection v2.1 is included in [`postman/DepShield_API.postman_collection.json`](../postman/DepShield_API.postman_collection.json).

### Importing into Postman:
1. Open Postman.
2. Click **Import** in the upper-left navigation bar.
3. Drag and drop `postman/DepShield_API.postman_collection.json`.
4. Click the collection name in your sidebar and select the **Variables** tab.
5. Set:
   - `baseUrl` -> `http://localhost:8000` (or `http://localhost:8080`)
   - `nvdApiKey` -> your NIST NVD key
   - `geminiApiKey` -> your Google Gemini key
6. Execute requests individually or run the collection through Newman / Postman Collection Runner!
