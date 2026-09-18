# DepShield Model Context Protocol (MCP) Agent Guide

This guide provides operational instructions, tool schemas, recommended invocation sequences, and integration recipes for AI coding assistants (such as **Antigravity**, **Claude Desktop**, and **Cursor**) interacting with the **DepShield MCP Server** (`mcp_server.py`).

---

## 🤖 MCP Tool Inventory & Purpose

DepShield exposes three primary tools designed to guide an AI agent through a complete dependency security audit and remediation lifecycle:

| Tool Name | Scope | Primary Purpose |
| :--- | :--- | :--- |
| **`audit_manifest`** | Workspace File | Broad bill-of-materials audit of an entire repository manifest (`requirements.txt`, `package.json`, `package-lock.json`). Traverses direct and transitive dependencies. |
| **`audit_package`** | Individual Package | Deep-dive vulnerability, publication age, and registry checksum inspection on an individual dependency. |
| **`analyze_upgrade`** | Version Delta | Synthesizes breaking change risks, deprecations, and a safe migration plan when upgrading between package versions. |

---

## 🔄 Recommended Invocation Order & Workflows

To achieve reliable, reproducible dependency security reviews, AI agents should follow structured call patterns based on the user's objective:

### Workflow 1: Repository Security Audit & Remediation (Standard)

```
   ┌────────────────────────────────────────────────────────┐
   │ [STEP 1] audit_manifest(path="requirements.txt")       │
   │ Discover all direct & transitive CVEs across the repo. │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │ [STEP 2] audit_package(name="vulnerable_pkg", ...)     │
   │ Deep dive into high-severity or tampered packages.     │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │ [STEP 3] analyze_upgrade(name="...", cur="...", ...)   │
   │ Synthesize breaking change risks before version bumps. │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │ [STEP 4] Apply code edits & update manifest            │
   │ Verify build passes with the updated dependency.       │
   └────────────────────────────────────────────────────────┘
```

#### Why this order matters:
1. **Breadth-First Discovery (`audit_manifest`)**: Never start by guessing individual package names. Running `audit_manifest` provides an authoritative inventory of all declared dependencies and flags known CVEs, outdated versions, and checksum mismatches in a single pass.
2. **Root-Cause Isolation (`audit_package`)**: If `audit_manifest` reveals that a transitive dependency is vulnerable (e.g. `requests -> urllib3`), invoking `audit_package` on `urllib3` reveals whether bumping `requests` or pinning `urllib3` directly is the safest path forward.
3. **Preventing Breakage (`analyze_upgrade`)**: Bumping a major dependency version blindly can break APIs or remove expected classes. Invoking `analyze_upgrade` ensures the agent reviews semver hazards and follows a structured upgrade strategy before writing code modifications.

---

### Workflow 2: Pre-Installation Package Evaluation

When a user asks: *"Can we use package X in our project?"* or *"Is package X safe to install?"*:

1. **Step 1: Invoke `audit_package(name="X", ecosystem="PyPI")`**:
   - Inspect `vulnerable` status, CVE list, publication age (detects brand-new/hallucinated typosquatting packages), and latest version.
2. **Step 2: Decision Gate**:
   - If vulnerabilities exist, evaluate whether a newer patched version exists.
   - If release age is < 7 days, advise caution regarding supply chain tamper risk.
3. **Step 3: Recommend Manifest Entry**:
   - Present the safe, pinned version to the user.

---

### Workflow 3: Outdated Dependency Modernization

When updating legacy projects or resolving deprecation warnings:

1. **Step 1: Invoke `audit_manifest(path="package.json")`**:
   - Identify packages with `is_outdated: true`.
2. **Step 2: For each outdated package, invoke `analyze_upgrade(...)`**:
   - Evaluate major vs minor version delta.
   - Check if breaking changes affect the user's specific codebase patterns.
3. **Step 3: Generate Remediation Plan**:
   - Provide the user with an incremental migration plan, prioritizing patch/minor updates before tackling major breaking changes.

---

## 🛠️ Tool Specifications & Parameter Reference

### 1. `audit_manifest`

Reads and audits a software dependency manifest file inside the workspace.

#### Input Schema:
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute filesystem path to manifest (e.g. /workspace/requirements.txt)"
    },
    "max_depth": {
      "type": "number",
      "description": "Maximum recursion depth for transitive dependencies (default: 3, set to 1 for direct-only)"
    },
    "nvd_api_key": {
      "type": "string",
      "description": "Optional NIST NVD API key to avoid rate limiting"
    }
  },
  "required": ["path"]
}
```

#### Example Call:
```json
{
  "name": "audit_manifest",
  "arguments": {
    "path": "/path/to/project/requirements.txt",
    "max_depth": 2
  }
}
```

---

### 2. `audit_package`

Deep-dive audit for an individual package.

#### Input Schema:
```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Package name (e.g. 'lodash', 'requests')"
    },
    "version": {
      "type": "string",
      "description": "Optional version string. Defaults to latest registry release."
    },
    "ecosystem": {
      "type": "string",
      "enum": ["PyPI", "npm"],
      "description": "Target ecosystem: 'PyPI' or 'npm' (default: PyPI)"
    },
    "max_depth": {
      "type": "number",
      "description": "Maximum recursion depth for transitive dependencies (default: 3)"
    }
  },
  "required": ["name"]
}
```

#### Example Call:
```json
{
  "name": "audit_package",
  "arguments": {
    "name": "lodash",
    "version": "4.17.20",
    "ecosystem": "npm",
    "max_depth": 1
  }
}
```

---

### 3. `analyze_upgrade`

Assesses breaking change risks and upgrade paths using Gemini AI or structured semver models.

#### Input Schema:
```json
{
  "type": "object",
  "properties": {
    "package_name": {
      "type": "string",
      "description": "Name of package (e.g. 'minimatch')"
    },
    "resolved_version": {
      "type": "string",
      "description": "Currently pinned version (e.g. '3.0.0')"
    },
    "latest_version": {
      "type": "string",
      "description": "Target version to upgrade to (e.g. '10.2.5')"
    },
    "ecosystem": {
      "type": "string",
      "enum": ["PyPI", "npm"],
      "description": "Package ecosystem (PyPI or npm, default: PyPI)"
    },
    "gemini_api_key": {
      "type": "string",
      "description": "Optional Gemini API key for AI synthesis"
    }
  },
  "required": ["package_name", "resolved_version", "latest_version"]
}
```

#### Example Call:
```json
{
  "name": "analyze_upgrade",
  "arguments": {
    "package_name": "minimatch",
    "resolved_version": "3.0.0",
    "latest_version": "10.2.5",
    "ecosystem": "npm"
  }
}
```

---

## ⚙️ Client Integration Recipes

### Claude Desktop
Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "depshield": {
      "command": "python3",
      "args": ["/path/to/Dependency-Checker/mcp_server.py"],
      "env": {
        "NVD_API_KEY": "your-nvd-api-key",
        "GEMINI_API_KEY": "your-gemini-api-key"
      }
    }
  }
}
```

### Cursor / Antigravity Agent Configuration
Add to `.cursor/mcp.json` or `.agents/mcp_config.json`:

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

### Docker Containerized MCP Execution
If you prefer running the MCP server without Python on the host machine:

```json
{
  "mcpServers": {
    "depshield-docker": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "depshield:latest", "python3", "/app/mcp_server.py"]
    }
  }
}
```
