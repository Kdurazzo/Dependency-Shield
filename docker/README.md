# DepShield Docker Environment

This directory provides containerized infrastructure for **DepShield** ([Dependency-Checker](https://github.com/Kdurazzo/Dependency-Checker)), modeled after the modular architecture found in [LiteGraph Docker](https://github.com/litegraphdb/litegraph/tree/main/docker).

---

## 🏗️ Architecture Overview

The compose stack orchestrates the core components into decoupled, resilient services:

```
                  ┌─────────────────────────────────┐
                  │          Client / Browser       │
                  └──────────────┬──────────────────┘
                                 │
                                 │ Port 8080
                                 ▼
                    ┌────────────────────────┐
                    │  depshield-dashboard   │
                    │      (nginx:alpine)    │
                    └────────────┬───────────┘
                                 │ /api/* (Reverse Proxy)
                                 ▼
                    ┌────────────────────────┐
                    │   depshield-backend    │  Port 8000
                    │ (Python REST / Engine) ├────────────── Direct API Clients
                    └────────────┬───────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ docker/data/ │         │ docker/logs/ │         │docker/reports│
└──────────────┘         └──────────────┘         └──────────────┘
```

### Services Defined in `compose.yaml`:
1. **`depshield-backend`** (`port 8000`):
   - Python 3.11 runtime executing `web_server.py 8000`.
   - Houses vulnerability databases queries (OSV, NIST NVD), parsing algorithms, graph traversal, and optional Gemini AI synthesis.
   - Built-in container healthcheck testing `/api/health`.
2. **`depshield-dashboard`** (`port 8080`):
   - Alpine Nginx reverse proxy serving the Glassmorphism dependency visualization frontend.
   - Routes all `/api/*` traffic transparently to `depshield-backend`.
3. **`depshield-mcp`** (Profile `mcp`):
   - Model Context Protocol server exposing `audit_manifest`, `audit_package`, and `analyze_upgrade` for AI agents.
4. **`depshield-cli`** (Profile `cli`):
   - On-demand CLI container runner to audit volume-mounted workspaces without local Python setup.

---

## 📁 Directory Structure & Persisted Volumes

```
docker/
├── .env.example              # Environment variables template
├── .env                      # Active runtime environment settings
├── README.md                 # This documentation
├── compose.yaml              # Multi-container Docker Compose file
├── depshield.json            # Centralized engine & scanner configuration
├── depshield-mcp.json        # MCP server registration descriptor
├── smoke.sh                  # Automated smoke test suite (POSIX)
├── smoke.bat                 # Automated smoke test suite (Windows)
├── nginx/
│   └── nginx.conf            # Reverse proxy & static asset routing
├── data/                     # [PERSISTED] Cached vulnerability indices & downloads
├── reports/                  # [PERSISTED] Output Markdown & HTML audit reports
├── logs/                     # [PERSISTED] Runtime application logs
│   ├── backend/              # REST API and scanner execution logs
│   ├── dashboard/            # Nginx access and error logs
│   └── mcp/                  # MCP server interaction logs
└── factory/                  # Factory reset baseline
    ├── reset.sh              # Bash script to restore factory clean install
    ├── reset.bat             # Windows batch script to restore factory clean install
    ├── compose.yaml          # Factory pristine compose specification
    ├── depshield.json        # Factory pristine engine config
    ├── depshield-mcp.json    # Factory pristine MCP config
    ├── .env.example          # Factory pristine environment defaults
    └── nginx/
        └── nginx.conf        # Factory pristine Nginx config
```

---

## 🚀 Quick Start

### 1. Configure Environment (Optional)
Copy the example environment file if you haven't already:
```bash
cd docker
cp .env.example .env
```
Optionally add your `NVD_API_KEY` or `GEMINI_API_KEY` into `.env`.

### 2. Build and Start Services
```bash
docker compose up -d --build
```

### 3. Verify Container Status
```bash
docker compose ps
```
Once healthy, access:
- **Interactive Web Dashboard**: [http://localhost:8080](http://localhost:8080)
- **Direct Backend REST API**: [http://localhost:8000](http://localhost:8000)

### 4. Run the Automated Smoke Suite
```bash
./smoke.sh
```

---

## 🧰 Running Auxiliary Services

### Run One-Off CLI Audits via Docker
Audit a local manifest file mounted from your host system:
```bash
docker compose run --rm depshield-cli /workspace/test_requirements.txt -o /app/reports
```
Generated reports will immediately appear in your host's `docker/reports/` directory.

Generated reports will immediately appear in your host's `docker/reports/` directory.

Run in automated agent execution mode:
```bash
docker compose run --rm depshield-cli /workspace/test_requirements.txt --agent
```

Synthesize a Gemini 2.5 Flash Markdown report (via Google session or API key):
```bash
# Using Google Account session activation:
docker compose run --rm -e GOOGLE_LOGGED_IN=true depshield-cli /workspace/test_requirements.txt --report -o /app/reports

# Or using an explicit Gemini API key:
docker compose run --rm -e GEMINI_API_KEY="your-key" depshield-cli /workspace/test_requirements.txt --report -o /app/reports
```

### Run the MCP Service
Start the persistent MCP container for agent integration:
```bash
docker compose --profile mcp up -d depshield-mcp
```

---

## 🔄 Factory Reset (Clean Install)

To return the entire Docker setup to pristine factory defaults for clean testing:

### macOS / Linux:
```bash
cd docker/factory
./reset.sh
```

### Windows:
```cmd
cd docker\factory
reset.bat
```

The script will prompt you:
```
Type 'RESET' to confirm:
```
When confirmed, the reset script will:
1. Stop and remove all active DepShield containers.
2. Remove any Docker volumes and orphan containers.
3. Clean all runtime logs in `docker/logs/`, reports in `docker/reports/`, and cache in `docker/data/`.
4. Restore pristine copies of all configuration templates (`compose.yaml`, `depshield.json`, `depshield-mcp.json`, `nginx.conf`, `.env`).
