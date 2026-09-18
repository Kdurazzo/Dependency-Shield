FROM python:3.11-slim

WORKDIR /app

# Install curl for container health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create persistent storage directories
RUN mkdir -p /app/logs /app/reports /app/data

# Copy application core modules
COPY checker.py depshield.py parsers.py registry_client.py reporter.py web_server.py mcp_server.py /app/

# Copy static web assets
COPY web/ /app/web/

# Copy sample packages and test manifests
COPY test_depshield.py test_package.json test_requirements.txt lodash-4.17.21.tgz /app/

# Ensure scripts are executable
RUN chmod +x /app/depshield.py /app/mcp_server.py

# Default entrypoint (can be overridden in docker-compose.yml or compose.yaml)
ENTRYPOINT ["python3", "/app/depshield.py"]
