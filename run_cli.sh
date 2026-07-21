#!/bin/bash

# Determine directory of this script to locate the Dockerfile
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build/update the container image
echo "[*] Building/Updating DepShield Docker image..."
docker build -t depshield "$SCRIPT_DIR"

# Run the container:
# - Mount the host's current working directory to /workspace in the container
# - Set the container's working directory to /workspace
# - Pass NVD_API_KEY environment variable if set on the host
# - Forward all command-line arguments to depshield
docker run --rm -it \
  -v "$(pwd):/workspace" \
  -w /workspace \
  -e NVD_API_KEY="$NVD_API_KEY" \
  depshield "$@"
