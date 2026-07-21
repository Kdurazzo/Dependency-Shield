@echo off
REM Get the directory where this script is located
SET SCRIPT_DIR=%~dp0

echo [*] Building/Updating DepShield Docker image...
docker build -t depshield "%SCRIPT_DIR%"

echo [*] Running DepShield in Docker...
docker run --rm -it -v "%cd%:/workspace" -w /workspace -e NVD_API_KEY=%NVD_API_KEY% depshield %*
