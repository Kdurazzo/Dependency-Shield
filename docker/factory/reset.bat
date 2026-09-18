@echo off
rem reset.bat - Reset DepShield docker environment to factory defaults
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "FACTORY_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%FACTORY_DIR%\..") do set "DOCKER_DIR=%%~fI"

echo.
echo ==========================================================
echo   DepShield - Reset to Factory Defaults
echo ==========================================================
echo.
echo WARNING: This is a DESTRUCTIVE action. The following will
echo be permanently deleted / reset:
echo.
echo   - Running DepShield containers (backend, dashboard, mcp)
echo   - Generated audit reports in docker\reports\
echo   - Runtime logs in docker\logs\ (backend, dashboard, mcp)
echo   - Persisted cache / data in docker\data\
echo   - Docker configuration changes to compose.yaml
echo   - Docker configuration changes to depshield.json and depshield-mcp.json
echo   - Docker configuration changes to nginx\nginx.conf
echo   - Environment file docker\.env (reset to .env.example)
echo.
echo DepShield Docker configuration
echo will be restored to factory defaults.
echo.

set /p "CONFIRM=Type RESET to confirm: "
echo.

if not "%CONFIRM%"=="RESET" (
    echo Aborted. No changes were made.
    exit /b 1
)

echo [1/4] Stopping containers...
cd /d "%DOCKER_DIR%"
docker compose down --remove-orphans >nul 2>&1

echo [2/4] Restoring factory configurations...
copy /y "%FACTORY_DIR%\compose.yaml" "%DOCKER_DIR%\compose.yaml" >nul
copy /y "%FACTORY_DIR%\depshield.json" "%DOCKER_DIR%\depshield.json" >nul
copy /y "%FACTORY_DIR%\depshield-mcp.json" "%DOCKER_DIR%\depshield-mcp.json" >nul
copy /y "%FACTORY_DIR%\.env.example" "%DOCKER_DIR%\.env.example" >nul
copy /y "%FACTORY_DIR%\.env.example" "%DOCKER_DIR%\.env" >nul
if not exist "%DOCKER_DIR%\nginx" mkdir "%DOCKER_DIR%\nginx"
copy /y "%FACTORY_DIR%\nginx\nginx.conf" "%DOCKER_DIR%\nginx\nginx.conf" >nul
echo         Restored compose.yaml, depshield.json, depshield-mcp.json, .env, and nginx.conf

echo [3/4] Resetting runtime directories...
if exist "%DOCKER_DIR%\logs" rmdir /s /q "%DOCKER_DIR%\logs"
if exist "%DOCKER_DIR%\reports" rmdir /s /q "%DOCKER_DIR%\reports"
if exist "%DOCKER_DIR%\data" rmdir /s /q "%DOCKER_DIR%\data"

mkdir "%DOCKER_DIR%\logs\backend"
mkdir "%DOCKER_DIR%\logs\dashboard"
mkdir "%DOCKER_DIR%\logs\mcp"
mkdir "%DOCKER_DIR%\reports"
mkdir "%DOCKER_DIR%\data"
type nul > "%DOCKER_DIR%\logs\backend\.gitkeep"
type nul > "%DOCKER_DIR%\logs\dashboard\.gitkeep"
type nul > "%DOCKER_DIR%\logs\mcp\.gitkeep"
type nul > "%DOCKER_DIR%\reports\.gitkeep"
type nul > "%DOCKER_DIR%\data\.gitkeep"
echo         Cleared runtime logs, reports, and data directories

echo [4/4] Factory reset complete.
echo.
echo To start the clean environment:
echo   cd %DOCKER_DIR%
echo   docker compose up -d
echo.
