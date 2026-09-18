@echo off
rem smoke.bat - Automated smoke test suite for DepShield Docker deployment
setlocal enabledelayedexpansion

if "%BACKEND_URL%"=="" set "BACKEND_URL=http://localhost:8000"
if "%DASHBOARD_URL%"=="" set "DASHBOARD_URL=http://localhost:8080"

echo.
echo ==========================================================
echo   DepShield Docker Smoke Test Suite
echo ==========================================================
echo Backend URL:   %BACKEND_URL%
echo Dashboard URL: %DASHBOARD_URL%
echo.

echo [Test 1/3] Checking direct backend health endpoint (/api/health)...
curl -s -f "%BACKEND_URL%/api/health" | findstr /i "ok" >nul
if errorlevel 1 (
    echo FAILED! Direct backend health check failed.
    exit /b 1
) else (
    echo PASSED (status: ok)
)

echo [Test 2/3] Checking reverse proxy API routing (%DASHBOARD_URL%/api/health)...
curl -s -f "%DASHBOARD_URL%/api/health" | findstr /i "ok" >nul
if errorlevel 1 (
    echo FAILED! Reverse proxy health check failed.
    exit /b 1
) else (
    echo PASSED (reverse proxy working)
)

echo [Test 3/3] Exercising POST /api/v1/audit with package payload...
curl -s -X POST "%BACKEND_URL%/api/v1/audit" -H "Content-Type: application/json" -d "{\"packages\":[{\"name\":\"lodash\",\"version\":\"4.17.20\",\"ecosystem\":\"npm\"}],\"max_depth\":1}" | findstr /i "risk_level" >nul
if errorlevel 1 (
    echo FAILED! Audit API test failed.
    exit /b 1
) else (
    echo PASSED (Audit returned risk_level)
)

echo.
echo ==========================================================
echo   ALL SMOKE TESTS PASSED SUCCESSFULLY!
echo ==========================================================
echo.
