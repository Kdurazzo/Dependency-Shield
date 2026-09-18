#!/bin/bash
#
# smoke.sh - Automated smoke test suite for DepShield Docker deployment
#

set -e

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
DASHBOARD_URL="${DASHBOARD_URL:-http://localhost:8080}"

echo ""
echo "=========================================================="
echo "  DepShield Docker Smoke Test Suite"
echo "=========================================================="
echo "Backend URL:   $BACKEND_URL"
echo "Dashboard URL: $DASHBOARD_URL"
echo ""

# Test 1: Direct Backend Health Check
echo -n "[Test 1/4] Checking direct backend health endpoint (/api/health)... "
HEALTH_RESP=$(curl -s -f "$BACKEND_URL/api/health" || true)
if echo "$HEALTH_RESP" | grep -q '"status":\s*"ok"'; then
  echo "PASSED (status: ok)"
else
  echo "FAILED!"
  echo "Response: $HEALTH_RESP"
  exit 1
fi

# Test 2: Dashboard Frontend Serving
echo -n "[Test 2/4] Checking dashboard web UI HTTP response (/)... "
UI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$DASHBOARD_URL/")
if [ "$UI_STATUS" = "200" ]; then
  echo "PASSED (HTTP 200 OK)"
else
  echo "FAILED (HTTP $UI_STATUS)"
  exit 1
fi

# Test 3: Reverse Proxy API routing through Dashboard
echo -n "[Test 3/4] Checking Nginx reverse-proxy API routing ($DASHBOARD_URL/api/health)... "
PROXY_RESP=$(curl -s -f "$DASHBOARD_URL/api/health" || true)
if echo "$PROXY_RESP" | grep -q '"status":\s*"ok"'; then
  echo "PASSED (reverse proxy working)"
else
  echo "FAILED!"
  echo "Response: $PROXY_RESP"
  exit 1
fi

# Test 4: Package Audit API execution
echo -n "[Test 4/4] Exercising POST /api/v1/audit with package payload... "
AUDIT_RESP=$(curl -s -X POST "$BACKEND_URL/api/v1/audit" \
  -H "Content-Type: application/json" \
  -d '{"packages":[{"name":"lodash","version":"4.17.20","ecosystem":"npm"}],"max_depth":1}')

if echo "$AUDIT_RESP" | grep -q '"risk_level"'; then
  echo "PASSED (Audit returned risk_level)"
else
  echo "FAILED!"
  echo "Response: $AUDIT_RESP"
  exit 1
fi

echo ""
echo "=========================================================="
echo "  ALL SMOKE TESTS PASSED SUCCESSFULLY! "
echo "=========================================================="
echo ""
