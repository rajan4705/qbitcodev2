#!/usr/bin/env bash
# ==============================================================================
# Automated Verification Suite: Tests Production Docker Containers (8080, 8082, 6333)
# ==============================================================================
set -e

echo "============================================================================"
echo "RUNNING VERIFICATION SUITE AGAINST PRODUCTION DOCKER SERVICES"
echo "============================================================================"

# Test 1: SAST Health Check
echo -n "1. Testing SAST Health Check (8080)... "
RES_HEALTH_SAST=$(curl -s http://127.0.0.1:8080/health 2>/dev/null || true)
if echo "$RES_HEALTH_SAST" | grep -q "healthy"; then
  echo "✓ OK"
else
  echo "❌ FAILED: $RES_HEALTH_SAST"
  exit 1
fi

# Test 2: SCA Health Check
echo -n "2. Testing SCA Health Check (8082)... "
RES_HEALTH_SCA=$(curl -s http://127.0.0.1:8082/health 2>/dev/null || true)
if echo "$RES_HEALTH_SCA" | grep -q "healthy"; then
  echo "✓ OK"
else
  echo "❌ FAILED: $RES_HEALTH_SCA"
  exit 1
fi

# Test 3: Qdrant Health Check
echo -n "3. Testing Qdrant Health Check (6333)... "
RES_QDRANT=$(curl -s http://127.0.0.1:6333/healthz 2>/dev/null || true)
if echo "$RES_QDRANT" | grep -Eq "(passed|ok)"; then
  echo "✓ OK (healthz check passed)"
else
  echo "❌ FAILED: $RES_QDRANT"
  exit 1
fi

# Test 4: SCA Package Vulnerability Lookup
echo -n "4. Testing SCA Package Query (lodash 4.17.15 on 8082)... "
SCA_QUERY='{"package": "lodash", "version": "4.17.15", "ecosystem": "npm"}'
SCA_RES=$(curl -s -X POST "http://127.0.0.1:8082/api/v1/check/package" \
  -H "Content-Type: application/json" \
  -d "$SCA_QUERY" 2>/dev/null || true)

if echo "$SCA_RES" | grep -Eq "(vulnerabilit|advisories|cve_summary)"; then
  echo "✓ OK (Advisory match found)"
else
  echo "❌ FAILED: $SCA_RES"
  exit 1
fi

# Test 5: SAST Flaw CWE Attribution
echo -n "5. Testing SAST CWE Attribution (Buffer Overflow on 8080)... "
SAST_QUERY='{"code_snippet": "char buf[10]; strcpy(buf, input);", "language": "c", "flaw_summary": "Buffer overflow via strcpy without bounds check"}'
SAST_RES=$(curl -s -X POST "http://127.0.0.1:8080/api/v1/enrich_snippet" \
  -H "Content-Type: application/json" \
  -d "$SAST_QUERY" 2>/dev/null || true)

if echo "$SAST_RES" | grep -q "cwe"; then
  echo "✓ OK (Attributed to CWE)"
else
  echo "❌ FAILED: $SAST_RES"
  exit 1
fi

# Test 6: SAST Web UI HTML Check
echo -n "6. Testing SAST Dashboard UI (http://localhost:8080/)... "
SAST_UI=$(curl -s http://127.0.0.1:8080/ 2>/dev/null || true)
if echo "$SAST_UI" | grep -qi "<!DOCTYPE html>"; then
  echo "✓ OK (Web UI rendered)"
else
  echo "❌ FAILED"
  exit 1
fi

# Test 7: SCA Web UI HTML Check
echo -n "7. Testing SCA Dashboard UI (http://localhost:8082/)... "
SCA_UI=$(curl -s http://127.0.0.1:8082/ 2>/dev/null || true)
if echo "$SCA_UI" | grep -qi "<!DOCTYPE html>"; then
  echo "✓ OK (Web UI rendered)"
else
  echo "❌ FAILED"
  exit 1
fi

# Test 8: Web Cockpit GUI HTML Check (5433/5432)
UI_PORT="${UI_PORT:-5433}"
echo -n "8. Testing Web Cockpit GUI (http://localhost:${UI_PORT}/)... "
WEB_UI=$(curl -s "http://127.0.0.1:${UI_PORT}/" 2>/dev/null || curl -s "http://127.0.0.1:5432/" 2>/dev/null || true)
if echo "$WEB_UI" | grep -qi "Qbit Code Reviewer"; then
  echo "✓ OK (Web Cockpit rendered)"
else
  echo "⚠️  Web Cockpit not reached on ${UI_PORT} or 5432 (optional GUI container)"
fi

echo "============================================================================"
echo "🎉 ALL CORE PRODUCTION SYSTEM TESTS PASSED!"
echo "============================================================================"
echo "Production Access Points:"
echo "  • SAST Dashboard   : http://localhost:8080/"
echo "  • SAST Swagger     : http://localhost:8080/docs"
echo "  • SCA Dashboard    : http://localhost:8082/"
echo "  • SCA Swagger      : http://localhost:8082/docs"
echo "  • Qdrant Web UI    : http://localhost:6333/dashboard"
echo "  • Web Cockpit GUI  : http://localhost:${UI_PORT}/"
echo "============================================================================"

