#!/bin/bash
# Test connectivity between all services
set -e

echo "=== Multi-Cloud IPAM Scanner - Connectivity Test ==="
echo ""

# Test backend health
echo "1. Testing Backend Health..."
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
if curl -sf "$BACKEND_URL/health" > /dev/null 2>&1; then
  HEALTH=$(curl -sf "$BACKEND_URL/health")
  echo "   ✅ Backend is reachable: $HEALTH"
else
  echo "   ❌ Backend is not reachable at $BACKEND_URL"
fi

# Test API v1 health
echo "2. Testing API v1 Health..."
if curl -sf "$BACKEND_URL/api/v1/health" > /dev/null 2>&1; then
  echo "   ✅ API v1 is reachable"
else
  echo "   ❌ API v1 is not reachable"
fi

# Test Redis connectivity (via backend)
echo "3. Testing Redis (via backend)..."
REDIS_STATUS=$(curl -sf "$BACKEND_URL/api/v1/health" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('redis','unknown'))" 2>/dev/null || echo "unknown")
echo "   Redis status: $REDIS_STATUS"

# Test frontend
echo "4. Testing Frontend..."
FRONTEND_URL="${FRONTEND_URL:-http://localhost:5173}"
if curl -sf "$FRONTEND_URL" > /dev/null 2>&1; then
  echo "   ✅ Frontend is reachable at $FRONTEND_URL"
else
  echo "   ❌ Frontend is not reachable at $FRONTEND_URL"
fi

echo ""
echo "=== Test Complete ==="
