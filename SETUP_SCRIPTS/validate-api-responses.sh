#!/bin/bash
# validate-api-responses.sh
# Verifies that APIs are responding

BASE_URL="http://localhost:3000"

echo "Checking System Health..."
curl -s "$BASE_URL/api/health" | grep "ok" && echo "Health OK" || echo "Health FAIL"

echo "Checking Login Page..."
curl -s -I "$BASE_URL/auth/login" | grep "200 OK" && echo "Login Page OK" || echo "Login Page FAIL"

# Note: Further validation requires authenticated session (cookie).
# Use Postman Runner for full test suite.
