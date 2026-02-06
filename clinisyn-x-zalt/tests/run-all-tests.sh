#!/bin/bash
# Clinisyn x Zalt.io - Kapsamlı Test Suite
# Kullanım: ./run-all-tests.sh

set -e

API_URL="https://api.zalt.io"
REALM_ID="clinisyn"
TEST_EMAIL="drsmith@clinisyn.com"
TEST_PASSWORD="SecurePass123!"

echo "============================================"
echo "   CLINISYN x ZALT.IO TEST SUITE"
echo "   $(date)"
echo "============================================"
echo ""

PASSED=0
FAILED=0
RESULTS=()

# Helper function
test_endpoint() {
    local name=$1
    local result=$2
    local expected=$3
    
    if [[ "$result" == *"$expected"* ]]; then
        echo "✅ $name - PASS"
        ((PASSED++))
        RESULTS+=("{\"test\":\"$name\",\"status\":\"pass\"}")
    else
        echo "❌ $name - FAIL"
        echo "   Expected: $expected"
        echo "   Got: $result"
        ((FAILED++))
        RESULTS+=("{\"test\":\"$name\",\"status\":\"fail\"}")
    fi
}

# Test 1: Health Check
echo "1. Health Check"
HEALTH=$(curl -s $API_URL/health)
test_endpoint "Health Check" "$HEALTH" "healthy"

# Test 2: Login
echo "2. Login"
LOGIN=$(curl -s -X POST $API_URL/login \
    -H "Content-Type: application/json" \
    -d "{\"realm_id\":\"$REALM_ID\",\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
test_endpoint "Login" "$LOGIN" "Login successful"

# Extract tokens
ACCESS_TOKEN=$(echo $LOGIN | jq -r '.tokens.access_token')
REFRESH_TOKEN=$(echo $LOGIN | jq -r '.tokens.refresh_token')

if [ "$ACCESS_TOKEN" == "null" ]; then
    echo "❌ Login failed - cannot continue tests"
    exit 1
fi

# Test 3: Token Refresh
echo "3. Token Refresh"
REFRESH=$(curl -s -X POST $API_URL/refresh \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")
test_endpoint "Token Refresh" "$REFRESH" "Token refreshed"

# Update access token
ACCESS_TOKEN=$(echo $REFRESH | jq -r '.tokens.access_token')

# Test 4: TOTP MFA Setup
echo "4. TOTP MFA Setup"
MFA_SETUP=$(curl -s -X POST $API_URL/v1/auth/mfa/setup \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"method":"totp"}')
test_endpoint "TOTP MFA Setup" "$MFA_SETUP" "secret"

# Test 5: WebAuthn Register Options
echo "5. WebAuthn Register Options"
WEBAUTHN=$(curl -s -X POST $API_URL/v1/auth/webauthn/register/options \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json")
test_endpoint "WebAuthn Register" "$WEBAUTHN" "challenge"

# Test 6: WebAuthn Credentials List
echo "6. WebAuthn Credentials List"
CREDS=$(curl -s -X GET $API_URL/v1/auth/webauthn/credentials \
    -H "Authorization: Bearer $ACCESS_TOKEN")
test_endpoint "WebAuthn List" "$CREDS" "credentials"

# Test 7: SMS MFA Risk Warning
echo "7. SMS MFA Risk Warning"
SMS_WARNING=$(curl -s "$API_URL/v1/auth/mfa/sms/risk-warning?realm_id=$REALM_ID")
test_endpoint "SMS MFA Warning" "$SMS_WARNING" "warning"

# Test 8: Password Reset Request
echo "8. Password Reset Request"
PWD_RESET=$(curl -s -X POST $API_URL/v1/auth/password-reset/request \
    -H "Content-Type: application/json" \
    -d "{\"realm_id\":\"$REALM_ID\",\"email\":\"$TEST_EMAIL\"}")
test_endpoint "Password Reset" "$PWD_RESET" "password reset"

# Test 9: JWKS Endpoint
echo "9. JWKS Endpoint"
JWKS=$(curl -s $API_URL/.well-known/jwks.json)
test_endpoint "JWKS Endpoint" "$JWKS" "RS256"

# Test 10: OpenID Configuration
echo "10. OpenID Configuration"
OIDC=$(curl -s $API_URL/.well-known/openid-configuration)
test_endpoint "OpenID Config" "$OIDC" "issuer"

# Test 11: Logout
echo "11. Logout"
LOGOUT=$(curl -s -X POST $API_URL/logout \
    -H "Authorization: Bearer $ACCESS_TOKEN")
test_endpoint "Logout" "$LOGOUT" "Logout successful"

# Test 12: Email Enumeration Protection
echo "12. Email Enumeration Protection"
ENUM=$(curl -s -X POST $API_URL/login \
    -H "Content-Type: application/json" \
    -d "{\"realm_id\":\"$REALM_ID\",\"email\":\"nonexistent@test.com\",\"password\":\"wrong\"}")
test_endpoint "Email Enumeration" "$ENUM" "INVALID_CREDENTIALS"

echo ""
echo "============================================"
echo "   TEST RESULTS"
echo "============================================"
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"
echo "📊 Total:  $((PASSED + FAILED))"
echo ""

# Save results to JSON
echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"passed\":$PASSED,\"failed\":$FAILED,\"tests\":[$(IFS=,; echo "${RESULTS[*]}")]}" > test-results.json

if [ $FAILED -gt 0 ]; then
    echo "⚠️  Some tests failed!"
    exit 1
else
    echo "🎉 All tests passed!"
    exit 0
fi
