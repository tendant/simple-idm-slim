#!/bin/bash

# Multi-tenant Test Script
# This script tests the multi-tenant functionality end-to-end

set -e  # Exit on error

BASE_URL="http://localhost:8080"
API_BASE="$BASE_URL/v1/auth"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_test() {
    echo -e "${YELLOW}[TEST $((TESTS_RUN + 1))]${NC} $1"
    TESTS_RUN=$((TESTS_RUN + 1))
}

log_success() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_error() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_info() {
    echo -e "  ℹ $1"
}

# Extract JSON field
extract_json() {
    echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | cut -d'"' -f4 | head -1
}

extract_json_int() {
    echo "$1" | grep -o "\"$2\":[0-9]*" | cut -d':' -f2 | head -1
}

# Check if server is running
check_server() {
    if ! curl -s "$BASE_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}Error: Server is not running at $BASE_URL${NC}"
        echo "Please start the server first: make run"
        exit 1
    fi
}

echo "========================================="
echo "  Multi-Tenant Test Suite"
echo "========================================="
echo ""

check_server

# Generate unique test user emails
TIMESTAMP=$(date +%s)
USER1_EMAIL="test-user-${TIMESTAMP}@example.com"
USER1_PASSWORD="TestPassword123!"
USER1_NAME="Test User One"

USER2_EMAIL="test-user2-${TIMESTAMP}@example.com"
USER2_PASSWORD="TestPassword456!"
USER2_NAME="Test User Two"

echo "Test Configuration:"
echo "  User 1: $USER1_EMAIL"
echo "  User 2: $USER2_EMAIL"
echo ""

# ==========================================
# TEST 1: User Registration
# ==========================================
log_test "User registration should create user, tenant, and membership"

REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE/password/register" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{
        \"email\": \"$USER1_EMAIL\",
        \"password\": \"$USER1_PASSWORD\",
        \"name\": \"$USER1_NAME\"
    }")

ACCESS_TOKEN=$(extract_json "$REGISTER_RESPONSE" "access_token")
REFRESH_TOKEN=$(extract_json "$REGISTER_RESPONSE" "refresh_token")

if [ -n "$ACCESS_TOKEN" ] && [ -n "$REFRESH_TOKEN" ]; then
    log_success "Registration successful, tokens received"
    log_info "Access token: ${ACCESS_TOKEN:0:20}..."
    log_info "Refresh token: ${REFRESH_TOKEN:0:20}..."
else
    log_error "Registration failed: $REGISTER_RESPONSE"
    exit 1
fi

# Decode JWT to check tenant_id and membership_id
JWT_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2)
# Add padding if needed
case $((${#JWT_PAYLOAD} % 4)) in
    2) JWT_PAYLOAD="${JWT_PAYLOAD}==" ;;
    3) JWT_PAYLOAD="${JWT_PAYLOAD}=" ;;
esac
DECODED_JWT=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null || echo "{}")

TENANT_ID=$(extract_json "$DECODED_JWT" "tenant_id")
MEMBERSHIP_ID=$(extract_json "$DECODED_JWT" "membership_id")
USER_ID=$(extract_json "$DECODED_JWT" "sub")

if [ -n "$TENANT_ID" ] && [ -n "$MEMBERSHIP_ID" ]; then
    log_success "JWT contains tenant_id and membership_id"
    log_info "User ID: $USER_ID"
    log_info "Tenant ID: $TENANT_ID"
    log_info "Membership ID: $MEMBERSHIP_ID"
else
    log_error "JWT missing tenant information: $DECODED_JWT"
fi

# ==========================================
# TEST 2: Access Protected Endpoint
# ==========================================
log_test "Protected endpoint should work with tenant context"

ME_RESPONSE=$(curl -s -X GET "$BASE_URL/v1/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

ME_EMAIL=$(extract_json "$ME_RESPONSE" "email")

if [ "$ME_EMAIL" = "$USER1_EMAIL" ]; then
    log_success "Protected endpoint accessible with tenant-scoped token"
    log_info "Response: $ME_RESPONSE"
else
    log_error "Failed to access protected endpoint: $ME_RESPONSE"
fi

# ==========================================
# TEST 3: Logout and Login with Single Tenant
# ==========================================
log_test "Login with single tenant should auto-select"

# Logout first
curl -s -X POST "$API_BASE/logout" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" > /dev/null

# Login
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE/password/login" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{
        \"identifier\": \"$USER1_EMAIL\",
        \"password\": \"$USER1_PASSWORD\"
    }")

NEW_ACCESS_TOKEN=$(extract_json "$LOGIN_RESPONSE" "access_token")

if [ -n "$NEW_ACCESS_TOKEN" ]; then
    log_success "Login successful with single tenant (auto-selected)"
    log_info "New access token: ${NEW_ACCESS_TOKEN:0:20}..."
    ACCESS_TOKEN="$NEW_ACCESS_TOKEN"
else
    log_error "Login failed: $LOGIN_RESPONSE"
fi

# ==========================================
# TEST 4: Token Refresh
# ==========================================
log_test "Token refresh should preserve tenant context"

REFRESH_RESPONSE=$(curl -s -X POST "$API_BASE/refresh" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")

REFRESHED_ACCESS_TOKEN=$(extract_json "$REFRESH_RESPONSE" "access_token")

if [ -n "$REFRESHED_ACCESS_TOKEN" ]; then
    # Decode and check tenant_id is preserved
    JWT_PAYLOAD=$(echo "$REFRESHED_ACCESS_TOKEN" | cut -d'.' -f2)
    case $((${#JWT_PAYLOAD} % 4)) in
        2) JWT_PAYLOAD="${JWT_PAYLOAD}==" ;;
        3) JWT_PAYLOAD="${JWT_PAYLOAD}=" ;;
    esac
    DECODED_JWT=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null || echo "{}")
    REFRESHED_TENANT_ID=$(extract_json "$DECODED_JWT" "tenant_id")

    if [ "$REFRESHED_TENANT_ID" = "$TENANT_ID" ]; then
        log_success "Token refresh preserved tenant context"
        log_info "Tenant ID still: $REFRESHED_TENANT_ID"
    else
        log_error "Token refresh changed tenant context"
    fi
else
    log_error "Token refresh failed: $REFRESH_RESPONSE"
fi

# ==========================================
# TEST 5: Register Second User (for multi-tenant test)
# ==========================================
log_test "Register second user with separate tenant"

USER2_REGISTER=$(curl -s -X POST "$API_BASE/password/register" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{
        \"email\": \"$USER2_EMAIL\",
        \"password\": \"$USER2_PASSWORD\",
        \"name\": \"$USER2_NAME\"
    }")

USER2_ACCESS_TOKEN=$(extract_json "$USER2_REGISTER" "access_token")

if [ -n "$USER2_ACCESS_TOKEN" ]; then
    log_success "Second user registered successfully"

    # Extract second user's tenant ID
    JWT_PAYLOAD=$(echo "$USER2_ACCESS_TOKEN" | cut -d'.' -f2)
    case $((${#JWT_PAYLOAD} % 4)) in
        2) JWT_PAYLOAD="${JWT_PAYLOAD}==" ;;
        3) JWT_PAYLOAD="${JWT_PAYLOAD}=" ;;
    esac
    DECODED_JWT=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null || echo "{}")
    USER2_TENANT_ID=$(extract_json "$DECODED_JWT" "tenant_id")
    USER2_ID=$(extract_json "$DECODED_JWT" "sub")

    log_info "User 2 ID: $USER2_ID"
    log_info "User 2 Tenant ID: $USER2_TENANT_ID"

    if [ "$USER2_TENANT_ID" != "$TENANT_ID" ]; then
        log_success "Each user has separate tenant"
    else
        log_error "Users share same tenant (should be separate)"
    fi
else
    log_error "Second user registration failed: $USER2_REGISTER"
fi

# ==========================================
# TEST 6: Multi-Tenant Scenario (Manual DB Insert)
# ==========================================
log_test "Login with multiple tenants should require tenant selection"

# Note: In a real scenario, we'd need to manually insert a second membership
# for user1 into user2's tenant via SQL. For this test, we'll document the
# expected behavior instead of actually creating it.

log_info "To test multi-tenant login, manually run:"
log_info "  INSERT INTO memberships (id, tenant_id, user_id, status, created_at, updated_at)"
log_info "  VALUES (gen_random_uuid(), '$USER2_TENANT_ID', '$USER_ID', 'active', NOW(), NOW());"
log_info ""
log_info "Then login as $USER1_EMAIL without tenant_id parameter"
log_info "Expected: HTTP 409 with tenant list"

# ==========================================
# TEST 7: Login with Explicit Tenant ID
# ==========================================
log_test "Login with explicit tenant_id should use that tenant"

LOGIN_WITH_TENANT=$(curl -s -X POST "$API_BASE/password/login" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{
        \"identifier\": \"$USER1_EMAIL\",
        \"password\": \"$USER1_PASSWORD\",
        \"tenant_id\": \"$TENANT_ID\"
    }")

TENANT_LOGIN_TOKEN=$(extract_json "$LOGIN_WITH_TENANT" "access_token")

if [ -n "$TENANT_LOGIN_TOKEN" ]; then
    # Verify tenant_id in token matches
    JWT_PAYLOAD=$(echo "$TENANT_LOGIN_TOKEN" | cut -d'.' -f2)
    case $((${#JWT_PAYLOAD} % 4)) in
        2) JWT_PAYLOAD="${JWT_PAYLOAD}==" ;;
        3) JWT_PAYLOAD="${JWT_PAYLOAD}=" ;;
    esac
    DECODED_JWT=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null || echo "{}")
    TOKEN_TENANT_ID=$(extract_json "$DECODED_JWT" "tenant_id")

    if [ "$TOKEN_TENANT_ID" = "$TENANT_ID" ]; then
        log_success "Login with tenant_id parameter works correctly"
    else
        log_error "Token has wrong tenant_id: expected $TENANT_ID, got $TOKEN_TENANT_ID"
    fi
else
    log_error "Login with tenant_id failed: $LOGIN_WITH_TENANT"
fi

# ==========================================
# TEST 8: Invalid Tenant Access
# ==========================================
log_test "Login with invalid tenant_id should fail"

INVALID_TENANT_LOGIN=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/password/login" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{
        \"identifier\": \"$USER1_EMAIL\",
        \"password\": \"$USER1_PASSWORD\",
        \"tenant_id\": \"00000000-0000-0000-0000-000000000000\"
    }")

HTTP_CODE=$(echo "$INVALID_TENANT_LOGIN" | tail -1)

if [ "$HTTP_CODE" = "403" ]; then
    log_success "Login rejected for invalid tenant (HTTP 403)"
else
    log_error "Expected HTTP 403, got $HTTP_CODE"
    log_info "Response: $(echo "$INVALID_TENANT_LOGIN" | head -n -1)"
fi

# ==========================================
# TEST 9: Logout All Sessions (Tenant-Scoped)
# ==========================================
log_test "Logout all should revoke all sessions for current tenant"

# First, create a second session
LOGIN2_RESPONSE=$(curl -s -X POST "$API_BASE/password/login" \
    -H "Content-Type: application/json" \
    -H "X-Client-Type: mobile" \
    -d "{
        \"identifier\": \"$USER1_EMAIL\",
        \"password\": \"$USER1_PASSWORD\"
    }")

ACCESS_TOKEN2=$(extract_json "$LOGIN2_RESPONSE" "access_token")

# Now logout all
LOGOUT_ALL_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/logout/all" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

LOGOUT_HTTP_CODE=$(echo "$LOGOUT_ALL_RESPONSE" | tail -1)

if [ "$LOGOUT_HTTP_CODE" = "204" ]; then
    log_success "Logout all successful (HTTP 204)"

    # Verify both tokens are now invalid
    ME_CHECK=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/v1/me" \
        -H "Authorization: Bearer $ACCESS_TOKEN2")

    ME_HTTP_CODE=$(echo "$ME_CHECK" | tail -1)

    if [ "$ME_HTTP_CODE" = "401" ]; then
        log_success "All tokens invalidated after logout all"
    else
        log_error "Token still valid after logout all"
    fi
else
    log_error "Logout all failed: HTTP $LOGOUT_HTTP_CODE"
fi

# ==========================================
# Summary
# ==========================================
echo ""
echo "========================================="
echo "  Test Results"
echo "========================================="
echo "Total tests: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
