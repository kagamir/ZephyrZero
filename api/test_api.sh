#!/bin/bash

# ZephyrZero API Test Script

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test function
test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_code=$4
    local description=$5
    local token=$6

    echo -e "${YELLOW}Test: $description${NC}"
    echo "Request: $method $BASE_URL$endpoint"
    
    if [ -n "$data" ]; then
        echo "Data: $data"
    fi
    
    local curl_cmd="curl -s -w '%{http_code}' -X $method"
    
    if [ -n "$token" ]; then
        curl_cmd="$curl_cmd -H 'Authorization: Bearer $token'"
    fi
    
    if [ -n "$data" ]; then
        curl_cmd="$curl_cmd -H 'Content-Type: application/json' -d '$data'"
    fi
    
    curl_cmd="$curl_cmd $BASE_URL$endpoint"
    
    local response=$(eval $curl_cmd)
    local status_code="${response: -3}"
    local body="${response%???}"
    
    if [ "$status_code" = "$expected_code" ]; then
        echo -e "${GREEN}✓ Success (Status Code: $status_code)${NC}"
        echo "Response: $body"
    else
        echo -e "${RED}✗ Failed (Expected: $expected_code, Actual: $status_code)${NC}"
        echo "Response: $body"
    fi
    
    echo "----------------------------------------"
    echo
}

# Base URL
BASE_URL="http://localhost:8080"

echo "ZephyrZero API Test Suite"
echo "========================="
echo

# Test 1: Health Check
test_endpoint "GET" "/api/v1/health" "" "200" "Health Check"

# Test 2: User Registration
USER_DATA='{"username":"testuser","email":"test@example.com","password":"password123","confirm_password":"password123"}'
test_endpoint "POST" "/api/v1/auth/register" "$USER_DATA" "201" "User Registration"

# Test 3: User Login
LOGIN_DATA='{"username":"testuser","password":"password123"}'
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$LOGIN_DATA" "$BASE_URL/api/v1/auth/login")
ACCESS_TOKEN=$(echo $RESPONSE | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
test_endpoint "POST" "/api/v1/auth/login" "$LOGIN_DATA" "200" "User Login"

echo "Access Token: $ACCESS_TOKEN"
echo

# Test 4: Get User Profile (requires authentication)
test_endpoint "GET" "/api/v1/auth/profile" "" "200" "Get User Profile" "$ACCESS_TOKEN"

# Test 5: File Upload (requires authentication and file)
# Note: This test requires a multipart form upload with an actual file
echo -e "${YELLOW}Test: File Upload${NC}"
echo "Note: This test requires manual execution with an actual file"
echo "Example: curl -X POST -H \"Authorization: Bearer \$ACCESS_TOKEN\" -F \"file=@test.txt\" \"$BASE_URL/api/v1/files/upload\""
echo "----------------------------------------"
echo

# Test 6: Get User Files (requires authentication)
test_endpoint "GET" "/api/v1/files" "" "200" "Get User Files" "$ACCESS_TOKEN"

# Test 7: Logout (requires authentication)
test_endpoint "POST" "/api/v1/auth/logout" "" "200" "User Logout" "$ACCESS_TOKEN"

# Test 8: Unauthenticated Access (should fail)
test_endpoint "GET" "/api/v1/auth/profile" "" "401" "Unauthenticated Profile Access"

# Test 9: Invalid Login
INVALID_LOGIN='{"username":"testuser","password":"wrongpassword"}'
test_endpoint "POST" "/api/v1/auth/login" "$INVALID_LOGIN" "401" "Invalid Login Credentials"

# Test 10: Admin Routes (requires admin privileges)
test_endpoint "GET" "/api/v1/admin/audit-logs" "" "401" "Admin Audit Logs (Unauthenticated)"

echo "Test suite completed!"
echo
echo "Note: Some tests may require additional setup:"
echo "1. Make sure the API server is running on $BASE_URL"
echo "2. The database should be properly initialized"
echo "3. File upload tests require actual files"
echo "4. Admin tests require an admin user" 