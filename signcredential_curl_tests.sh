#!/bin/bash

# SignCredential Security Test Script using cURL
# ==============================================
# This script provides quick manual testing of the signCredential security fixes

# Configuration
BASE_URL="http://localhost:8080"  # Update with your service URL
AUTH_TOKEN=""  # Add your auth token if required

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to make HTTP request
make_request() {
    local test_name="$1"
    local test_data="$2"
    local expected_status="$3"
    
    echo -e "${BLUE}🧪 Testing: $test_name${NC}"
    
    # Make the request
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        ${AUTH_TOKEN:+-H "Authorization: Bearer $AUTH_TOKEN"} \
        -d "$test_data" \
        "$BASE_URL/signCredential")
    
    # Extract status code and body
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    # Check result
    if [ "$status_code" = "$expected_status" ]; then
        echo -e "${GREEN}✅ PASS${NC} - Expected: $expected_status, Got: $status_code"
    else
        echo -e "${RED}❌ FAIL${NC} - Expected: $expected_status, Got: $status_code"
        echo -e "${YELLOW}Response: $body${NC}"
    fi
    echo ""
}

# Test 1: Valid Request
echo -e "${BLUE}📋 TEST 1: Valid Request${NC}"
valid_request='{
  "id": "test-valid-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}'
make_request "Valid Request" "$valid_request" "200"

# Test 2: Null Message
echo -e "${BLUE}📋 TEST 2: Null Message${NC}"
null_message='{
  "id": "test-null-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": null,
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}'
make_request "Null Message" "$null_message" "400"

# Test 3: Empty Message
echo -e "${BLUE}📋 TEST 3: Empty Message${NC}"
empty_message='{
  "id": "test-empty-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}'
make_request "Empty Message" "$empty_message" "400"

# Test 4: Invalid Base64 Format
echo -e "${BLUE}📋 TEST 4: Invalid Base64 Format${NC}"
invalid_base64='{
  "id": "test-invalid-base64-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "Invalid@Base64#Format!",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}'
make_request "Invalid Base64 Format" "$invalid_base64" "400"

# Test 5: Large Message (>1MB)
echo -e "${BLUE}📋 TEST 5: Large Message (>1MB)${NC}"
# Generate a large Base64 string (>1MB)
large_data=$(python3 -c "
import base64
large_string = 'A' * 1048577  # > 1MB
print(base64.b64encode(large_string.encode()).decode())
")
large_message="{
  \"id\": \"test-large-001\",
  \"version\": \"1.0\",
  \"requesttime\": \"2024-01-15T10:30:00.000Z\",
  \"request\": {
    \"message\": \"$large_data\",
    \"applicationId\": \"KERNEL\",
    \"referenceId\": \"SIGN\"
  }
}"
make_request "Large Message (>1MB)" "$large_message" "400"

# Test 6: Invalid ApplicationId Format
echo -e "${BLUE}📋 TEST 6: Invalid ApplicationId Format${NC}"
invalid_app_id='{
  "id": "test-invalid-app-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "INVALID@APP#ID!",
    "referenceId": "SIGN"
  }
}'
make_request "Invalid ApplicationId Format" "$invalid_app_id" "400"

# Test 7: Invalid ReferenceId Format
echo -e "${BLUE}📋 TEST 7: Invalid ReferenceId Format${NC}"
invalid_ref_id='{
  "id": "test-invalid-ref-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "INVALID@REF#ID!"
  }
}'
make_request "Invalid ReferenceId Format" "$invalid_ref_id" "400"

# Test 8: Unauthorized ApplicationId
echo -e "${BLUE}📋 TEST 8: Unauthorized ApplicationId${NC}"
unauthorized_app='{
  "id": "test-unauthorized-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "UNAUTHORIZED_APP",
    "referenceId": "SIGN"
  }
}'
make_request "Unauthorized ApplicationId" "$unauthorized_app" "403"

# Test 9: SQL Injection Attempt
echo -e "${BLUE}📋 TEST 9: SQL Injection Attempt${NC}"
sql_injection='{
  "id": "test-sql-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL\"; DROP TABLE users; --",
    "referenceId": "SIGN"
  }
}'
make_request "SQL Injection Attempt" "$sql_injection" "400"

# Test 10: XSS Attempt
echo -e "${BLUE}📋 TEST 10: XSS Attempt${NC}"
xss_attempt='{
  "id": "test-xss-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "<script>alert(\"XSS\")</script>",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}'
make_request "XSS Attempt" "$xss_attempt" "400"

# Test 11: Path Traversal Attempt
echo -e "${BLUE}📋 TEST 11: Path Traversal Attempt${NC}"
path_traversal='{
  "id": "test-path-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "../../etc/passwd",
    "referenceId": "SIGN"
  }
}'
make_request "Path Traversal Attempt" "$path_traversal" "400"

# Test 12: Missing Required Fields
echo -e "${BLUE}📋 TEST 12: Missing Required Fields${NC}"
missing_fields='{
  "id": "test-missing-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ="
  }
}'
make_request "Missing Required Fields" "$missing_fields" "400"

# Test 13: Malformed JSON
echo -e "${BLUE}📋 TEST 13: Malformed JSON${NC}"
echo -e "${BLUE}🧪 Testing: Malformed JSON${NC}"
malformed_response=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    ${AUTH_TOKEN:+-H "Authorization: Bearer $AUTH_TOKEN"} \
    -d '{"invalid": json}' \
    "$BASE_URL/signCredential")

malformed_status=$(echo "$malformed_response" | tail -n1)
if [ "$malformed_status" = "400" ]; then
    echo -e "${GREEN}✅ PASS${NC} - Expected: 400, Got: $malformed_status"
else
    echo -e "${RED}❌ FAIL${NC} - Expected: 400, Got: $malformed_status"
fi
echo ""

# Test 14: Performance Test (Multiple Requests)
echo -e "${BLUE}📋 TEST 14: Performance Test (10 concurrent requests)${NC}"
echo -e "${BLUE}🧪 Testing: Performance${NC}"
start_time=$(date +%s.%N)

for i in {1..10}; do
    {
        curl -s -X POST \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            ${AUTH_TOKEN:+-H "Authorization: Bearer $AUTH_TOKEN"} \
            -d "$valid_request" \
            "$BASE_URL/signCredential" > /dev/null
    } &
done

wait
end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
echo -e "${GREEN}✅ Performance Test Completed${NC} - Duration: ${duration}s for 10 requests"
echo ""

# Summary
echo -e "${BLUE}📊 TEST SUMMARY${NC}"
echo -e "${BLUE}===============${NC}"
echo -e "Total Tests: 14"
echo -e "Check the results above for PASS/FAIL status"
echo -e ""
echo -e "${YELLOW}💡 Tips:${NC}"
echo -e "1. Update BASE_URL variable with your service URL"
echo -e "2. Add AUTH_TOKEN if authentication is required"
echo -e "3. Ensure your service is running before executing tests"
echo -e "4. Check logs for detailed error information"
echo -e ""
echo -e "${GREEN}🎉 Test execution completed!${NC}"
