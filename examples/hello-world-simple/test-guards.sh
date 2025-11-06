#!/bin/bash

# Test script for Noony Guard System Examples
# This script demonstrates all the guard system endpoints

set -e

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  Testing Noony Guard System Examples${NC}"
echo "==============================================="
echo

# Function to make HTTP requests and show results
test_endpoint() {
    local method=$1
    local endpoint=$2
    local headers=$3
    local data=$4
    local description=$5
    
    echo -e "${YELLOW}Testing: ${description}${NC}"
    echo -e "${BLUE}Request: ${method} ${endpoint}${NC}"
    
    if [ -n "$headers" ]; then
        echo -e "${BLUE}Headers: ${headers}${NC}"
    fi
    
    if [ -n "$data" ]; then
        echo -e "${BLUE}Data: ${data}${NC}"
    fi
    
    echo "Response:"
    if [ -n "$data" ]; then
        curl -s -X $method $BASE_URL$endpoint $headers -d "$data" | jq '.' || echo "Failed to parse JSON"
    else
        curl -s -X $method $BASE_URL$endpoint $headers | jq '.' || echo "Failed to parse JSON"
    fi
    echo
    echo "---"
    echo
}

# Test 1: System Status (No authentication required)
test_endpoint "GET" "/systemStatus" "" "" "System Status - No Auth Required"

# Test 2: Authentication Test - Valid User
test_endpoint "POST" "/authTest" \
    "-H 'Authorization: Bearer demo-user123'" \
    "" \
    "Authentication Test - Valid User (demo-user123)"

# Test 3: Authentication Test - Admin User
test_endpoint "POST" "/authTest" \
    "-H 'Authorization: Bearer demo-admin456'" \
    "" \
    "Authentication Test - Admin User (demo-admin456)"

# Test 4: Authentication Test - Demo User
test_endpoint "POST" "/authTest" \
    "-H 'Authorization: Bearer demo-demo789'" \
    "" \
    "Authentication Test - Demo User (demo-demo789)"

# Test 5: Guarded Hello World - User with greeting:create permission
test_endpoint "POST" "/guardedHelloWorld" \
    "-H 'Authorization: Bearer demo-user123' -H 'Content-Type: application/json'" \
    '{"name": "John", "greeting": "Hello", "includeTimestamp": true}' \
    "Guarded Hello World - User with greeting:create permission"

# Test 6: Guarded Hello World - Admin user
test_endpoint "POST" "/guardedHelloWorld" \
    "-H 'Authorization: Bearer demo-admin456' -H 'Content-Type: application/json'" \
    '{"name": "Admin", "greeting": "Welcome"}' \
    "Guarded Hello World - Admin User"

# Test 7: Guarded Hello World - Demo user with user:hello permission
test_endpoint "POST" "/guardedHelloWorld" \
    "-H 'Authorization: Bearer demo-demo789' -H 'Content-Type: application/json'" \
    '{"name": "Demo User", "greeting": "Hi"}' \
    "Guarded Hello World - Demo user with user:hello permission"

# Test 8: Invalid token
echo -e "${RED}Testing Error Cases:${NC}"
echo

test_endpoint "POST" "/authTest" \
    "-H 'Authorization: Bearer invalid-token'" \
    "" \
    "Authentication Test - Invalid Token (Should fail with 401)"

# Test 9: Missing authorization header
test_endpoint "POST" "/guardedHelloWorld" \
    "-H 'Content-Type: application/json'" \
    '{"name": "Test"}' \
    "Guarded Hello World - No Auth Header (Should fail with 401)"

# Test 10: Invalid request body
test_endpoint "POST" "/guardedHelloWorld" \
    "-H 'Authorization: Bearer demo-user123' -H 'Content-Type: application/json'" \
    '{"invalid": "request"}' \
    "Guarded Hello World - Invalid Request Body (Should fail with 400)"

echo -e "${GREEN}✅ Guard System Testing Complete!${NC}"
echo
echo -e "${BLUE}Performance Tips:${NC}"
echo "- Run the same requests again to see caching in action"
echo "- Check the console logs for guard performance metrics"
echo "- First request will be slower due to cache warmup"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo "- Try the fastify-production-api example for advanced guard strategies"
echo "- Modify the mock users in index-with-guards.ts to test different scenarios"
echo "- Check the console for detailed performance metrics in development mode"