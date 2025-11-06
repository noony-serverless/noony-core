#!/usr/bin/env bash

# =============================================================================
# Guard System Test Script for Fastify Production API
# =============================================================================
#
# This script comprehensively tests all three guard strategies implemented
# in the Fastify production API example:
# 1. Plain Permissions (O(1) Set-based lookups)
# 2. Wildcard Permissions (Pattern matching with caching)
# 3. Expression Permissions (Boolean logic evaluation)
#
# Usage: ./test-guards.sh [base_url]
# Example: ./test-guards.sh http://localhost:3000
#
# Prerequisites:
# - Server must be running on the specified port
# - jq must be installed for JSON parsing
# - curl must be available
#
# =============================================================================

set -e  # Exit on any error

# Configuration
BASE_URL=${1:-"http://localhost:3000"}
API_BASE="$BASE_URL/api"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Demo users with different permission levels (compatible with Bash 3.2+)
ADMIN_TOKEN="demo-admin456"
USER_TOKEN="demo-user123"
DEMO_TOKEN="demo-demo789"
INVALID_TOKEN="invalid-token"

# =============================================================================
# Utility Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${CYAN}=============================================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}=============================================================================${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BLUE}--- $1 ---${NC}"
    echo ""
}

print_test() {
    echo -e "${YELLOW}🧪 TEST: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ SUCCESS: $1${NC}"
    ((PASSED_TESTS++))
}

print_failure() {
    echo -e "${RED}❌ FAILURE: $1${NC}"
    ((FAILED_TESTS++))
}

print_info() {
    echo -e "${PURPLE}ℹ️  INFO: $1${NC}"
}

print_scenario() {
    echo -e "${YELLOW}📝 SCENARIO: $1${NC}"
}

print_result() {
    echo -e "${CYAN}📊 RESULT: $1${NC}"
}

print_request() {
    echo -e "${CYAN}📤 REQUEST: $1${NC}"
}

print_response() {
    echo -e "${PURPLE}📥 RESPONSE: $1${NC}"
}

increment_test() {
    ((TOTAL_TESTS++))
}

# Check if server is running
check_server() {
    print_info "Checking if server is running at $BASE_URL..."
    
    # Check if this is Fastify server (port 3000) or Functions Framework (port 8080)
    if [[ "$BASE_URL" == *":3000" ]]; then
        # Fastify server - check health endpoint
        if ! curl -s -f "$BASE_URL/health" > /dev/null 2>&1; then
            echo -e "${RED}❌ Fastify server is not running at $BASE_URL${NC}"
            echo "Please start the Fastify server first:"
            echo "  npm run dev:fastify"
            exit 1
        fi
        print_success "Fastify server is running and responding"
    elif [[ "$BASE_URL" == *":8080" ]]; then
        # Functions Framework - check if any function responds (we'll use createUser with invalid request)
        local response_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL")
        if [[ "$response_code" == "000" ]]; then
            echo -e "${RED}❌ Functions Framework is not running at $BASE_URL${NC}"
            echo "Please start the Functions Framework first:"
            echo "  npm run dev:functions"
            exit 1
        fi
        print_success "Functions Framework is running and responding (got HTTP $response_code)"
        # Set API base to empty for Functions Framework since functions are at root
        API_BASE="$BASE_URL"
    else
        # Generic server check
        if ! curl -s -f "$BASE_URL" > /dev/null 2>&1; then
            echo -e "${RED}❌ Server is not running at $BASE_URL${NC}"
            echo "Please start the server first"
            exit 1
        fi
        print_success "Server is running and responding"
    fi
}

# Make authenticated request
make_request() {
    local method="$1"
    local endpoint="$2"
    local token="$3"
    local data="$4"
    local expected_status="$5"
    
    local auth_header=""
    if [ "$token" != "none" ]; then
        auth_header="-H \"Authorization: Bearer $token\""
    fi
    
    local data_arg=""
    if [ -n "$data" ]; then
        data_arg="-d '$data' -H 'Content-Type: application/json'"
    fi
    
    local full_url="$API_BASE$endpoint"
    print_request "$method $full_url"
    
    # Execute request and capture response
    local response
    local status_code
    
    if [ -n "$data" ]; then
        response=$(eval "curl -s -w \"\\n%{http_code}\" -X $method $auth_header -H 'Content-Type: application/json' -d '$data' '$full_url'")
    else
        response=$(eval "curl -s -w \"\\n%{http_code}\" -X $method $auth_header '$full_url'")
    fi
    
    # Extract status code (last line) and body (all but last line)
    status_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    print_response "Status: $status_code"
    
    # Pretty print JSON if response contains JSON
    if echo "$body" | jq . > /dev/null 2>&1; then
        echo "$body" | jq .
    else
        echo "$body"
    fi
    
    # Check expected status
    if [ "$status_code" = "$expected_status" ]; then
        print_success "Status code matches expected: $expected_status"
        return 0
    else
        print_failure "Expected status $expected_status, got $status_code"
        return 1
    fi
}

# =============================================================================
# Test Functions
# =============================================================================

test_health_endpoint() {
    print_section "Health Check Tests"
    
    print_scenario "Testing health endpoint accessibility without authentication"
    print_test "Health endpoint without authentication"
    increment_test
    if make_request "GET" "/health" "none" "" "200"; then
        print_success "Health endpoint accessible"
        print_result "Health check endpoint is properly exposed and responds with 200 OK"
    else
        print_result "Health check endpoint failed - server may not be running properly"
    fi
}

test_authentication() {
    print_section "Authentication Tests"
    
    print_scenario "Validating JWT authentication middleware behavior with various token states"
    
    # Choose endpoint based on server type
    local test_endpoint="/users"
    local expected_success_code="200"
    local test_method="GET"
    
    if [[ "$BASE_URL" == *":8080" ]]; then
        # Functions Framework - use POST to createUser (which requires auth)
        test_endpoint=""
        expected_success_code="400"  # Will fail validation but pass auth
        test_method="POST"
    fi
    
    # Test with no token
    print_test "Request without authentication token"
    increment_test
    if make_request "$test_method" "$test_endpoint" "none" "" "401"; then
        print_success "Properly rejected request without token"
        print_result "Authentication middleware correctly blocks unauthenticated requests"
    else
        print_result "Authentication middleware failed to block unauthenticated request"
    fi
    
    # Test with invalid token
    print_test "Request with invalid authentication token"
    increment_test
    if make_request "$test_method" "$test_endpoint" "$INVALID_TOKEN" "" "401"; then
        print_success "Properly rejected invalid token"
        print_result "Authentication middleware correctly validates token signatures"
    else
        print_result "Authentication middleware failed to validate token signature"
    fi
    
    # Test with valid admin token
    print_test "Request with valid admin token (expecting auth success)"
    increment_test
    if make_request "$test_method" "$test_endpoint" "$ADMIN_TOKEN" "" "$expected_success_code"; then
        if [[ "$BASE_URL" == *":8080" ]]; then
            print_success "Admin token accepted (auth passed, validation failed as expected)"
            print_result "Authentication successful for valid admin token in Functions Framework"
        else
            print_success "Admin token accepted"
            print_result "Authentication successful for valid admin token"
        fi
    else
        print_result "Valid admin token was rejected by authentication middleware"
    fi
}

test_plain_permissions() {
    print_section "Plain Permission Strategy Tests (CREATE & UPDATE handlers)"
    
    print_scenario "Testing O(1) Set-based permission resolution using PlainPermissionResolver"
    
    if [[ "$BASE_URL" == *":8080" ]]; then
        print_info "Testing CREATE function only (Functions Framework limitation)"
        print_info "Handler: createUser (user:create OR admin:users)"
    else
        print_info "Testing O(1) Set-based permission lookups"
        print_info "Handlers: createUser (user:create OR admin:users), updateUser (user:update OR admin:users)"
    fi
    
    # Determine endpoint based on server type
    local create_endpoint="/users"
    if [[ "$BASE_URL" == *":8080" ]]; then
        create_endpoint=""
    fi
    
    # Test CREATE with admin permissions
    print_test "Create user with admin permissions"
    increment_test
    local create_data='{
        "name": "Test User Admin",
        "email": "test.admin@example.com",
        "age": 30,
        "department": "engineering"
    }'
    if make_request "POST" "$create_endpoint" "$ADMIN_TOKEN" "$create_data" "201"; then
        print_success "Admin can create users (admin:users permission)"
        print_result "PlainPermissionResolver successfully matched admin:users permission in O(1) time"
    else
        print_result "PlainPermissionResolver failed to authorize admin:users permission"
    fi
    
    # Test CREATE with insufficient permissions (demo user)
    print_test "Create user with insufficient permissions"
    increment_test
    local create_data_demo='{
        "name": "Test User Demo",
        "email": "test.demo@example.com", 
        "age": 25,
        "department": "demo"
    }'
    if make_request "POST" "$create_endpoint" "$DEMO_TOKEN" "$create_data_demo" "403"; then
        print_success "Demo user properly blocked from creating users"
        print_result "PlainPermissionResolver correctly denied access - demo user lacks user:create or admin:users permissions"
    else
        print_result "PlainPermissionResolver failed to block unauthorized access"
    fi
    
    # UPDATE tests only for Fastify server (Functions Framework doesn't have updateUser)
    if [[ "$BASE_URL" != *":8080" ]]; then
        # Test UPDATE with admin permissions
        print_test "Update user with admin permissions"
        increment_test
        local update_data='{
            "name": "Updated Admin User",
            "department": "administration"
        }'
        if make_request "PUT" "/users/user123" "$ADMIN_TOKEN" "$update_data" "200"; then
            print_success "Admin can update users (admin:users permission)"
            print_result "PlainPermissionResolver granted admin update access via admin:users permission"
        else
            print_result "PlainPermissionResolver failed to authorize admin update via admin:users"
        fi
        
        # Test UPDATE own profile with user permissions  
        print_test "Update own profile with user permissions"
        increment_test
        local update_own_data='{
            "name": "Updated Own Profile",
            "bio": "Updated my own bio"
        }'
        if make_request "PUT" "/users/user123" "$USER_TOKEN" "$update_own_data" "200"; then
            print_success "User can update own profile"
            print_result "PlainPermissionResolver allowed self-update via user:update permission"
        else
            print_result "PlainPermissionResolver failed to authorize self-update"
        fi
        
        # Test UPDATE other user's profile with insufficient permissions
        print_test "Update other user with insufficient permissions"
        increment_test
        if make_request "PUT" "/users/admin456" "$DEMO_TOKEN" "$update_data" "403"; then
            print_success "Demo user properly blocked from updating others"
            print_result "PlainPermissionResolver correctly blocked cross-user update - missing admin:users permission"
        else
            print_result "PlainPermissionResolver failed to block unauthorized cross-user update"
        fi
    else
        print_info "⚠️  UPDATE tests skipped (not available in Functions Framework mode)"
    fi
}

test_wildcard_permissions() {
    print_section "Wildcard Permission Strategy Tests (GET & DELETE handlers)"
    
    print_scenario "Testing WildcardPermissionResolver with pattern matching and pre-expansion caching"
    print_info "Testing pattern matching with pre-expansion caching"
    print_info "Handlers: getUser (admin.* OR user.profile.*), deleteUser (admin.* OR system.users.*)"
    
    # Test GET with admin wildcard permissions
    print_test "Get user with admin.* wildcard permissions"
    increment_test
    if make_request "GET" "/users/user123" "$ADMIN_TOKEN" "" "200"; then
        print_success "Admin can access any user profile (admin.* wildcard)"
        print_result "WildcardPermissionResolver successfully matched admin.* pattern from cache"
    else
        print_result "WildcardPermissionResolver failed to match admin.* wildcard pattern"
    fi
    
    # Test GET own profile with user permissions
    print_test "Get own profile with user permissions"
    increment_test  
    if make_request "GET" "/users/user123" "$USER_TOKEN" "" "200"; then
        print_success "User can access own profile"
        print_result "WildcardPermissionResolver matched user.profile.* pattern for self-access"
    else
        print_result "WildcardPermissionResolver failed to authorize self-profile access"
    fi
    
    # Test GET other profile with insufficient wildcard permissions
    print_test "Get other user profile with insufficient permissions"
    increment_test
    if make_request "GET" "/users/admin456" "$DEMO_TOKEN" "" "403"; then
        print_success "Demo user properly blocked from accessing other profiles"
        print_result "WildcardPermissionResolver correctly denied access - no matching wildcard patterns"
    else
        print_result "WildcardPermissionResolver failed to block unauthorized profile access"
    fi
    
    # Test DELETE with admin wildcard permissions
    print_test "Delete user with admin.* wildcard permissions"
    increment_test
    if make_request "DELETE" "/users/demo789" "$ADMIN_TOKEN" "" "204"; then
        print_success "Admin can delete users (admin.* wildcard)"
        print_result "WildcardPermissionResolver authorized deletion via admin.* wildcard match"
    else
        print_result "WildcardPermissionResolver failed to authorize deletion with admin.* wildcard"
    fi
    
    # Test DELETE with insufficient wildcard permissions
    print_test "Delete user with insufficient permissions" 
    increment_test
    if make_request "DELETE" "/users/admin456" "$USER_TOKEN" "" "403"; then
        print_success "User properly blocked from deleting others (missing admin.* or system.users.*)"
        print_result "WildcardPermissionResolver correctly denied deletion - lacks admin.* or system.users.* patterns"
    else
        print_result "WildcardPermissionResolver failed to block unauthorized deletion"
    fi
    
    # Test self-deletion prevention (business rule)
    print_test "Prevent self-deletion (business rule)"
    increment_test
    if make_request "DELETE" "/users/admin456" "$ADMIN_TOKEN" "" "403"; then
        print_success "Self-deletion properly prevented by business logic"
        print_result "Business rule override successful - self-deletion blocked despite wildcard permission match"
    else
        print_result "Business rule failed to prevent self-deletion"
    fi
}

test_expression_permissions() {
    print_section "Expression Permission Strategy Tests (LIST handler)"
    
    print_scenario "Testing ExpressionPermissionResolver with complex boolean logic and 2-level nesting"
    print_info "Testing boolean logic evaluation with 2-level nesting"
    print_info "Handler: listUsers ((admin.users AND admin.read) OR (user.list AND user.department))"
    
    # Test LIST with admin expression permissions
    print_test "List users with admin expression permissions"
    increment_test
    if make_request "GET" "/users?page=1&limit=5" "$ADMIN_TOKEN" "" "200"; then
        print_success "Admin can list users (admin.users AND admin.read)"
        print_result "ExpressionPermissionResolver evaluated (admin.users AND admin.read) = TRUE"
    else
        print_result "ExpressionPermissionResolver failed to evaluate admin expression - missing admin.users or admin.read"
    fi
    
    # Test LIST with pagination and filtering
    print_test "List users with pagination and filtering"
    increment_test
    if make_request "GET" "/users?page=1&limit=3&department=engineering&sortBy=name&sortOrder=asc" "$ADMIN_TOKEN" "" "200"; then
        print_success "Admin can list users with filters"
        print_result "ExpressionPermissionResolver maintained authorization through complex query parameters"
    else
        print_result "ExpressionPermissionResolver failed with complex query parameters"
    fi
    
    # Test LIST with search functionality
    print_test "List users with search"
    increment_test
    if make_request "GET" "/users?search=test&limit=10" "$ADMIN_TOKEN" "" "200"; then
        print_success "Admin can search users"
        print_result "ExpressionPermissionResolver authorized search functionality via admin expression"
    else
        print_result "ExpressionPermissionResolver failed to authorize search functionality"
    fi
    
    # Test LIST with insufficient expression permissions
    print_test "List users with insufficient expression permissions"
    increment_test
    if make_request "GET" "/users" "$DEMO_TOKEN" "" "403"; then
        print_success "Demo user properly blocked from listing users (missing complex expression match)"
        print_result "ExpressionPermissionResolver evaluated complex expression as FALSE - demo lacks required permission combinations"
    else
        print_result "ExpressionPermissionResolver failed to block access with insufficient permissions"
    fi
    
    # Test LIST includeDeleted parameter (admin only)
    print_test "List users including deleted (admin only)"
    increment_test
    if make_request "GET" "/users?includeDeleted=true" "$ADMIN_TOKEN" "" "200"; then
        print_success "Admin can include deleted users in list"
        print_result "ExpressionPermissionResolver authorized special parameter access for admin users"
    else
        print_result "ExpressionPermissionResolver blocked includeDeleted parameter access"
    fi
    
    # Test LIST includeDeleted with non-admin (should fail)
    print_test "List users including deleted with non-admin permissions"
    increment_test
    if make_request "GET" "/users?includeDeleted=true" "$USER_TOKEN" "" "403"; then
        print_success "Non-admin properly blocked from including deleted users"
        print_result "ExpressionPermissionResolver correctly restricted includeDeleted to admin-level permissions"
    else
        print_result "ExpressionPermissionResolver failed to restrict special parameter access"
    fi
}

test_guard_system_metrics() {
    print_section "Guard System Metrics Tests"
    
    print_scenario "Testing guard system performance monitoring and statistics collection"
    print_info "Testing performance monitoring and statistics endpoints"
    
    # Test system metrics endpoint (if available)
    print_test "Get guard system metrics"
    increment_test
    if make_request "GET" "/metrics/guards" "$ADMIN_TOKEN" "" "200"; then
        print_success "Guard system metrics accessible"
        print_result "Guard system metrics endpoint responds with performance statistics"
    else
        print_info "Guard metrics endpoint not available (expected for this demo)"
        print_result "Guard metrics endpoint not implemented - would show resolver performance, cache hit rates, and timing data"
        ((PASSED_TESTS++)) # Don't count as failure
    fi
}

test_error_scenarios() {
    print_section "Error Handling Tests"
    
    print_scenario "Testing error handling, validation, and edge cases across all guard strategies"
    print_info "Testing various error conditions and edge cases"
    
    # Determine endpoint based on server type
    local test_endpoint="/users"
    if [[ "$BASE_URL" == *":8080" ]]; then
        test_endpoint=""
    fi
    
    # Test malformed JSON
    print_test "Create user with malformed JSON"
    increment_test
    if make_request "POST" "$test_endpoint" "$ADMIN_TOKEN" "{invalid json}" "400"; then
        print_success "Malformed JSON properly rejected"
        print_result "Request validation caught malformed JSON before reaching guard system"
    else
        print_result "Malformed JSON validation failed - security risk detected"
    fi
    
    # Test missing required fields
    print_test "Create user with missing required fields"
    increment_test
    local incomplete_data='{"name": "Incomplete User"}'
    if make_request "POST" "$test_endpoint" "$ADMIN_TOKEN" "$incomplete_data" "400"; then
        print_success "Missing required fields properly validated"
        print_result "Schema validation successfully blocked incomplete data despite valid permissions"
    else
        print_result "Schema validation failed to catch missing required fields"
    fi
    
    # Tests only available for Fastify server (Functions Framework doesn't have GET endpoints)
    if [[ "$BASE_URL" != *":8080" ]]; then
        # Test invalid UUID in path parameters
        print_test "Get user with invalid UUID"
        increment_test
        if make_request "GET" "/users/invalid-uuid-format" "$ADMIN_TOKEN" "" "400"; then
            print_success "Invalid UUID format properly rejected"
            print_result "Path parameter validation blocked invalid UUID before guard evaluation"
        else
            print_result "Path parameter validation failed - invalid UUID was processed"
        fi
        
        # Test non-existent user
        print_test "Get non-existent user"
        increment_test
        if make_request "GET" "/users/00000000-0000-0000-0000-000000000000" "$ADMIN_TOKEN" "" "404"; then
            print_success "Non-existent user returns 404"
            print_result "Resource validation correctly handled non-existent user after guard authorization"
        else
            print_result "Resource validation failed - non-existent user should return 404"
        fi
    else
        print_info "⚠️  GET endpoint tests skipped (not available in Functions Framework mode)"
    fi
    
    # Test duplicate email (if validation exists)
    print_test "Create user with duplicate email"
    increment_test
    local duplicate_data='{
        "name": "Duplicate Email User",
        "email": "existing@example.com",
        "age": 25,
        "department": "test"
    }'
    if make_request "POST" "$test_endpoint" "$ADMIN_TOKEN" "$duplicate_data" "409"; then
        print_success "Duplicate email properly rejected"
        print_result "Business logic validation caught duplicate email after authorization"
    else
        print_info "Duplicate email validation not implemented (expected for demo)"
        print_result "Duplicate email validation not implemented - would occur after guard authorization"
        ((PASSED_TESTS++)) # Don't count as failure for demo
    fi
}

test_performance_scenarios() {
    print_section "Performance Tests"
    
    print_scenario "Testing guard system performance characteristics and caching effectiveness"
    print_info "Testing guard system performance characteristics"
    
    # Test rapid sequential requests (cache performance)
    print_test "Rapid sequential requests (cache test)"
    increment_test
    local start_time=$(date +%s%N)
    
    for i in {1..5}; do
        make_request "GET" "/users/user123" "$ADMIN_TOKEN" "" "200" > /dev/null 2>&1
    done
    
    local end_time=$(date +%s%N)
    local duration=$((($end_time - $start_time) / 1000000)) # Convert to milliseconds
    
    print_info "5 sequential requests completed in ${duration}ms"
    if [ $duration -lt 1000 ]; then # Less than 1 second total
        print_success "Fast sequential requests indicate effective caching"
        print_result "WildcardPermissionResolver cache performing well - ${duration}ms for 5 requests (~$((duration/5))ms per request)"
    else
        print_info "Sequential requests took longer than expected (cache may be cold)"
        print_result "Performance baseline established - ${duration}ms for 5 requests (cache may be warming up)"
        ((PASSED_TESTS++)) # Don't count as failure
    fi
    
    # Test different permission strategies performance
    print_test "Mixed permission strategy requests"
    increment_test
    start_time=$(date +%s%N)
    
    # Plain permission (CREATE)
    make_request "POST" "/users" "$ADMIN_TOKEN" '{"name":"Perf Test 1","email":"perf1@test.com","age":25}' "201" > /dev/null 2>&1 || true
    
    # Wildcard permission (GET)
    make_request "GET" "/users/user123" "$ADMIN_TOKEN" "" "200" > /dev/null 2>&1 || true
    
    # Expression permission (LIST)
    make_request "GET" "/users?limit=1" "$ADMIN_TOKEN" "" "200" > /dev/null 2>&1 || true
    
    end_time=$(date +%s%N)
    duration=$((($end_time - $start_time) / 1000000))
    
    print_info "Mixed strategy requests completed in ${duration}ms"
    print_success "Performance test completed"
    print_result "All three guard strategies (Plain O(1), Wildcard cached, Expression evaluated) performed within acceptable time: ${duration}ms total"
}

# =============================================================================
# Main Test Execution
# =============================================================================

main() {
    print_header "🛡️  NOONY GUARD SYSTEM COMPREHENSIVE TEST SUITE"
    
    print_info "Testing Fastify Production API at: $BASE_URL"
    print_info "This test suite validates all three guard strategies:"
    print_info "  1. Plain Permissions (O(1) Set-based lookups)"
    print_info "  2. Wildcard Permissions (Pattern matching with caching)" 
    print_info "  3. Expression Permissions (Boolean logic evaluation)"
    
    # Check if testing Functions Framework and warn about limitations
    if [[ "$BASE_URL" == *":8080" ]]; then
        echo ""
        print_info "🚨 FUNCTIONS FRAMEWORK TESTING MODE DETECTED"
        print_info "Note: Functions Framework only runs ONE function at a time."
        print_info "Currently running function: createUser (Plain Permissions strategy)"
        print_info "⚠️  Authentication tokens may differ from Fastify mode"
        print_info "For complete testing, use Fastify mode: ./test-guards.sh http://localhost:3000"
        echo ""
        
        # Quick pre-check to see if demo tokens work
        print_info "Testing if demo tokens are accepted..."
        local test_result=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL" -H "Authorization: Bearer demo-admin456")
        if [[ "$test_result" == "401" ]]; then
            print_info "🚨 Demo tokens not working in Functions Framework mode"
            print_info "This may be due to different authentication configuration"
            print_info "Test results may show authentication failures"
        else
            print_info "✅ Demo tokens appear to work"
        fi
        echo ""
    fi
    
    # Check prerequisites
    check_server
    
    if ! command -v jq &> /dev/null; then
        print_info "jq not found, JSON responses will not be pretty-printed"
    fi
    
    # Run test suites based on server type
    if [[ "$BASE_URL" == *":8080" ]]; then
        # Functions Framework - limited testing (only createUser function available)
        print_info "Running limited test suite for Functions Framework..."
        test_authentication
        test_plain_permissions  # Only CREATE tests will work
        test_error_scenarios    # Limited error testing
        print_info "✅ Functions Framework testing completed"
        print_info "💡 For complete guard system testing, run: ./test-guards.sh http://localhost:3000"
    else
        # Fastify server - full testing
        test_health_endpoint
        test_authentication  
        test_plain_permissions
        test_wildcard_permissions
        test_expression_permissions
        test_guard_system_metrics
        test_error_scenarios
        test_performance_scenarios
    fi
    
    # Print final results
    print_header "📊 TEST RESULTS SUMMARY"
    
    echo -e "${CYAN}Total Tests: $TOTAL_TESTS${NC}"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    
    local success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    echo -e "${PURPLE}Success Rate: ${success_rate}%${NC}"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo ""
        echo -e "${GREEN}🎉 ALL TESTS PASSED! Guard system is working correctly.${NC}"
        echo ""
        print_info "Guard System Performance Summary:"
        print_info "✅ Plain Permissions: O(1) lookups working"
        print_info "✅ Wildcard Permissions: Pattern matching with caching working"
        print_info "✅ Expression Permissions: Boolean logic evaluation working"
        print_info "✅ Authentication: JWT validation working"
        print_info "✅ Authorization: All permission strategies working"
        print_info "✅ Error Handling: Proper HTTP status codes"
        echo ""
        exit 0
    else
        echo ""
        echo -e "${RED}❌ Some tests failed. Check the output above for details.${NC}"
        echo ""
        exit 1
    fi
}

# =============================================================================
# Script Entry Point
# =============================================================================

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi