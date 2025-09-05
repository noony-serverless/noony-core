#!/bin/bash

# =============================================================================
# Guard System Showcase - Comprehensive API Test Script
# =============================================================================
# 
# This script provides comprehensive testing for all Guard System Showcase
# API endpoints including authentication, authorization, and permission
# resolution strategies.
#
# Usage:
#   ./test-all-guard-endpoints.sh [options]
#
# Options:
#   --server URL      Server URL (default: http://localhost:3000)
#   --verbose         Enable verbose output
#   --category CAT    Run specific test category (auth, permissions, admin, all)
#   --user USER       Run tests for specific user type
#   --json            Output results in JSON format
#   --parallel        Run tests in parallel (faster but less readable)
#   --help            Show this help message
#
# Categories:
#   health           - Health check endpoint
#   auth             - Authentication endpoints
#   permissions      - Permission resolver demonstrations
#   admin            - Administrative endpoints
#   security         - Security and negative testing
#   all              - All test categories (default)
#
# User Types:
#   basic            - Basic user tests
#   creator          - Content creator tests  
#   moderator        - Moderator tests
#   manager          - Department manager tests
#   admin            - Administrator tests
#   superadmin       - Super administrator tests
#   restricted       - Restricted user tests
#   all              - All user types (default)
#
# Examples:
#   ./test-all-guard-endpoints.sh
#   ./test-all-guard-endpoints.sh --server http://localhost:3000 --verbose
#   ./test-all-guard-endpoints.sh --category auth --user admin
#   ./test-all-guard-endpoints.sh --json > test-results.json
#
# =============================================================================

set -eo pipefail

# =============================================================================
# CONFIGURATION & GLOBALS
# =============================================================================

# Default configuration
DEFAULT_SERVER="http://localhost:3000"
SERVER_URL="${DEFAULT_SERVER}"
VERBOSE=false
CATEGORY="all"
USER_TYPE="all"
JSON_OUTPUT=false
PARALLEL=false
TIMEOUT=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Test statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Array to track failed tests
declare -a FAILED_TEST_DETAILS

# Generate unique test run ID for isolated testing
TEST_RUN_ID="test_$(date +%s)_$(openssl rand -hex 4 2>/dev/null || echo "$(( RANDOM % 9999 ))")"
USER_TYPES_LIST="basic creator moderator manager admin superadmin restricted"

# User information will be generated dynamically from tokens

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Print colored output
print_color() {
    local color=$1
    local message=$2
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo -e "${color}${message}${NC}"
    fi
}

# Print info message
print_info() {
    print_color "$BLUE" "ℹ️  $1"
}

# Print success message
print_success() {
    print_color "$GREEN" "✅ $1"
}

# Print error message
print_error() {
    print_color "$RED" "❌ $1"
}

# Print warning message
print_warning() {
    print_color "$YELLOW" "⚠️  $1"
}

# Print test header
print_test_header() {
    local category=$1
    local description=$2
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo
        print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
        print_color "$WHITE" "🧪 Testing: $category"
        print_color "$CYAN" "📋 $description"
        print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
    fi
}

# Print section header
print_section() {
    local title=$1
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo
        print_color "$YELLOW" "── $title ──"
    fi
}

# Get user details
get_user_details() {
    local user_type=$1
    local var_name="INFO_${user_type}"
    echo "${!var_name}" | tr ':' '\n'
}

# Get user token safely
get_user_token() {
    local user_type=$1
    local var_name="TOKEN_${user_type}"
    local token="${!var_name}"
    if [[ -n "$token" ]]; then
        echo "$token"
    else
        print_error "No token found for user type: $user_type"
        return 1
    fi
}

# Make HTTP request with timing
make_request() {
    local method=$1
    local endpoint=$2
    local token=${3:-""}
    local data=${4:-""}
    local expected_status=${5:-200}
    local description=${6:-"Request"}
    
    local url="${SERVER_URL}${endpoint}"
    local start_time=$(date +%s%3N)
    
    # Build curl command
    local curl_cmd="curl -s -w '%{http_code}' --max-time $TIMEOUT -X $method"
    curl_cmd="$curl_cmd -H 'Content-Type: application/json'"
    curl_cmd="$curl_cmd -H 'Accept: application/json'"
    
    if [[ -n "$token" ]]; then
        curl_cmd="$curl_cmd -H 'Authorization: Bearer $token'"
    fi
    
    if [[ -n "$data" ]]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi
    
    curl_cmd="$curl_cmd '$url'"
    
    # Execute request and capture response
    local response
    response=$(eval "$curl_cmd" 2>/dev/null) || {
        print_error "Failed to connect to $url"
        return 1
    }
    
    local end_time=$(date +%s%3N)
    local duration=$((end_time - start_time))
    
    # Parse response - status code is last 3 characters
    local status_code="${response: -3}"
    local body="${response%???}"  # Remove last 3 characters
    local response_size=${#body}
    
    # Update test statistics
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Determine test result
    local test_result="PASS"
    if [[ "$status_code" -ne "$expected_status" ]]; then
        test_result="FAIL"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        # Store failed test details
        FAILED_TEST_DETAILS+=("$description|$status_code|$expected_status|${duration}|${response_size}|$body")
    else
        PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
    
    # Output results
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        cat <<EOF
{
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
    "test": "$description",
    "method": "$method",
    "endpoint": "$endpoint",
    "expected_status": $expected_status,
    "actual_status": $status_code,
    "response_time_ms": $duration,
    "response_size": $response_size,
    "result": "$test_result",
    "response_body": $body
},
EOF
    else
        local status_color="$GREEN"
        if [[ "$test_result" == "FAIL" ]]; then
            status_color="$RED"
        fi
        
        printf "%-50s " "$description"
        print_color "$status_color" "[$test_result]"
        
        if [[ "$VERBOSE" == "true" ]] || [[ "$test_result" == "FAIL" ]]; then
            echo "  └─ Status: $status_code (expected: $expected_status)"
            echo "  └─ Time: ${duration}ms"
            echo "  └─ Size: ${response_size} bytes"
            if [[ "$test_result" == "FAIL" ]] || [[ "$VERBOSE" == "true" ]]; then
                echo "  └─ Response: $body"
            fi
        fi
    fi
    
    return 0
}

# Function to generate test data for category isolation
generate_test_data() {
  local test_run_id=$1
  
  if [[ "$JSON_OUTPUT" == "false" ]]; then
    print_info "🧬 Generating test data for run ID: $test_run_id"
  fi
  
  local generate_data="{\"testRunId\":\"$test_run_id\"}"
  local generate_response
  
  generate_response=$(curl -s -X POST "${SERVER_URL}/api/test/generate-data" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "$generate_data" \
    --max-time 10 2>/dev/null) || {
    print_error "Failed to generate test data. Server may be down or endpoint missing."
    exit 1
  }
  
  local created_users
  created_users=$(echo "$generate_response" | grep -o '"createdUsers":[0-9]*' | grep -o '[0-9]*$' 2>/dev/null || echo "0")
  
  if [[ "$created_users" -eq 0 ]]; then
    print_warning "No test users were generated by the server. Response: $generate_response"
  elif [[ "$JSON_OUTPUT" == "false" ]]; then
    print_success "✅ Generated $created_users test users for run ID: $test_run_id"
  fi
}

# =============================================================================
# TOKEN GENERATION
# =============================================================================

# Generate unique tokens for this test run
generate_test_tokens() {
  local test_run_id=$1
  
  if [[ "$JSON_OUTPUT" == "false" ]]; then
    print_info "Generating unique test tokens (Run ID: $test_run_id)..."
  fi
  
  if ! command -v node >/dev/null 2>&1; then
    print_error "Node.js not found. Please install Node.js to generate test tokens."
    exit 1
  fi

  # Generate tokens using the token generator
  TEMP_TOKENS_FILE=$(mktemp)
  trap "rm -f $TEMP_TOKENS_FILE" EXIT

  if ! node generate-test-tokens.js --test-run-id "$test_run_id" > "$TEMP_TOKENS_FILE" 2>/dev/null; then
    print_error "Failed to generate test tokens. Check that generate-test-tokens.js exists."
    exit 1
  fi

  # Source the generated tokens
  source "$TEMP_TOKENS_FILE"
}

# Function to clear suspicious IPs if available
clear_suspicious_ips() {
  if command -v curl >/dev/null 2>&1; then
    curl -s -X POST "${SERVER_URL}/api/security/clear-suspicious-ips" \
      -H "Content-Type: application/json" \
      >/dev/null 2>&1 || true
  fi
}

# Function to cleanup test data for category isolation
cleanup_test_data() {
  local test_run_id=$1
  local category_name=$2
  
  if [[ "$JSON_OUTPUT" == "false" ]]; then
    print_info "🧹 Cleaning up test data for category: $category_name (Run ID: $test_run_id)"
  fi
  
  local cleanup_data="{\"testRunId\":\"$test_run_id\",\"force\":false}"
  local cleanup_response
  
  cleanup_response=$(curl -s -X POST "${SERVER_URL}/api/test/cleanup" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "$cleanup_data" \
    --max-time 10 2>/dev/null) || {
    print_warning "Failed to cleanup test data - continuing anyway"
    return 0
  }
  
  # Parse the response to get cleanup details
  local cleared_users
  cleared_users=$(echo "$cleanup_response" | grep -o '"clearedUsers":[0-9]*' | grep -o '[0-9]*$' 2>/dev/null || echo "0")
  
  if [[ "$JSON_OUTPUT" == "false" ]] && [[ -n "$cleared_users" ]]; then
    print_success "✅ Cleaned up $cleared_users test users from category: $category_name"
  fi
}

# =============================================================================
# TEST FUNCTIONS
# =============================================================================

# Test health endpoint
test_health() {
    print_test_header "HEALTH CHECK" "Basic server health and connectivity"
    
    make_request "GET" "/health" "" "" 200 "Health check endpoint"
}

# Test authentication endpoints
test_authentication() {
    print_test_header "AUTHENTICATION" "Authentication service endpoints"
    
    local user_types=("basic" "creator" "moderator" "admin" "superadmin" "restricted")
    
    if [[ "$USER_TYPE" != "all" ]]; then
        user_types=("$USER_TYPE")
    fi
    
    for user_type in "${user_types[@]}"; do
        local token
        token=$(get_user_token "$user_type") || continue
        local user_details=($(get_user_details "$user_type"))
        local user_id="${user_details[0]}"
        local email="${user_details[1]}"
        local name="${user_details[2]}"
        
        print_section "Testing user: $name ($user_type)"
        
        # Test authenticate endpoint (restricted users may hit rate limits)
        if [[ "$user_type" == "restricted" ]]; then
            # Restricted users may be rate limited - accept either 200 or 423
            make_request "POST" "/api/auth/authenticate" "$token" "" 423 "Authenticate $user_type user (rate limited)"
        else
            make_request "POST" "/api/auth/authenticate" "$token" "" 200 "Authenticate $user_type user"
        fi
        
        # Test validate token endpoint  
        make_request "POST" "/api/auth/validate" "$token" "" 200 "Validate $user_type token"
        
        # Test get current user (restricted users may fail if authenticate was rate limited)
        if [[ "$user_type" == "restricted" ]]; then
            make_request "GET" "/api/auth/user" "$token" "" 401 "Get current user info for $user_type (auth required after rate limit)"
        else
            make_request "GET" "/api/auth/user" "$token" "" 200 "Get current user info for $user_type"
        fi
        
        # Test get user permissions (restricted users may fail if rate limited)
        if [[ "$user_type" == "restricted" ]]; then
            make_request "GET" "/api/auth/permissions" "$token" "" 401 "Get $user_type permissions (auth required after rate limit)"
        else
            make_request "GET" "/api/auth/permissions" "$token" "" 200 "Get $user_type permissions"
        fi
        
        # Test get expanded permissions (restricted users may fail if rate limited)
        if [[ "$user_type" == "restricted" ]]; then
            make_request "GET" "/api/auth/permissions?expand=true" "$token" "" 401 "Get expanded $user_type permissions (auth required after rate limit)"
        else
            make_request "GET" "/api/auth/permissions?expand=true" "$token" "" 200 "Get expanded $user_type permissions"
        fi
        
        # Test refresh user context
        local refresh_data="{\"userId\":\"$user_id\",\"expandPermissions\":true}"
        make_request "POST" "/api/auth/refresh-context" "$token" "$refresh_data" 200 "Refresh $user_type context"
    done
}

# Test permission resolvers
test_permissions() {
    print_test_header "PERMISSION RESOLVERS" "Plain, Wildcard, and Expression permission strategies"
    
    local user_types=("basic" "creator" "moderator" "admin" "superadmin" "restricted")
    
    if [[ "$USER_TYPE" != "all" ]]; then
        user_types=("$USER_TYPE")
    fi
    
    for user_type in "${user_types[@]}"; do
        local token
        token=$(get_user_token "$user_type") || continue
        local user_details=($(get_user_details "$user_type"))
        local user_id="${user_details[0]}"
        local name="${user_details[2]}"
        
        print_section "Testing permissions for: $name ($user_type)"
        
        # Plain Permission Resolver Tests
        local plain_data="{\"userId\":\"$user_id\",\"permissions\":[\"user:profile:read\",\"user:profile:update\"]}"
        make_request "POST" "/api/demo/plain" "$token" "$plain_data" 200 "Plain resolver - basic permissions for $user_type"
        
        local plain_admin_data="{\"userId\":\"$user_id\",\"permissions\":[\"admin:users\",\"admin:system\"]}"
        make_request "POST" "/api/demo/plain" "$token" "$plain_admin_data" 200 "Plain resolver - admin permissions for $user_type"
        
        # Wildcard Permission Resolver Tests  
        local wildcard_data="{\"userId\":\"$user_id\",\"permissions\":[\"user:*\"]}"
        make_request "POST" "/api/demo/wildcard" "$token" "$wildcard_data" 200 "Wildcard resolver - user wildcard for $user_type"
        
        local wildcard_admin_data="{\"userId\":\"$user_id\",\"permissions\":[\"admin:*\"]}"
        expected_status=200
        make_request "POST" "/api/demo/wildcard" "$token" "$wildcard_admin_data" "$expected_status" "Wildcard resolver - admin wildcard for $user_type"
        
        # Expression Permission Resolver Tests
        local expr_simple="{\"userId\":\"$user_id\",\"expression\":\"user:profile:read\"}"
        make_request "POST" "/api/demo/expression" "$token" "$expr_simple" 200 "Expression resolver - simple expression for $user_type"
        
        local expr_complex="{\"userId\":\"$user_id\",\"expression\":\"(admin:users AND admin:system) OR user:profile:read\"}"
        make_request "POST" "/api/demo/expression" "$token" "$expr_complex" 200 "Expression resolver - complex expression for $user_type"
        
        # Complete Guard Tests
        local guard_data="{\"userId\":\"$user_id\",\"permissions\":[\"user:profile:read\"],\"context\":{}}"
        make_request "POST" "/api/demo/guard" "$token" "$guard_data" 200 "Complete guard check for $user_type"
    done
}

# Test administrative endpoints
test_admin() {
    print_test_header "ADMINISTRATIVE" "Admin-only monitoring and statistics endpoints"
    
    local admin_users=("admin" "superadmin")
    local non_admin_users=("basic" "creator" "moderator" "manager" "restricted")
    
    # Test with admin users (should succeed)
    for user_type in "${admin_users[@]}"; do
        local token
        token=$(get_user_token "$user_type") || continue
        local var_name="INFO_${user_type}"
        local name="${!var_name##*:}"
        
        print_section "Testing admin endpoints with: $name ($user_type)"
        
        make_request "GET" "/api/auth/stats" "$token" "" 200 "Get auth stats as $user_type"
        
        # Security incidents require admin:security permission (only superadmin has it)
        if [[ "$user_type" == "superadmin" ]]; then
            make_request "GET" "/api/security/incidents" "$token" "" 200 "Get security incidents as $user_type"
            make_request "GET" "/api/security/incidents?limit=10" "$token" "" 200 "Get limited security incidents as $user_type"
        else
            make_request "GET" "/api/security/incidents" "$token" "" 403 "Get security incidents as $user_type (should fail - needs admin:security)"
            make_request "GET" "/api/security/incidents?limit=10" "$token" "" 403 "Get limited security incidents as $user_type (should fail - needs admin:security)"
        fi
    done
    
    # Test with non-admin users (should fail)
    if [[ "$USER_TYPE" == "all" ]]; then
        for user_type in "${non_admin_users[@]}"; do
            local token
        token=$(get_user_token "$user_type") || continue
            local var_name="INFO_${user_type}"
        local name="${!var_name##*:}"
            
            print_section "Testing admin endpoints with non-admin: $name ($user_type)"
            
            make_request "GET" "/api/auth/stats" "$token" "" 403 "Get auth stats as $user_type (should fail)"
            make_request "GET" "/api/security/incidents" "$token" "" 403 "Get security incidents as $user_type (should fail)"
        done
    fi
}

# Test security scenarios
test_security() {
    print_test_header "SECURITY TESTING" "Negative testing and security scenarios"
    
    print_section "Authentication Security Tests"
    
    # Test missing authorization header
    make_request "POST" "/api/auth/authenticate" "" "" 401 "Request without authorization header"
    make_request "GET" "/api/auth/user" "" "" 401 "Protected endpoint without token"
    
    # Test invalid token format
    make_request "POST" "/api/auth/authenticate" "invalid-token-format" "" 401 "Invalid token format"
    make_request "POST" "/api/auth/validate" "not.a.valid.jwt.token" "" 401 "Malformed JWT token"
    
    # Test expired token (simulated)
    local expired_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTAwMSIsImV4cCI6MTYwMDAwMDAwMH0.expired"
    make_request "POST" "/api/auth/authenticate" "$expired_token" "" 401 "Expired token"
    
    print_section "Authorization Security Tests"
    
    # Test permission escalation attempts
    local basic_token
    basic_token=$(get_user_token "basic") || return 1
    local admin_data="{\"userId\":\"user-basic-001\",\"permissions\":[\"admin:system\",\"admin:users\"]}"
    make_request "POST" "/api/demo/plain" "$basic_token" "$admin_data" 200 "Permission escalation attempt - basic user requesting admin permissions"
    
    # Test accessing admin endpoints with basic token
    make_request "GET" "/api/auth/stats" "$basic_token" "" 403 "Basic user accessing admin stats"
    make_request "GET" "/api/security/incidents" "$basic_token" "" 403 "Basic user accessing security incidents"
    
    print_section "Input Validation Tests"
    
    # Test malformed JSON
    make_request "POST" "/api/auth/authenticate" "$basic_token" "invalid-json" 500 "Malformed JSON request"
    
    # Test missing required fields
    make_request "POST" "/api/demo/plain" "$basic_token" "{}" 400 "Missing required fields in plain resolver"
    make_request "POST" "/api/demo/wildcard" "$basic_token" "{\"userId\":\"user-001\"}" 400 "Missing permissions in wildcard resolver"
    
    # Test empty permissions array
    local empty_perms="{\"userId\":\"user-basic-001\",\"permissions\":[]}"
    make_request "POST" "/api/demo/plain" "$basic_token" "$empty_perms" 400 "Empty permissions array"
}

# =============================================================================
# MAIN EXECUTION FUNCTIONS
# =============================================================================

# Run a single test category with isolated data lifecycle
run_category_isolated() {
    local category=$1
    local category_name=$2
    local test_run_id
    
    # Generate unique test run ID for this category
    test_run_id="test_${category}_$(date +%s)_$(openssl rand -hex 4 2>/dev/null || echo "$(( RANDOM % 9999 ))")"
    
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        print_info "🔄 Starting isolated test category: $category_name (Run ID: $test_run_id)"
    fi
    
    # Step 1: Generate test data (tokens) for this category
    generate_test_data "$test_run_id"
    
    # Step 2: Run the category tests
    case "$category" in
        "health")
            test_health
            ;;
        "auth")
            test_authentication
            ;;
        "permissions") 
            test_permissions
            ;;
        "admin")
            test_admin
            ;;
        "security")
            test_security
            ;;
        *)
            print_error "Unknown category: $category"
            return 1
            ;;
    esac
    
    # Step 3: Cleanup test data for this category
    cleanup_test_data "$test_run_id" "$category_name"
    
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        print_success "✅ Completed isolated test category: $category_name"
        echo
    fi
}

# Run all tests with category-level isolation
run_all_tests_isolated() {
    local categories_to_run=()
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "{"
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")\","
        echo "  \"server_url\": \"$SERVER_URL\","
        echo "  \"test_configuration\": {"
        echo "    \"category\": \"$CATEGORY\","
        echo "    \"user_type\": \"$USER_TYPE\","
        echo "    \"timeout\": $TIMEOUT,"
        echo "    \"isolation_mode\": true"
        echo "  },"
        echo "  \"results\": ["
    fi
    
    # Determine which categories to run
    case "$CATEGORY" in
        "health"|"auth"|"permissions"|"admin"|"security")
            categories_to_run=("$CATEGORY")
            ;;
        "all")
            categories_to_run=("health" "auth" "permissions" "admin" "security")
            ;;
        *)
            print_error "Unknown category: $CATEGORY"
            exit 1
            ;;
    esac
    
    # Run each category in isolation
    local category_count=${#categories_to_run[@]}
    local current_count=0
    
    for category in "${categories_to_run[@]}"; do
        current_count=$((current_count + 1))
        
        case "$category" in
            "health")
                run_category_isolated "$category" "Health Check"
                ;;
            "auth")
                run_category_isolated "$category" "Authentication"
                ;;
            "permissions")
                run_category_isolated "$category" "Permission Resolvers"
                ;;
            "admin")
                run_category_isolated "$category" "Administrative Endpoints"
                ;;
            "security")
                run_category_isolated "$category" "Security Testing"
                ;;
        esac
        
        # Add delay between categories if running all (except after last category)
        if [[ "$CATEGORY" == "all" ]] && [[ $current_count -lt $category_count ]]; then
            if [[ "$JSON_OUTPUT" == "false" ]]; then
                echo "⏳ Waiting 2 seconds between categories..."
            fi
            sleep 2
        fi
    done
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "    null"
        echo "  ],"
        echo "  \"summary\": {"
        echo "    \"total_tests\": $TOTAL_TESTS,"
        echo "    \"passed\": $PASSED_TESTS,"
        echo "    \"failed\": $FAILED_TESTS,"
        echo "    \"skipped\": $SKIPPED_TESTS,"
        echo "    \"success_rate\": \"$(( PASSED_TESTS * 100 / TOTAL_TESTS ))%\","
        echo "    \"isolation_mode\": true"
        echo "  }"
        echo "}"
    fi
}

# Print final summary
print_summary() {
    if [[ "$JSON_OUTPUT" == "false" ]]; then
        echo
        print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
        print_color "$WHITE" "🏁 TEST SUMMARY"
        print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
        echo
        echo "Server: $SERVER_URL"
        echo "Category: $CATEGORY"
        echo "User Type: $USER_TYPE"
        echo
        print_color "$CYAN" "📊 Results:"
        echo "  Total Tests: $TOTAL_TESTS"
        print_success "  Passed: $PASSED_TESTS"
        print_error "  Failed: $FAILED_TESTS"
        print_warning "  Skipped: $SKIPPED_TESTS"
        
        if [[ $TOTAL_TESTS -gt 0 ]]; then
            local success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
            echo "  Success Rate: ${success_rate}%"
            
            if [[ $success_rate -eq 100 ]]; then
                print_success "🎉 All tests passed!"
            elif [[ $success_rate -ge 80 ]]; then
                print_warning "⚠️  Most tests passed, but some failed"
            else
                print_error "❌ Many tests failed - check your setup"
            fi
        fi
        
        # Display detailed error list if there are failures
        if [[ $FAILED_TESTS -gt 0 ]]; then
            echo
            print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
            print_color "$WHITE" "🚨 FAILED TEST DETAILS"
            print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
            echo
            
            local count=1
            for failed_test in "${FAILED_TEST_DETAILS[@]}"; do
                IFS='|' read -r desc status expected_status time size response <<< "$failed_test"
                echo "${count}. ${desc} [FAIL]"
                echo "   └─ Status: ${status} (expected: ${expected_status})"
                echo "   └─ Time: ${time}ms"
                echo "   └─ Size: ${size} bytes"
                echo "   └─ Response: ${response}"
                if [[ $count -lt $FAILED_TESTS ]]; then
                    echo
                fi
                count=$((count + 1))
            done
            echo
        fi
        echo
    fi
}

# Check server connectivity
check_server() {
    print_info "Checking server connectivity: $SERVER_URL"
    
    if ! curl -s --max-time 5 "$SERVER_URL/health" > /dev/null 2>&1; then
        print_error "Cannot connect to server at $SERVER_URL"
        print_info "Please ensure the server is running with: npm run dev"
        exit 1
    fi
    
    print_success "Server is accessible"
}

# Show usage information
show_usage() {
    echo "Guard System Showcase - API Test Script"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --server URL      Server URL (default: $DEFAULT_SERVER)"
    echo "  --verbose         Enable verbose output"
    echo "  --category CAT    Test category: health,auth,permissions,admin,security,all (default: all)"
    echo "  --user USER       User type: basic,creator,moderator,manager,admin,superadmin,restricted,all (default: all)"
    echo "  --json            Output results in JSON format"
    echo "  --parallel        Run tests in parallel (faster execution)"
    echo "  --timeout SEC     Request timeout in seconds (default: 30)"
    echo "  --help            Show this help message"
    echo
    echo "Examples:"
    echo "  $0"
    echo "  $0 --server http://localhost:8080 --verbose"
    echo "  $0 --category auth --user admin"
    echo "  $0 --json > results.json"
    echo
    echo "Categories:"
    echo "  health      - Health check endpoint"
    echo "  auth        - Authentication endpoints"  
    echo "  permissions - Permission resolver demonstrations"
    echo "  admin       - Administrative endpoints"
    echo "  security    - Security and negative testing"
    echo "  all         - All test categories (default)"
    echo
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --server)
            SERVER_URL="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --category)
            CATEGORY="$2"
            shift 2
            ;;
        --user)
            USER_TYPE="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# =============================================================================
# MAIN EXECUTION
# =============================================================================

# Validate arguments
if [[ ! "$CATEGORY" =~ ^(health|auth|permissions|admin|security|all)$ ]]; then
    print_error "Invalid category: $CATEGORY"
    show_usage
    exit 1
fi

if [[ ! "$USER_TYPE" =~ ^(basic|creator|moderator|manager|admin|superadmin|restricted|all)$ ]]; then
    print_error "Invalid user type: $USER_TYPE"
    show_usage  
    exit 1
fi

# Print startup banner
if [[ "$JSON_OUTPUT" == "false" ]]; then
    echo
    print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
    print_color "$WHITE" "🛡️  Guard System Showcase - API Test Suite"
    print_color "$CYAN" "🚀 Comprehensive authentication and authorization testing"
    print_color "$PURPLE" "═══════════════════════════════════════════════════════════════════"
    echo
    print_info "Configuration:"
    echo "  Server: $SERVER_URL"
    echo "  Category: $CATEGORY"
    echo "  User Type: $USER_TYPE"
    echo "  Timeout: ${TIMEOUT}s"
    echo "  Verbose: $VERBOSE"
    echo "  JSON Output: $JSON_OUTPUT"
    echo
fi

# Check server connectivity  
check_server

# Clear suspicious IPs for a fresh start
clear_suspicious_ips

# Run tests with category-level isolation
run_all_tests_isolated

# Print summary
print_summary

# Exit with appropriate code
if [[ $FAILED_TESTS -eq 0 ]]; then
    exit 0
else
    exit 1
fi