#!/bin/bash
#
# Storage API Conformance Test Runner
#
# This script handles service lifecycle management, port conflicts, and flexible test execution.
# It is designed to be AI-agent-friendly for automated testing workflows.
#
# Usage: ./run_tests.sh [OPTIONS] [BACKEND]
#
# Examples:
#   ./run_tests.sh                          # Run all tests with filesystem backend (default)
#   ./run_tests.sh backend_name             # Run tests with specified backend
#   ./run_tests.sh -k "stat"                # Run only stat-related tests
#   ./run_tests.sh --no-parallel --verbose  # Debug mode: serial execution with verbose output
#   ./run_tests.sh --force                  # Kill any existing service on ports first
#   ./run_tests.sh --service-only           # Start service and wait (for manual testing)
#   ./run_tests.sh --test-only              # Run tests against already-running service
#

set -e

# =============================================================================
# Configuration (can be overridden via environment variables)
# =============================================================================

GRPC_PORT=${GRPC_PORT:-50051}
HTTP_PORT=${HTTP_PORT:-8011}
SERVICE_TIMEOUT=${SERVICE_TIMEOUT:-30}
PARALLEL_WORKERS=${PARALLEL_WORKERS:-8}
STORAGE_DIR="${STORAGE_DIR:-}"
BACKEND="${BACKEND:-filesystem}"

# For custom backends: additional arguments to pass to the backend subcommand
# Example: BACKEND_ARGS="--connection-string 'DefaultEndpointsProtocol=http;...' --container my-container"
BACKEND_ARGS="${BACKEND_ARGS:-}"

# For custom backends: the resource base URL for tests (REQUIRED for non-filesystem backends)
# Example: TEST_STORAGE_API_RESOURCE_BASE="azurite-storage://my-service"
# This is implementation-dependent and must be provided by the user
TEST_STORAGE_API_RESOURCE_BASE="${TEST_STORAGE_API_RESOURCE_BASE:-}"

# =============================================================================
# Script Variables
# =============================================================================

SERVICE_PID=""
CREATED_STORAGE_DIR=false
FORCE_KILL=false
PARALLEL=true
VERBOSE=false
SERVICE_ONLY=false
TEST_ONLY=false
KEYWORD=""
MARKERS=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

show_usage() {
    cat << EOF
Storage API Conformance Test Runner

USAGE:
    ./run_tests.sh [OPTIONS] [BACKEND]

BACKENDS:
    filesystem              Local filesystem backend (default, no extra config needed)
    <custom>                Custom backends require BACKEND_ARGS and TEST_STORAGE_API_RESOURCE_BASE

OPTIONS:
    -h, --help              Show this help message
    -f, --force             Kill any existing service on the ports before starting
    -k, --keyword PATTERN   Run only tests matching pattern (passed to pytest -k)
    -m, --markers EXPR      Run only tests matching marker expression (pytest -m)
    --no-parallel           Run tests serially (slower but clearer output for debugging)
    --parallel N            Number of parallel workers (default: $PARALLEL_WORKERS)
    -v, --verbose           Extra test output (pytest -vv)
    --service-only          Start service and wait (don't run tests)
    --test-only             Run tests without starting service (assume already running)
    --clean                 Clean up temp files and exit

ENVIRONMENT VARIABLES:
    GRPC_PORT               gRPC port (default: 50051)
    HTTP_PORT               HTTP port (default: 8011)
    STORAGE_DIR             Storage directory for filesystem backend (default: auto-created temp dir)
    SERVICE_TIMEOUT         Seconds to wait for service ready (default: 30)
    PARALLEL_WORKERS        Number of pytest-xdist workers (default: 8)
    BACKEND                 Backend to test (default: filesystem)

  Custom Backend Variables (REQUIRED for non-filesystem backends):
    TEST_STORAGE_API_RESOURCE_BASE
                            Resource base URL for tests. This is implementation-dependent
                            and must match what your backend's capabilities endpoint returns.
                            Example: "azurite-storage://my-azurite-service"

    BACKEND_ARGS            Additional arguments to pass to the backend subcommand.
                            These are passed directly after the backend name.
                            Example: "--connection-string 'connstr' --container test-bucket"

EXAMPLES:
    # Default: Run all tests with filesystem backend
    ./run_tests.sh

    # Run specific tests with filesystem backend
    ./run_tests.sh -k "stat" --verbose

    # Run with a custom backend (e.g., hypothetical azurite backend)
    TEST_STORAGE_API_RESOURCE_BASE="azurite-storage://azurite" \\
    BACKEND_ARGS="--connection-string 'DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;...' --container conformance-tests" \\
    ./run_tests.sh azurite

    # Run tests serially with verbose output (for debugging)
    ./run_tests.sh --no-parallel --verbose -k "stat"

    # Force restart if service is already running
    ./run_tests.sh --force

    # Start service only (for manual API exploration)
    ./run_tests.sh --service-only

    # Run tests against already-running service (must set resource base)
    TEST_STORAGE_API_RESOURCE_BASE="azurite-storage://azurite" \\
    ./run_tests.sh --test-only azurite

    # Run only gRPC or REST tests
    ./run_tests.sh -m "grpc"
    ./run_tests.sh -m "rest"

CUSTOM BACKEND SETUP:
    For non-filesystem backends, you must:
    1. Set TEST_STORAGE_API_RESOURCE_BASE to match your backend's resource base URL
       (check your backend's capabilities endpoint or implementation)
    2. Set BACKEND_ARGS with any backend-specific command line arguments
    3. Ensure any external dependencies (e.g., Azurite emulator) are running

    See README.md for detailed custom backend documentation.
EOF
}

# =============================================================================
# Dependency Checks
# =============================================================================

check_dependencies() {
    local missing=()

    if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
        missing+=("python/python3")
    fi

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        print_error "Missing required dependencies: ${missing[*]}"
        print_info "Please install the missing dependencies and try again."
        exit 1
    fi
}

# =============================================================================
# Port Management Functions
# =============================================================================

check_port_available() {
    local port=$1
    
    # Try lsof first (most common)
    if command -v lsof &> /dev/null; then
        if lsof -i ":$port" -sTCP:LISTEN &> /dev/null; then
            return 1  # Port is in use
        fi
        return 0  # Port is available
    fi
    
    # Fallback to ss
    if command -v ss &> /dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            return 1  # Port is in use
        fi
        return 0  # Port is available
    fi
    
    # Fallback to netstat
    if command -v netstat &> /dev/null; then
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            return 1  # Port is in use
        fi
        return 0  # Port is available
    fi
    
    # Last resort: try to connect
    if command -v nc &> /dev/null; then
        if nc -z localhost "$port" 2>/dev/null; then
            return 1  # Port is in use
        fi
        return 0  # Port is available
    fi
    
    # Can't check, assume available
    print_warning "Cannot check port availability (no lsof, ss, netstat, or nc found)"
    return 0
}

get_pid_on_port() {
    local port=$1
    
    if command -v lsof &> /dev/null; then
        lsof -t -i ":$port" -sTCP:LISTEN 2>/dev/null || true
    elif command -v ss &> /dev/null; then
        ss -tlnp 2>/dev/null | grep ":$port " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1
    elif command -v netstat &> /dev/null; then
        netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 | head -1
    fi
}

kill_process_on_port() {
    local port=$1
    local pids
    
    pids=$(get_pid_on_port "$port")
    
    if [ -z "$pids" ]; then
        return 0
    fi
    
    for pid in $pids; do
        if [ -n "$pid" ] && [ "$pid" != "-" ]; then
            print_info "Killing process $pid on port $port..."
            kill "$pid" 2>/dev/null || true
            
            # Wait up to 5 seconds for graceful shutdown
            local count=0
            while [ $count -lt 5 ] && kill -0 "$pid" 2>/dev/null; do
                sleep 1
                count=$((count + 1))
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                print_warning "Process $pid didn't stop gracefully, forcing..."
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
    done
    
    # Give ports time to be released
    sleep 1
}

ensure_ports_free() {
    local ports_in_use=()
    
    if ! check_port_available "$GRPC_PORT"; then
        ports_in_use+=("$GRPC_PORT (gRPC)")
    fi
    
    if ! check_port_available "$HTTP_PORT"; then
        ports_in_use+=("$HTTP_PORT (HTTP)")
    fi
    
    if [ ${#ports_in_use[@]} -eq 0 ]; then
        return 0
    fi
    
    if [ "$FORCE_KILL" = true ]; then
        print_info "Ports in use: ${ports_in_use[*]}"
        print_info "Force flag set, killing existing processes..."
        
        kill_process_on_port "$GRPC_PORT"
        kill_process_on_port "$HTTP_PORT"
        
        # Verify ports are now free
        if ! check_port_available "$GRPC_PORT" || ! check_port_available "$HTTP_PORT"; then
            print_error "Failed to free ports. Please manually kill processes and try again."
            print_info "Try: lsof -i :$HTTP_PORT -i :$GRPC_PORT"
            exit 1
        fi
        
        print_success "Ports freed successfully"
    else
        print_error "Ports already in use: ${ports_in_use[*]}"
        echo ""
        print_info "Options:"
        echo "  1. Use --force to kill existing processes"
        echo "  2. Use --test-only to run tests against the existing service"
        echo "  3. Manually stop the service: pkill -f 'local-filesystem-service'"
        echo ""
        print_info "To see what's using the ports:"
        echo "  lsof -i :$HTTP_PORT -i :$GRPC_PORT"
        exit 1
    fi
}

# =============================================================================
# Service Lifecycle Functions
# =============================================================================

start_service() {
    print_info "Starting $BACKEND backend on gRPC port $GRPC_PORT, HTTP port $HTTP_PORT..."
    
    # Check if we're in filesystem_example directory or need to find it
    local service_cmd="local-filesystem-service"
    
    # Check if service is available
    if ! command -v "$service_cmd" &> /dev/null; then
        # Try to activate venv - prefer conformance_tests venv since it has all deps
        if [ -f "conformance_tests/.venv/bin/activate" ]; then
            source "conformance_tests/.venv/bin/activate"
        elif [ -f "filesystem_example/.venv/bin/activate" ]; then
            source "filesystem_example/.venv/bin/activate"
        elif [ -f ".venv/bin/activate" ]; then
            source ".venv/bin/activate"
        fi
        
        if ! command -v "$service_cmd" &> /dev/null; then
            print_error "local-filesystem-service command not found!"
            print_info "Please ensure you've installed the filesystem_example package:"
            echo "  cd conformance_tests && python -m venv .venv && source .venv/bin/activate"
            echo "  pip install -e ../filesystem_example"
            exit 1
        fi
    fi
    
    # Start the service based on backend type
    # Note: port options must come BEFORE the backend subcommand
    case "$BACKEND" in
        filesystem)
            # Create temp storage directory if not specified
            if [ -z "$STORAGE_DIR" ]; then
                STORAGE_DIR=$(mktemp -d)
                CREATED_STORAGE_DIR=true
                print_info "Created temp storage directory: $STORAGE_DIR"
            fi
            
            $service_cmd \
                --grpc-port "$GRPC_PORT" \
                --http-port "$HTTP_PORT" \
                filesystem \
                --static-dir "$STORAGE_DIR" &
            
            # Set resource base for tests (filesystem has a known default)
            export TEST_STORAGE_API_RESOURCE_BASE="file-storage://fileservice"
            ;;
        *)
            # Custom backend - requires user to provide configuration
            if [ -z "$TEST_STORAGE_API_RESOURCE_BASE" ]; then
                print_error "Custom backend '$BACKEND' requires TEST_STORAGE_API_RESOURCE_BASE to be set."
                echo ""
                print_info "The resource base is implementation-dependent. Set it to match your backend's"
                print_info "capabilities endpoint response. Example:"
                echo ""
                echo "  TEST_STORAGE_API_RESOURCE_BASE=\"azurite-storage://my-service\" \\"
                echo "  BACKEND_ARGS=\"--connection-string '...' --container test\" \\"
                echo "  ./run_tests.sh $BACKEND"
                echo ""
                exit 1
            fi
            
            if [ -z "$BACKEND_ARGS" ]; then
                print_warning "BACKEND_ARGS is empty. Most custom backends require additional arguments."
                print_info "If your backend needs configuration, set BACKEND_ARGS. Example:"
                echo "  BACKEND_ARGS=\"--connection-string '...' --container test\""
                echo ""
            fi
            
            print_info "Starting custom backend with:"
            print_info "  Resource base: $TEST_STORAGE_API_RESOURCE_BASE"
            print_info "  Backend args: ${BACKEND_ARGS:-<none>}"
            
            # Start the service with user-provided backend arguments
            # shellcheck disable=SC2086
            $service_cmd \
                --grpc-port "$GRPC_PORT" \
                --http-port "$HTTP_PORT" \
                "$BACKEND" \
                $BACKEND_ARGS &
            
            # Resource base is already set by the user via environment variable
            export TEST_STORAGE_API_RESOURCE_BASE
            ;;
    esac
    
    SERVICE_PID=$!
    print_info "Service started with PID $SERVICE_PID (backend: $BACKEND)"
}

wait_for_service_ready() {
    local max_attempts=$SERVICE_TIMEOUT
    local attempt=0
    
    print_info "Waiting for service to be ready (timeout: ${max_attempts}s)..."
    
    while [ $attempt -lt $max_attempts ]; do
        # Check if service process is still running
        if [ -n "$SERVICE_PID" ] && ! kill -0 "$SERVICE_PID" 2>/dev/null; then
            print_error "Service process (PID $SERVICE_PID) died unexpectedly"
            print_info "Check the service logs for errors"
            return 1
        fi
        
        # Try to reach the capabilities endpoint
        if curl -sf "http://localhost:${HTTP_PORT}/v1beta/capabilities/services" > /dev/null 2>&1; then
            print_success "Service is ready!"
            return 0
        fi
        
        sleep 1
        attempt=$((attempt + 1))
        
        # Show progress every 5 seconds
        if [ $((attempt % 5)) -eq 0 ]; then
            print_info "Still waiting... (${attempt}/${max_attempts}s)"
        fi
    done
    
    print_error "Service failed to start within ${max_attempts} seconds"
    print_info "Try running the service manually to see errors:"
    echo "  local-filesystem-service filesystem --static-dir /tmp/test-storage"
    return 1
}

stop_service() {
    if [ -n "$SERVICE_PID" ]; then
        print_info "Stopping service (PID $SERVICE_PID)..."
        
        if kill -0 "$SERVICE_PID" 2>/dev/null; then
            # Send SIGTERM for graceful shutdown
            kill "$SERVICE_PID" 2>/dev/null || true
            
            # Wait up to 5 seconds for graceful shutdown
            local count=0
            while [ $count -lt 5 ] && kill -0 "$SERVICE_PID" 2>/dev/null; do
                sleep 1
                count=$((count + 1))
            done
            
            # Force kill if still running
            if kill -0 "$SERVICE_PID" 2>/dev/null; then
                print_warning "Service didn't stop gracefully, forcing..."
                kill -9 "$SERVICE_PID" 2>/dev/null || true
            fi
        fi
        
        SERVICE_PID=""
        print_success "Service stopped"
    fi
}

# =============================================================================
# Test Execution
# =============================================================================

run_tests() {
    local exit_code=0
    
    # Build pytest command as an array for safe execution
    local cmd=("run-conformance-tests")
    
    # Check if command is available
    if ! command -v run-conformance-tests &> /dev/null; then
        # Try to activate venv
        if [ -f "conformance_tests/.venv/bin/activate" ]; then
            source "conformance_tests/.venv/bin/activate"
        elif [ -f ".venv/bin/activate" ]; then
            source ".venv/bin/activate"
        fi
        
        if ! command -v run-conformance-tests &> /dev/null; then
            print_error "run-conformance-tests command not found!"
            print_info "Please ensure you've installed the conformance_tests package:"
            echo "  cd conformance_tests && python -m venv .venv && source .venv/bin/activate && pip install -e ."
            exit 1
        fi
    fi
    
    # Ensure the resource base is exported
    print_info "Resource base: $TEST_STORAGE_API_RESOURCE_BASE"
    
    # Add parallel execution flag
    if [ "$PARALLEL" = true ]; then
        cmd+=("-n" "$PARALLEL_WORKERS")
    fi
    
    # Add keyword filter
    if [ -n "$KEYWORD" ]; then
        cmd+=("-k" "$KEYWORD")
    fi
    
    # Add marker filter
    if [ -n "$MARKERS" ]; then
        cmd+=("-m" "$MARKERS")
    fi
    
    # Add verbose flag
    if [ "$VERBOSE" = true ]; then
        cmd+=("-vv")
    fi
    
    echo ""
    print_info "Running tests..."
    echo "Command: ${cmd[*]}"
    echo ""
    
    # Execute and capture exit code
    set +e
    "${cmd[@]}"
    exit_code=$?
    set -e
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        print_success "All tests passed!"
    else
        print_error "Some tests failed (exit code: $exit_code)"
    fi
    
    return $exit_code
}

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
    echo ""
    print_info "Cleaning up..."
    
    stop_service
    
    # Clean up temp storage directory
    if [ "$CREATED_STORAGE_DIR" = true ] && [ -n "$STORAGE_DIR" ] && [ -d "$STORAGE_DIR" ]; then
        print_info "Removing temp storage directory: $STORAGE_DIR"
        rm -rf "$STORAGE_DIR"
    fi
}

do_clean() {
    print_info "Cleaning up any leftover temp files..."
    
    # Kill any running services
    if command -v pkill &> /dev/null; then
        pkill -f "local-filesystem-service" 2>/dev/null || true
    fi
    
    # Clean up temp directories
    rm -rf /tmp/tmp.* 2>/dev/null || true
    
    print_success "Cleanup complete"
}

# =============================================================================
# Main Script
# =============================================================================

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -f|--force)
            FORCE_KILL=true
            shift
            ;;
        -k|--keyword)
            KEYWORD="$2"
            shift 2
            ;;
        -m|--markers)
            MARKERS="$2"
            shift 2
            ;;
        --no-parallel)
            PARALLEL=false
            shift
            ;;
        --parallel)
            PARALLEL_WORKERS="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --service-only)
            SERVICE_ONLY=true
            shift
            ;;
        --test-only)
            TEST_ONLY=true
            shift
            ;;
        --clean)
            do_clean
            exit 0
            ;;
        *)
            BACKEND="$1"
            shift
            ;;
    esac
done

# Set up trap for cleanup
trap cleanup EXIT INT TERM

# Check dependencies
check_dependencies

# Main execution flow
echo ""
echo "=========================================="
echo " Storage API Conformance Test Runner"
echo " Backend: $BACKEND"
echo "=========================================="
echo ""

TEST_EXIT_CODE=0

if [ "$TEST_ONLY" = true ]; then
    print_info "Test-only mode: assuming service is already running"
    print_info "Expected endpoints:"
    echo "  - REST: http://localhost:$HTTP_PORT"
    echo "  - gRPC: localhost:$GRPC_PORT"
    echo ""
    
    # Set resource base based on backend for test-only mode
    case "$BACKEND" in
        filesystem)
            # Filesystem has a known default
            export TEST_STORAGE_API_RESOURCE_BASE="${TEST_STORAGE_API_RESOURCE_BASE:-file-storage://fileservice}"
            ;;
        *)
            # Custom backends require user to provide resource base
            if [ -z "$TEST_STORAGE_API_RESOURCE_BASE" ]; then
                print_error "Custom backend '$BACKEND' requires TEST_STORAGE_API_RESOURCE_BASE to be set."
                echo ""
                print_info "Set it to match your running service's resource base. Example:"
                echo ""
                echo "  TEST_STORAGE_API_RESOURCE_BASE=\"azurite-storage://my-service\" \\"
                echo "  ./run_tests.sh --test-only $BACKEND"
                echo ""
                exit 1
            fi
            export TEST_STORAGE_API_RESOURCE_BASE
            ;;
    esac
    print_info "Resource base: $TEST_STORAGE_API_RESOURCE_BASE"
    echo ""
    
    run_tests || TEST_EXIT_CODE=$?
else
    # Ensure ports are free
    ensure_ports_free
    
    # Start service
    start_service
    
    # Wait for service to be ready
    if ! wait_for_service_ready; then
        exit 1
    fi
    
    if [ "$SERVICE_ONLY" = true ]; then
        print_info "Service-only mode: service is running"
        print_info "Endpoints:"
        echo "  - REST: http://localhost:$HTTP_PORT"
        echo "  - gRPC: localhost:$GRPC_PORT"
        echo "  - REST Docs: http://localhost:$HTTP_PORT/v1beta/fileobject/docs"
        echo ""
        print_info "Press Ctrl+C to stop the service"
        
        # Wait indefinitely
        while true; do
            sleep 1
        done
    else
        # Run tests
        run_tests || TEST_EXIT_CODE=$?
    fi
fi

exit $TEST_EXIT_CODE
