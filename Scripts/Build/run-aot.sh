#!/bin/bash

# Ecliptix AOT Server Runner
# This script builds and runs the Ecliptix server with AOT compilation for optimal performance

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_FILE="$PROJECT_DIR/Ecliptix.Core/Ecliptix.Core.csproj"

# Auto-detect default runtime
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [[ "$(uname -m)" == "arm64" ]]; then
        RUNTIME_ID="osx-arm64"
    else
        RUNTIME_ID="osx-x64"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [[ "$(uname -m)" == "aarch64" ]]; then
        RUNTIME_ID="linux-arm64"
    else
        RUNTIME_ID="linux-x64"
    fi
else
    RUNTIME_ID="linux-x64"  # Default fallback
fi

CONFIGURATION="Release"
# OUTPUT_DIR and AOT_BINARY will be set after parsing arguments

# Parse command line arguments
CLEAN=false
SKIP_BUILD=false
VERBOSE=false
HELP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean|-c)
            CLEAN=true
            shift
            ;;
        --skip-build|-s)
            SKIP_BUILD=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            HELP=true
            shift
            ;;
        --runtime|-r)
            RUNTIME_ID="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            HELP=true
            shift
            ;;
    esac
done

# Set paths after parsing arguments
OUTPUT_DIR="$PROJECT_DIR/Ecliptix.Core/bin/$CONFIGURATION/net9.0/$RUNTIME_ID/publish"
AOT_BINARY="$OUTPUT_DIR/Ecliptix.Core"

# Help function
show_help() {
    echo -e "${BLUE}Ecliptix AOT Server Runner${NC}"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -c, --clean        Clean build artifacts before building"
    echo "  -s, --skip-build   Skip build and run existing AOT binary"
    echo "  -v, --verbose      Enable verbose output"
    echo "  -r, --runtime      Specify runtime identifier (default: linux-x64)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                 # Build and run with default settings"
    echo "  $0 --clean         # Clean build and run"
    echo "  $0 --skip-build    # Run existing AOT binary without rebuilding"
    echo "  $0 --runtime osx-x64 --verbose  # Build for macOS with verbose output"
    echo ""
}

if [ "$HELP" = true ]; then
    show_help
    exit 0
fi

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if dotnet is installed
    if ! command -v dotnet &> /dev/null; then
        log_error ".NET SDK is not installed or not in PATH"
        exit 1
    fi
    
    # Check dotnet version
    DOTNET_VERSION=$(dotnet --version)
    log "Found .NET SDK version: $DOTNET_VERSION"
    
    # Check if project file exists
    if [ ! -f "$PROJECT_FILE" ]; then
        log_error "Project file not found: $PROJECT_FILE"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Clean build artifacts
clean_build() {
    if [ "$CLEAN" = true ]; then
        log "Cleaning build artifacts..."
        cd "$PROJECT_DIR"
        
        if [ "$VERBOSE" = true ]; then
            dotnet clean --configuration "$CONFIGURATION" --verbosity detailed
        else
            dotnet clean --configuration "$CONFIGURATION" > /dev/null 2>&1
        fi
        
        # Remove publish directory
        if [ -d "$OUTPUT_DIR" ]; then
            rm -rf "$OUTPUT_DIR"
            log "Removed publish directory"
        fi
        
        log_success "Clean completed"
    fi
}

# Build AOT binary
build_aot() {
    if [ "$SKIP_BUILD" = true ]; then
        log "Skipping build as requested"
        return
    fi
    
    log "Starting AOT compilation..."
    log "Configuration: $CONFIGURATION"
    log "Runtime: $RUNTIME_ID"
    log "Output: $OUTPUT_DIR"
    
    cd "$PROJECT_DIR"
    
    # Build command with appropriate verbosity
    if [ "$VERBOSE" = true ]; then
        PUBLISH_CMD="dotnet publish \"$PROJECT_FILE\" --configuration $CONFIGURATION --runtime $RUNTIME_ID --verbosity detailed"
    else
        PUBLISH_CMD="dotnet publish \"$PROJECT_FILE\" --configuration $CONFIGURATION --runtime $RUNTIME_ID"
    fi
    
    log "Executing: $PUBLISH_CMD"
    
    # Capture build time
    BUILD_START=$(date +%s)
    
    if eval "$PUBLISH_CMD"; then
        BUILD_END=$(date +%s)
        BUILD_TIME=$((BUILD_END - BUILD_START))
        log_success "AOT compilation completed in ${BUILD_TIME}s"
    else
        log_error "AOT compilation failed"
        exit 1
    fi
}

# Kill processes using required ports
kill_port_processes() {
    local ports=(5051 8080)
    local killed_any=false
    
    for port in "${ports[@]}"; do
        local pids=$(lsof -ti:$port 2>/dev/null || true)
        if [ -n "$pids" ]; then
            log_warning "Port $port is in use by process(es): $pids"
            if kill -9 $pids 2>/dev/null; then
                log_success "Killed process(es) using port $port"
                killed_any=true
            else
                log_warning "Failed to kill some processes on port $port"
            fi
        fi
    done
    
    if [ "$killed_any" = true ]; then
        log "Waiting 2 seconds for ports to be released..."
        sleep 2
    fi
}

# Check if AOT binary exists and is executable
check_binary() {
    if [ ! -f "$AOT_BINARY" ]; then
        log_error "AOT binary not found: $AOT_BINARY"
        log_error "Try running without --skip-build to build the binary first"
        exit 1
    fi
    
    if [ ! -x "$AOT_BINARY" ]; then
        log "Making binary executable..."
        chmod +x "$AOT_BINARY"
    fi
    
    # Get binary size
    BINARY_SIZE=$(du -h "$AOT_BINARY" | cut -f1)
    log_success "AOT binary ready: $AOT_BINARY ($BINARY_SIZE)"
}

# Display system information
show_system_info() {
    log "System Information:"
    echo "  OS: $(uname -s)"
    echo "  Architecture: $(uname -m)"
    echo "  Kernel: $(uname -r)"
    echo "  Binary: $AOT_BINARY"
    echo "  Working Directory: $PROJECT_DIR/Ecliptix.Core"
}

# Run the AOT server
run_server() {
    log "Starting Ecliptix AOT server..."
    show_system_info
    
    # Change to the project directory for proper config file resolution
    cd "$PROJECT_DIR/Ecliptix.Core"
    
    # Set environment variables for optimal AOT performance
    export DOTNET_ReadyToRun=0  # Disable ReadyToRun since we're using AOT
    export DOTNET_TieredCompilation=0  # Disable tiered compilation for AOT
    export DOTNET_TC_QuickJit=0  # Disable quick JIT for AOT
    
    log "Environment configured for AOT execution"
    log "Server starting with native AOT binary..."
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  🚀 Ecliptix AOT Server Starting...${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # Execute the AOT binary
    exec "$AOT_BINARY"
}

# Cleanup function for graceful shutdown
cleanup() {
    log_warning "Received interrupt signal, shutting down..."
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Main execution
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════╗"
    echo "║        Ecliptix AOT Server           ║"
    echo "║     High-Performance Cryptographic   ║"
    echo "║          Protocol Server             ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    check_prerequisites
    kill_port_processes
    clean_build
    build_aot
    check_binary
    run_server
}

# Run the main function
main