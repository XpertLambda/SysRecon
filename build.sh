#!/bin/bash

# SysRecon Build Script for Cross-compilation to Windows
# Usage: ./build.sh [release|debug] [clean]

set -e

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
TOOLCHAIN_FILE="$PROJECT_ROOT/cmake/mingw-w64-x86_64.cmake"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
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
    log_info "Checking build prerequisites..."
    
    # Check for required tools
    local tools=("cmake" "make" "x86_64-w64-mingw32-gcc" "x86_64-w64-mingw32-g++")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools:"
        printf '%s\n' "${missing_tools[@]}"
        echo
        log_info "On Arch Linux, install with:"
        echo "sudo pacman -S mingw-w64-gcc cmake make base-devel"
        exit 1
    fi
    
    log_success "All prerequisites found"
}

# Parse command line arguments
BUILD_TYPE="Release"
CLEAN_BUILD=false

for arg in "$@"; do
    case $arg in
        release)
            BUILD_TYPE="Release"
            ;;
        debug)
            BUILD_TYPE="Debug"
            ;;
        clean)
            CLEAN_BUILD=true
            ;;
        *)
            log_warning "Unknown argument: $arg"
            ;;
    esac
done

# Clean build directory if requested
if [ "$CLEAN_BUILD" = true ]; then
    log_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Configure project
log_info "Configuring SysRecon for Windows (x64) - $BUILD_TYPE build..."
cd "$BUILD_DIR"

cmake \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX="$BUILD_DIR/install" \
    "$PROJECT_ROOT"

if [ $? -ne 0 ]; then
    log_error "CMake configuration failed"
    exit 1
fi

# Build project
log_info "Building SysRecon..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    log_error "Build failed"
    exit 1
fi

# Package if release build
if [ "$BUILD_TYPE" = "Release" ]; then
    log_info "Creating release package..."
    make package
    
    if [ $? -eq 0 ]; then
        log_success "Package created successfully"
        ls -la *.zip 2>/dev/null || log_warning "No ZIP package found"
    fi
fi

log_success "Build completed successfully!"
log_info "Executable: $BUILD_DIR/sysrecon.exe"

# Show build summary
echo
echo "=== BUILD SUMMARY ==="
echo "Build Type: $BUILD_TYPE"
echo "Target: Windows x64"
echo "Toolchain: MinGW-w64"
echo "Output: $BUILD_DIR/sysrecon.exe"

if [ -f "$BUILD_DIR/sysrecon.exe" ]; then
    file_size=$(stat -c%s "$BUILD_DIR/sysrecon.exe")
    file_size_mb=$((file_size / 1024 / 1024))
    echo "Size: ${file_size_mb}MB"
fi

echo "===================="
