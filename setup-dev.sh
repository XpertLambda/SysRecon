#!/bin/bash

# SysRecon Development Environment Setup Script for Arch Linux
# This script installs the necessary tools for cross-compiling to Windows

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if running on Arch Linux
if ! command -v pacman &> /dev/null; then
    log_error "This script is designed for Arch Linux with pacman package manager"
    exit 1
fi

log_info "Setting up SysRecon development environment on Arch Linux..."

# Update package database
log_info "Updating package database..."
sudo pacman -Sy

# Install development tools
log_info "Installing development tools..."
PACKAGES=(
    "cmake"
    "make"
    "base-devel"
    "git"
    "mingw-w64-gcc"
    "mingw-w64-binutils"
    "mingw-w64-headers"
    "mingw-w64-crt"
    "mingw-w64-winpthreads"
)

# Check which packages are already installed
MISSING_PACKAGES=()
for package in "${PACKAGES[@]}"; do
    if ! pacman -Q "$package" &> /dev/null; then
        MISSING_PACKAGES+=("$package")
    else
        log_info "Package $package is already installed"
    fi
done

# Install missing packages
if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    log_info "Installing missing packages: ${MISSING_PACKAGES[*]}"
    sudo pacman -S --needed "${MISSING_PACKAGES[@]}"
else
    log_success "All required packages are already installed"
fi

# Verify cross-compilation tools
log_info "Verifying cross-compilation tools..."
TOOLS=(
    "x86_64-w64-mingw32-gcc"
    "x86_64-w64-mingw32-g++"
    "x86_64-w64-mingw32-windres"
    "x86_64-w64-mingw32-ar"
    "cmake"
    "make"
)

MISSING_TOOLS=()
for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    log_error "Missing tools: ${MISSING_TOOLS[*]}"
    log_error "Please install the missing packages manually"
    exit 1
fi

log_success "All cross-compilation tools are available"

# Test cross-compilation
log_info "Testing cross-compilation..."
cat > /tmp/test_mingw.cpp << 'EOF'
#include <iostream>
#include <windows.h>

int main() {
    std::cout << "Hello from MinGW cross-compilation!" << std::endl;
    
    // Test Windows API
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    std::cout << "Target architecture: " << sysinfo.dwProcessorType << std::endl;
    
    return 0;
}
EOF

if x86_64-w64-mingw32-g++ -o /tmp/test_mingw.exe /tmp/test_mingw.cpp -static-libgcc -static-libstdc++; then
    log_success "Cross-compilation test successful"
    rm -f /tmp/test_mingw.cpp /tmp/test_mingw.exe
else
    log_error "Cross-compilation test failed"
    rm -f /tmp/test_mingw.cpp /tmp/test_mingw.exe
    exit 1
fi

# Optional: Install additional development tools
log_info "You may also want to install these optional tools:"
echo "  - Visual Studio Code: yay -S visual-studio-code-bin"
echo "  - GDB for debugging: sudo pacman -S gdb"
echo "  - Valgrind for memory analysis: sudo pacman -S valgrind"
echo "  - Wine for testing Windows executables: sudo pacman -S wine"

log_success "Development environment setup complete!"
log_info "You can now build SysRecon by running: ./build.sh"
