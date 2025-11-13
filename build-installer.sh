#!/bin/bash
# ===================================================================
# SysRecon Windows Installer Build Script (Linux Cross-Compilation)
# ===================================================================
# This script builds the SysRecon installer for Windows from Linux
# 
# Requirements:
#   - makensis (NSIS compiler) installed on Linux
#   - SysRecon already cross-compiled (sysrecon.exe in build directory)
#
# Install NSIS on Linux:
#   Arch:   sudo pacman -S nsis
#   Ubuntu: sudo apt install nsis
#   Fedora: sudo dnf install mingw32-nsis
# ===================================================================

set -e  # Exit on error

echo "============================================"
echo "SysRecon Installer Build Script (Linux)"
echo "============================================"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if NSIS is installed
if ! command -v makensis &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} NSIS (makensis) not found"
    echo
    echo "Please install NSIS:"
    echo "  Arch Linux:   sudo pacman -S nsis"
    echo "  Ubuntu/Debian: sudo apt install nsis"
    echo "  Fedora:       sudo dnf install mingw32-nsis"
    echo
    exit 1
fi

echo -e "${GREEN}[OK]${NC} NSIS found: $(which makensis)"
echo

# Check if executable exists
if [ ! -f "build/sysrecon.exe" ]; then
    echo -e "${RED}[ERROR]${NC} sysrecon.exe not found in build directory"
    echo
    echo "Please build the project first:"
    echo "  ./build.sh"
    echo "  OR manually:"
    echo "    mkdir build && cd build"
    echo "    cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw-w64-x86_64.cmake .."
    echo "    make -j\$(nproc)"
    echo
    exit 1
fi

echo -e "${GREEN}[OK]${NC} SysRecon executable found"
echo

# Check if required files exist
if [ ! -f "config.json" ]; then
    echo -e "${YELLOW}[WARNING]${NC} config.json not found - creating default"
    cat > config.json <<EOF
{
  "verbose": false,
  "output_dir": "./reports",
  "report_format": "all",
  "modules": {
    "accounts": true,
    "services": true,
    "processes": true,
    "network": true,
    "registry": true,
    "memory": true
  }
}
EOF
fi

if [ ! -f "LICENSE" ]; then
    echo -e "${YELLOW}[WARNING]${NC} LICENSE file not found - creating placeholder"
    cat > LICENSE <<EOF
Proprietary Software - All Rights Reserved
Copyright (c) 2025 XpertLambda

Unauthorized copying, modification, distribution, or use of this software
is strictly prohibited.
EOF
fi

if [ ! -f "README.md" ]; then
    echo -e "${RED}[ERROR]${NC} README.md not found"
    echo "Please ensure README.md exists in the project root"
    exit 1
fi

echo -e "${GREEN}[OK]${NC} All required files found"
echo

# Create installer
echo "============================================"
echo "Building Windows Installer..."
echo "============================================"
echo

# Run NSIS compiler
if makensis -V4 installer.nsi; then
    echo
    echo "============================================"
    echo -e "${GREEN}Installer Build Successful!${NC}"
    echo "============================================"
    echo
    echo "Installer created: SysRecon-Setup-1.0.0.exe"
    echo
    echo "File size: $(du -h SysRecon-Setup-*.exe | cut -f1)"
    echo
    echo "You can now transfer this installer to Windows and run it."
    echo "The installer includes:"
    echo "  ✓ SysRecon.exe"
    echo "  ✓ Configuration files"
    echo "  ✓ Documentation"
    echo "  ✓ Start Menu shortcuts"
    echo "  ✓ Desktop shortcut (optional)"
    echo "  ✓ PATH integration (optional)"
    echo "  ✓ Uninstaller"
    echo
    echo "To test on Windows:"
    echo "  1. Transfer SysRecon-Setup-1.0.0.exe to Windows"
    echo "  2. Right-click and 'Run as Administrator'"
    echo "  3. Follow the installation wizard"
    echo
else
    echo
    echo "============================================"
    echo -e "${RED}Installer Build FAILED!${NC}"
    echo "============================================"
    echo
    echo "Please check the error messages above."
    echo
    exit 1
fi
