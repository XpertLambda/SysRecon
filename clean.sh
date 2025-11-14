#!/bin/bash

# SysRecon - Clean Build Script
# Removes all build artifacts and generated files

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          SysRecon Clean Script - Remove Build Files         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Function to print colored messages
print_info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

print_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

print_warning() {
    echo -e "\e[33m[WARNING]\e[0m $1"
}

# Remove build directory
if [ -d "build" ]; then
    print_info "Removing build directory..."
    rm -rf build
    print_success "build/ directory removed"
else
    print_warning "build/ directory not found (already clean)"
fi

# Remove installer executable
if [ -f "SysRecon-Setup-1.1.0.exe" ]; then
    print_info "Removing installer executable..."
    rm -f SysRecon-Setup-1.1.0.exe
    print_success "SysRecon-Setup-1.1.0.exe removed"
else
    print_warning "SysRecon-Setup-1.1.0.exe not found"
fi

# Remove any old installer versions
OLD_INSTALLERS=$(find . -maxdepth 1 -name "SysRecon-Setup-*.exe" 2>/dev/null)
if [ -n "$OLD_INSTALLERS" ]; then
    print_info "Removing old installer versions..."
    rm -f SysRecon-Setup-*.exe
    print_success "Old installers removed"
fi

# Remove NSIS package (if exists)
if [ -f "SysRecon-1.1.0-win64.exe" ]; then
    print_info "Removing NSIS package..."
    rm -f SysRecon-1.1.0-win64.exe
    print_success "NSIS package removed"
fi

# Remove checksums file
if [ -f "checksums.txt" ]; then
    print_info "Removing checksums file..."
    rm -f checksums.txt
    print_success "checksums.txt removed"
fi

# Remove portable packages (if any)
if [ -d "SysRecon-1.1.0-Portable" ] || [ -f "SysRecon-1.1.0-Portable.zip" ]; then
    print_info "Removing portable packages..."
    rm -rf SysRecon-1.1.0-Portable SysRecon-1.1.0-Portable.zip SysRecon-Portable.zip
    print_success "Portable packages removed"
fi

# Remove CMake cache files (if any in root)
if [ -f "CMakeCache.txt" ]; then
    print_info "Removing CMake cache files..."
    rm -f CMakeCache.txt
    print_success "CMake cache removed"
fi

# Remove backup files (if any)
BACKUP_FILES=$(find . -maxdepth 1 -name "*.backup" -o -name "*~" 2>/dev/null)
if [ -n "$BACKUP_FILES" ]; then
    print_info "Removing backup files..."
    rm -f *.backup *~
    print_success "Backup files removed"
fi

# Remove reports directory (optional - commented out by default)
# Uncomment if you want to clean reports too
# if [ -d "reports" ]; then
#     print_info "Removing reports directory..."
#     rm -rf reports
#     print_success "reports/ directory removed"
# fi

echo ""
print_success "Clean completed successfully!"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "To rebuild:"
echo "  ./build.sh                  # Build executable"
echo "  ./build-installer.sh        # Build installer"
echo "═══════════════════════════════════════════════════════════════"
echo ""
