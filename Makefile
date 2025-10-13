# SysRecon Makefile for Cross-compilation to Windows
# Usage: make [TARGET] [OPTIONS]

# Compiler and tools
CXX = x86_64-w64-mingw32-g++
AR = x86_64-w64-mingw32-ar
WINDRES = x86_64-w64-mingw32-windres

# Project configuration
PROJECT_NAME = sysrecon
VERSION = 1.0.0
TARGET = $(PROJECT_NAME).exe

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# Compiler flags
CXXFLAGS = -std=c++20 -Wall -Wextra -Wpedantic
CXXFLAGS += -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX
CXXFLAGS += -DSYSRECON_VERSION=\"$(VERSION)\"
CXXFLAGS += -I$(INCLUDE_DIR)

# Linker flags
LDFLAGS = -static-libgcc -static-libstdc++ -static
LDFLAGS += -Wl,--subsystem,console

# Windows libraries
LIBS = -ladvapi32 -lkernel32 -luser32 -lnetapi32 -lwtsapi32 -lpsapi
LIBS += -liphlpapi -lws2_32 -ldbghelp -lversion -lsetupapi

# Build configuration
ifeq ($(DEBUG),1)
    CXXFLAGS += -g -O0 -DDEBUG
    BUILD_TYPE = debug
else
    CXXFLAGS += -O3 -DNDEBUG
    BUILD_TYPE = release
endif

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp) \
          $(wildcard $(SRC_DIR)/core/*.cpp)

# Generate object file names
OBJECTS = $(SOURCES:%.cpp=$(OBJ_DIR)/%.o)

# Create necessary directories
$(shell mkdir -p $(BUILD_DIR) $(OBJ_DIR) $(OBJ_DIR)/$(SRC_DIR) $(OBJ_DIR)/$(SRC_DIR)/core)

# Default target
.PHONY: all
all: $(BUILD_DIR)/$(TARGET)

# Build the main executable
$(BUILD_DIR)/$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)
	@echo "Build complete: $@"

# Compile source files
$(OBJ_DIR)/%.o: %.cpp
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build directory..."
	rm -rf $(BUILD_DIR)

# Create release package
.PHONY: package
package: $(BUILD_DIR)/$(TARGET)
	@echo "Creating release package..."
	@mkdir -p $(BUILD_DIR)/package
	cp $(BUILD_DIR)/$(TARGET) $(BUILD_DIR)/package/
	cp README.md $(BUILD_DIR)/package/
	cp LICENSE $(BUILD_DIR)/package/
	cp config.json $(BUILD_DIR)/package/
	@mkdir -p $(BUILD_DIR)/package/docs
	cp -r docs/* $(BUILD_DIR)/package/docs/
	cd $(BUILD_DIR) && zip -r $(PROJECT_NAME)-$(VERSION)-windows-x64.zip package/
	@echo "Package created: $(BUILD_DIR)/$(PROJECT_NAME)-$(VERSION)-windows-x64.zip"

# Debug build
.PHONY: debug
debug:
	$(MAKE) DEBUG=1

# Install (copy to /usr/local/bin or similar)
.PHONY: install
install: $(BUILD_DIR)/$(TARGET)
	@echo "Install target not implemented for cross-compiled Windows executable"
	@echo "Copy $(BUILD_DIR)/$(TARGET) to your Windows system"

# Show build information
.PHONY: info
info:
	@echo "SysRecon Build Information"
	@echo "========================="
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Target: $(TARGET)"
	@echo "Build Type: $(BUILD_TYPE)"
	@echo "Compiler: $(CXX)"
	@echo "Flags: $(CXXFLAGS)"
	@echo "Libraries: $(LIBS)"
	@echo "Sources: $(words $(SOURCES)) files"

# Test cross-compilation environment
.PHONY: test-env
test-env:
	@echo "Testing cross-compilation environment..."
	@which $(CXX) > /dev/null && echo "✓ Cross-compiler found: $(CXX)" || echo "✗ Cross-compiler not found: $(CXX)"
	@which $(AR) > /dev/null && echo "✓ Archiver found: $(AR)" || echo "✗ Archiver not found: $(AR)"
	@which $(WINDRES) > /dev/null && echo "✓ Resource compiler found: $(WINDRES)" || echo "✗ Resource compiler not found: $(WINDRES)"

# Help target
.PHONY: help
help:
	@echo "SysRecon Makefile Help"
	@echo "====================="
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the project (default)"
	@echo "  debug      - Build with debug information"
	@echo "  clean      - Remove build artifacts"
	@echo "  package    - Create release package"
	@echo "  install    - Install the executable"
	@echo "  info       - Show build information"
	@echo "  test-env   - Test cross-compilation environment"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1    - Enable debug build"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Release build"
	@echo "  make debug              # Debug build"
	@echo "  make clean all          # Clean and rebuild"
	@echo "  make package            # Create release package"
