cmake_minimum_required(VERSION 3.20)
project(SysRecon VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable cross-compilation for Windows from Linux
if(WIN32)
    set(CMAKE_SYSTEM_NAME Windows)
    set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
    set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
    set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
endif()

# Compiler flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3 -DNDEBUG)
    endif()
endif()

# Windows-specific settings
if(WIN32)
    add_definitions(-DUNICODE -D_UNICODE)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    # Use console subsystem
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mconsole")
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules)

# Source files
set(SOURCES
    src/main.cpp
    src/core/engine.cpp
    src/core/logger.cpp
    src/core/config.cpp
    src/core/utils.cpp
    modules/accounts/user_enum.cpp
    modules/services/service_enum.cpp
    modules/processes/process_enum.cpp
    modules/network/network_enum.cpp
    modules/registry/registry_analyzer.cpp
    modules/memory/memory_analyzer.cpp
    modules/reporting/report_generator.cpp
)

# Header files
set(HEADERS
    include/sysrecon.h
    include/core/engine.h
    include/core/logger.h
    include/core/config.h
    include/core/utils.h
    include/modules/accounts/user_enum.h
    include/modules/services/service_enum.h
    include/modules/processes/process_enum.h
    include/modules/network/network_enum.h
    include/modules/registry/registry_analyzer.h
    include/modules/memory/memory_analyzer.h
    include/modules/reporting/report_generator.h
)

# Create executable
add_executable(sysrecon ${SOURCES} ${HEADERS})

# Windows libraries
if(WIN32)
    target_link_libraries(sysrecon
        advapi32    # Registry, security APIs
        kernel32    # Process, memory APIs
        user32      # User APIs
        netapi32    # Network APIs
        wtsapi32    # Terminal Services APIs
        psapi       # Process status APIs
        iphlpapi    # IP Helper APIs
        ws2_32      # Winsock
        dbghelp     # Debug help library
        version     # Version APIs
        setupapi    # Setup APIs
    )
endif()

# Installation
install(TARGETS sysrecon DESTINATION bin)

# CPack configuration for packaging
include(CPack)
set(CPACK_PACKAGE_NAME "SysRecon")
set(CPACK_PACKAGE_VENDOR "SysRecon Team")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Windows Security Audit Tool")
set(CPACK_GENERATOR "ZIP;NSIS")
