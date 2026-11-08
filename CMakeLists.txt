cmake_minimum_required(VERSION 3.20)
project(SysRecon VERSION 1.8.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Cross-compiling for Windows is driven by cmake/mingw-w64-x86_64.cmake.
# Toolchain variables must be set in that file, not here -- setting them after
# project() has no effect.

option(SYSRECON_BUILD_TESTS "Build the unit test suite" ON)
option(SYSRECON_WERROR "Treat compiler warnings as errors" OFF)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(SYSRECON_WERROR)
        add_compile_options(-Werror)
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3 -DNDEBUG)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /utf-8)
    if(SYSRECON_WERROR)
        add_compile_options(/WX)
    endif()
endif()

# Windows-specific settings
if(WIN32)
    add_definitions(-DUNICODE -D_UNICODE)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    # -mconsole is a MinGW/GCC flag; MSVC's link.exe rejects it.
    if(MINGW)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mconsole")
    else()
        set_property(GLOBAL PROPERTY WIN32_EXECUTABLE OFF)
    endif()
endif()

# Single source of truth for the version, consumed by sysrecon.h.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/sysrecon_version.h
    @ONLY
)

# ---------------------------------------------------------------------------
# sysrecon_core: platform-independent logic, compiled natively so it can be
# unit-tested on any host without wine. Must contain no Win32 dependencies.
# ---------------------------------------------------------------------------
add_library(sysrecon_core STATIC
    src/core/text_utils.cpp
    src/core/utils_common.cpp
    src/core/logger.cpp
    src/core/config.cpp
    src/core/scan_plan.cpp
    src/core/findings.cpp
    src/core/scoring.cpp
)
target_include_directories(sysrecon_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

# ---------------------------------------------------------------------------
# sysrecon: the Windows executable.
# ---------------------------------------------------------------------------
set(SOURCES
    src/main.cpp
    src/core/engine.cpp
    src/core/utils.cpp
    modules/accounts/user_enum.cpp
    modules/services/service_enum.cpp
    modules/processes/process_enum.cpp
    modules/network/network_enum.cpp
    modules/registry/registry_analyzer.cpp
    modules/memory/memory_analyzer.cpp
    modules/privesc/privesc_analyzer.cpp
    modules/domain/domain_recon.cpp
    modules/eventlogs/event_log_analyzer.cpp
    modules/reporting/report_generator.cpp
)

set(HEADERS
    include/sysrecon.h
    include/core/engine.h
    include/core/logger.h
    include/core/config.h
    include/core/utils.h
    include/core/text_utils.h
    include/core/scan_plan.h
    include/core/findings.h
    include/core/scoring.h
    include/core/whitelist.h
    include/modules/accounts/user_enum.h
    include/modules/services/service_enum.h
    include/modules/processes/process_enum.h
    include/modules/network/network_enum.h
    include/modules/registry/registry_analyzer.h
    include/modules/memory/memory_analyzer.h
    include/modules/privesc/privesc_analyzer.h
    include/modules/domain/domain_recon.h
    include/modules/eventlogs/event_log_analyzer.h
    include/modules/reporting/report_generator.h
)

if(WIN32)
    add_executable(sysrecon ${SOURCES} ${HEADERS})
    target_include_directories(sysrecon PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/modules
        ${CMAKE_CURRENT_SOURCE_DIR}/external
        ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    target_link_libraries(sysrecon PRIVATE
        sysrecon_core
        advapi32    # Registry, security APIs
        kernel32    # Process, memory APIs
        user32      # User APIs
        netapi32    # Network APIs
        wtsapi32    # Terminal Services APIs
        psapi       # Process status APIs
        iphlpapi    # IP Helper APIs
        ws2_32      # Winsock
        dbghelp     # MiniDumpWriteDump
        wintrust    # Authenticode signature verification
        crypt32     # Certificate / signer extraction
        taskschd    # Scheduled Task Scheduler COM
        ole32       # COM (Task Scheduler, WMI)
        oleaut32    # COM BSTR/VARIANT
        wbemuuid    # WMI (Win32_QuickFixEngineering)
        wevtapi     # Event log queries (Event Logs module)
    )
    if(MINGW)
        # Wide-character entry point: the CRT calls wmain(argc, wchar_t**).
        target_compile_options(sysrecon PRIVATE -municode)
        target_link_options(sysrecon PRIVATE -municode)
    endif()
    install(TARGETS sysrecon DESTINATION bin)
else()
    message(STATUS "Not targeting Windows: building sysrecon_core and tests only.")
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SYSRECON_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    add_executable(sysrecon_tests
        tests/test_core.cpp
        tests/test_whitelist.cpp
        tests/test_report_escaping.cpp
        tests/test_text_utils.cpp
        tests/test_scan_plan.cpp
        tests/test_config.cpp
        tests/test_utils_crypto.cpp
        tests/test_findings.cpp
        tests/test_scoring.cpp
    )
    target_link_libraries(sysrecon_tests PRIVATE sysrecon_core GTest::gtest_main)
    # Lets tests validate the config.json that actually ships.
    target_compile_definitions(sysrecon_tests PRIVATE
        SYSRECON_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

    include(GoogleTest)
    gtest_discover_tests(sysrecon_tests)
endif()

# ---------------------------------------------------------------------------
# Packaging. CPack snapshots CPACK_* variables at include() time, so
# include(CPack) must come last.
# ---------------------------------------------------------------------------
set(CPACK_PACKAGE_NAME "SysRecon")
set(CPACK_PACKAGE_VENDOR "SysRecon Team")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Windows Security Audit Tool")
set(CPACK_GENERATOR "ZIP")
include(CPack)
