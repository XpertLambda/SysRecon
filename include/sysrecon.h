#pragma once

// SysRecon - Windows Audit Tool 2025
// Main header file with common includes and definitions

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <tlhelp32.h>
    #include <psapi.h>
    #include <lm.h>
    #include <wtsapi32.h>
    #include <dbghelp.h>
    // #include <version.h>  // Optional - for file version info
    #include <setupapi.h>
    #include <winreg.h>
    #include <sddl.h>
    #include <aclapi.h>
    #include <accctrl.h>
#endif

// Standard C++ includes
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <exception>
#include <stdexcept>
#include <regex>
#include <filesystem>
#include <optional>
#include <variant>

// Forward declarations and basic types first
namespace SysRecon {
    using String = std::wstring;
    using StringA = std::string;
    using StringVector = std::vector<String>;
    using StringMap = std::map<String, String>;
    using ByteVector = std::vector<uint8_t>;
    
    // Security levels
    enum class SecurityLevel {
        Low = 0,
        Medium = 1,
        High = 2,
        Critical = 3
    };
    
    // Module types
    enum class ModuleType {
        Accounts,
        Services,
        Processes,
        Network,
        Registry,
        Memory,
        EventLogs,
        FileSystem
    };
    
    // Scan results
    struct ScanResult {
        String module_name;
        String item_name;
        String description;
        SecurityLevel risk_level;
        StringMap details;
        std::chrono::system_clock::time_point timestamp;
    };
    
    using ScanResults = std::vector<ScanResult>;
}

// Project includes (after types are defined)
#include "core/logger.h"
#include "core/config.h"
#include "core/utils.h"

// Version information
#define SYSRECON_VERSION_MAJOR 1
#define SYSRECON_VERSION_MINOR 0
#define SYSRECON_VERSION_PATCH 0
#define SYSRECON_VERSION "1.0.0"
#define SYSRECON_BUILD_DATE __DATE__
#define SYSRECON_BUILD_TIME __TIME__

// Common type definitions

// Forward declarations
// Utility macros
#ifdef _WIN32
    #define SYSRECON_WSTR(str) L##str
#else
    #define SYSRECON_WSTR(str) str
#endif

#define SYSRECON_LOG_ERROR(msg) SysRecon::Core::Logger::Instance().Error(msg)
#define SYSRECON_LOG_WARNING(msg) SysRecon::Core::Logger::Instance().Warning(msg)
#define SYSRECON_LOG_INFO(msg) SysRecon::Core::Logger::Instance().Info(msg)
#define SYSRECON_LOG_DEBUG(msg) SysRecon::Core::Logger::Instance().Debug(msg)
