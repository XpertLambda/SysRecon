#include "../../include/modules/registry/registry_analyzer.h"

namespace SysRecon {
namespace Modules {

RegistryAnalyzer::RegistryAnalyzer() 
    : scan_startup_keys_(true)
    , analyze_policies_(true)
    , check_permissions_(true)
    , initialized_(false) {
}

RegistryAnalyzer::~RegistryAnalyzer() {
    Cleanup();
}

bool RegistryAnalyzer::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Registry Analyzer module");
    initialized_ = true;
    return true;
}

bool RegistryAnalyzer::AnalyzeStartupKeys() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing registry startup keys...");
    
#ifdef _WIN32
    StringVector startup_keys = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    
    // Check HKLM keys
    for (const auto& key_path : startup_keys) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[16384];
            DWORD valueNameSize;
            wchar_t valueData[16384];
            DWORD valueDataSize;
            DWORD valueType;
            
            while (true) {
                valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
                valueDataSize = sizeof(valueData);
                
                LONG result = RegEnumValueW(hKey, index, valueName, &valueNameSize, 
                                           nullptr, &valueType, (LPBYTE)valueData, &valueDataSize);
                
                if (result == ERROR_SUCCESS) {
                    StartupEntry entry;
                    entry.name = String(valueName);
                    entry.command = String(valueData, valueDataSize / sizeof(wchar_t) - 1);
                    entry.location = L"HKLM\\" + key_path;
                    entry.is_enabled = true;
                    entry.is_signed = false;
                    entry.risk_level = SecurityLevel::Medium;
                    
                    startup_entries_.push_back(entry);
                    
                    // Create scan result
                    ScanResult scan_result;
                    scan_result.module_name = L"Registry";
                    scan_result.item_name = entry.name;
                    scan_result.description = L"Startup entry in: " + entry.location;
                    scan_result.details[L"Command"] = entry.command;
                    scan_result.details[L"Location"] = entry.location;
                    scan_result.risk_level = SecurityLevel::Medium;
                    scan_result.timestamp = std::chrono::system_clock::now();
                    scan_results_.push_back(scan_result);
                    
                    index++;
                } else {
                    break;
                }
            }
            RegCloseKey(hKey);
        }
    }
    
    // Check HKCU keys
    for (const auto& key_path : startup_keys) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, key_path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[16384];
            DWORD valueNameSize;
            wchar_t valueData[16384];
            DWORD valueDataSize;
            DWORD valueType;
            
            while (true) {
                valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
                valueDataSize = sizeof(valueData);
                
                LONG result = RegEnumValueW(hKey, index, valueName, &valueNameSize, 
                                           nullptr, &valueType, (LPBYTE)valueData, &valueDataSize);
                
                if (result == ERROR_SUCCESS) {
                    StartupEntry entry;
                    entry.name = String(valueName);
                    entry.command = String(valueData, valueDataSize / sizeof(wchar_t) - 1);
                    entry.location = L"HKCU\\" + key_path;
                    entry.is_enabled = true;
                    entry.is_signed = false;
                    entry.risk_level = SecurityLevel::Medium;
                    
                    startup_entries_.push_back(entry);
                    index++;
                } else {
                    break;
                }
            }
            RegCloseKey(hKey);
        }
    }
    
    SYSRECON_LOG_INFO(L"Found " + std::to_wstring(startup_entries_.size()) + L" startup entries");
    return true;
#else
    SYSRECON_LOG_INFO(L"Cross-compilation stub - feature available only on Windows");
    return true;
#endif
}

bool RegistryAnalyzer::AnalyzePolicies() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing security policies...");
    return true;
}

bool RegistryAnalyzer::AnalyzePermissions() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing registry permissions...");
    return true;
}

bool RegistryAnalyzer::ScanCustomKeys() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Scanning custom registry keys...");
    return true;
}

void RegistryAnalyzer::Cleanup() {
    startup_entries_.clear();
    policy_entries_.clear();
    registry_entries_.clear();
    scan_results_.clear();
    initialized_ = false;
}

}
}
