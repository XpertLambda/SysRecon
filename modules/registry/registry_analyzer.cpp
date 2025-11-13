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
    
#ifdef _WIN32
    // Analyze important security policy registry keys
    const std::vector<std::pair<HKEY, String>> policy_keys = {
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"},
    };
    
    for (const auto& [root_key, subkey] : policy_keys) {
        HKEY hKey;
        if (RegOpenKeyExW(root_key, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Enumerate values in this key
            DWORD index = 0;
            WCHAR value_name[256];
            DWORD value_name_size = 256;
            DWORD value_type;
            BYTE value_data[1024];
            DWORD value_data_size = sizeof(value_data);
            
            while (RegEnumValueW(hKey, index++, value_name, &value_name_size,
                                NULL, &value_type, value_data, &value_data_size) == ERROR_SUCCESS) {
                
                PolicyEntry policy;
                policy.policy_path = subkey;
                policy.policy_name = value_name;
                
                // Convert value data to string
                String value_str;
                if (value_type == REG_DWORD && value_data_size >= sizeof(DWORD)) {
                    DWORD dword_val = *(DWORD*)value_data;
                    value_str = std::to_wstring(dword_val);
                } else if (value_type == REG_SZ || value_type == REG_EXPAND_SZ) {
                    value_str = (WCHAR*)value_data;
                }
                
                policy.current_value = value_str;
                policy.risk_level = SecurityLevel::Low;
                
                // Check for risky configurations
                if (String(value_name) == L"EnableLUA" && value_str == L"0") {
                    policy.risk_level = SecurityLevel::High;
                    policy.description = L"User Account Control is disabled";
                    policy.recommended_value = L"1";
                    
                    ScanResult result;
                    result.module_name = L"Registry Policy";
                    result.item_name = L"UAC Disabled";
                    result.description = L"User Account Control is disabled";
                    result.risk_level = SecurityLevel::High;
                    result.details[L"key"] = subkey;
                    result.details[L"value"] = value_name;
                    result.details[L"data"] = value_str;
                    scan_results_.push_back(result);
                }
                
                if (String(value_name) == L"DisableAntiSpyware" && value_str == L"1") {
                    policy.risk_level = SecurityLevel::Critical;
                    policy.description = L"Windows Defender is disabled via policy";
                    policy.recommended_value = L"0";
                    
                    ScanResult result;
                    result.module_name = L"Registry Policy";
                    result.item_name = L"Windows Defender Disabled";
                    result.description = L"Windows Defender is disabled via policy";
                    result.risk_level = SecurityLevel::Critical;
                    result.details[L"key"] = subkey;
                    result.details[L"value"] = value_name;
                    scan_results_.push_back(result);
                }
                
                policy_entries_.push_back(policy);
                
                // Reset sizes for next iteration
                value_name_size = 256;
                value_data_size = sizeof(value_data);
            }
            
            RegCloseKey(hKey);
        }
    }
    
    SYSRECON_LOG_INFO(L"Found " + std::to_wstring(policy_entries_.size()) + L" policy entries");
    return true;
#else
    SYSRECON_LOG_INFO(L"Policy analysis only available on Windows");
    return false;
#endif
}

bool RegistryAnalyzer::AnalyzePermissions() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing registry permissions...");
    
#ifdef _WIN32
    // Check permissions on sensitive registry keys
    const std::vector<std::pair<HKEY, String>> sensitive_keys = {
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"},
    };
    
    for (const auto& [root_key, subkey] : sensitive_keys) {
        HKEY hKey;
        if (RegOpenKeyExW(root_key, subkey.c_str(), 0, READ_CONTROL, &hKey) == ERROR_SUCCESS) {
            // Get security descriptor
            DWORD sd_size = 0;
            SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            
            // First call to get size
            RegGetKeySecurity(hKey, si, NULL, &sd_size);
            
            if (sd_size > 0 && sd_size < 10000) { // Sanity check
                std::vector<BYTE> sd_buffer(sd_size);
                PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sd_buffer.data();
                
                if (RegGetKeySecurity(hKey, si, pSD, &sd_size) == ERROR_SUCCESS) {
                    // Successfully got security descriptor
                    ScanResult result;
                    result.module_name = L"Registry Permissions";
                    result.item_name = subkey;
                    result.description = L"Sensitive registry key permissions checked";
                    result.risk_level = SecurityLevel::Low;
                    result.details[L"key"] = subkey;
                    result.details[L"status"] = L"Accessible";
                    scan_results_.push_back(result);
                }
            }
            
            RegCloseKey(hKey);
        }
    }
    
    SYSRECON_LOG_INFO(L"Registry permission analysis complete");
    return true;
#else
    SYSRECON_LOG_INFO(L"Permission analysis only available on Windows");
    return false;
#endif
}

bool RegistryAnalyzer::ScanCustomKeys() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Scanning custom registry keys...");
    
#ifdef _WIN32
    // Scan additional interesting registry locations
    const std::vector<std::pair<HKEY, String>> custom_keys = {
        // Scheduled tasks
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"},
        // Shell extensions
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"},
        // Browser Helper Objects
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"},
        // LSA Authentication Packages
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa"},
        // Image File Execution Options (debugger hijacking)
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"},
    };
    
    for (const auto& [root_key, subkey] : custom_keys) {
        HKEY hKey;
        if (RegOpenKeyExW(root_key, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            RegistryEntry entry;
            entry.key_path = subkey;
            entry.value_name = L"<Key Exists>";
            entry.string_value = L"";
            entry.value_type = REG_NONE;
            entry.risk_level = SecurityLevel::Low;
            
            // Check for specific suspicious entries
            if (subkey.find(L"Image File Execution Options") != String::npos) {
                // This key can be used for debugger hijacking
                entry.risk_level = SecurityLevel::Medium;
                
                ScanResult result;
                result.module_name = L"Registry";
                result.item_name = L"Image File Execution Options";
                result.description = L"Registry key that can be used for process hijacking";
                result.risk_level = SecurityLevel::Medium;
                result.details[L"key"] = subkey;
                result.details[L"note"] = L"Check for suspicious debugger entries";
                scan_results_.push_back(result);
            }
            
            if (subkey.find(L"Browser Helper Objects") != String::npos) {
                // BHOs can be used for malicious purposes
                entry.risk_level = SecurityLevel::Medium;
                
                ScanResult result;
                result.module_name = L"Registry";
                result.item_name = L"Browser Helper Objects";
                result.description = L"IE browser extensions that load automatically";
                result.risk_level = SecurityLevel::Medium;
                result.details[L"key"] = subkey;
                scan_results_.push_back(result);
            }
            
            registry_entries_.push_back(entry);
            RegCloseKey(hKey);
        }
    }
    
    SYSRECON_LOG_INFO(L"Scanned " + std::to_wstring(custom_keys.size()) + L" custom registry locations");
    return true;
#else
    SYSRECON_LOG_INFO(L"Custom key scanning only available on Windows");
    return false;
#endif
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
