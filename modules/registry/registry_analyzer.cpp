#include "../../include/modules/registry/registry_analyzer.h"
#include "../../include/core/whitelist.h"
#include "../../include/core/text_utils.h"

namespace SysRecon {
namespace Modules {

#ifdef _WIN32
namespace {

// Returns the names of non-administrative principals that hold write access in
// `sd`'s DACL. A key like HKLM\...\Run that ordinary users can write to is a
// persistence foothold, and this is what the permission check is for.
StringVector FindWeakAcePrincipals(PSECURITY_DESCRIPTOR sd) {
    StringVector offenders;

    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted) ||
        !dacl_present || dacl == nullptr) {
        return offenders;  // No DACL: nothing we can assert.
    }

    // Well-known groups that must NOT have write access to these keys.
    struct KnownSid { WELL_KNOWN_SID_TYPE type; const wchar_t* label; };
    const KnownSid interesting[] = {
        { WinWorldSid,                    L"Everyone" },
        { WinBuiltinUsersSid,             L"BUILTIN\\Users" },
        { WinAuthenticatedUserSid,        L"Authenticated Users" },
        { WinInteractiveSid,              L"INTERACTIVE" },
    };

    const DWORD write_mask = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | WRITE_DAC | WRITE_OWNER;

    for (DWORD i = 0; i < dacl->AceCount; i++) {
        LPVOID ace_ptr = nullptr;
        if (!GetAce(dacl, i, &ace_ptr)) {
            continue;
        }
        auto* header = static_cast<ACE_HEADER*>(ace_ptr);
        // Only allow-ACEs grant access; deny-ACEs are not a weakness.
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            continue;
        }

        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(ace_ptr);
        if ((ace->Mask & write_mask) == 0) {
            continue;
        }

        PSID ace_sid = (PSID)&ace->SidStart;
        if (!IsValidSid(ace_sid)) {
            continue;
        }

        for (const auto& known : interesting) {
            DWORD sid_size = SECURITY_MAX_SID_SIZE;
            std::vector<BYTE> sid_buffer(sid_size);
            PSID well_known = (PSID)sid_buffer.data();
            if (!CreateWellKnownSid(known.type, nullptr, well_known, &sid_size)) {
                continue;
            }
            if (EqualSid(ace_sid, well_known)) {
                const String label(known.label);
                if (std::find(offenders.begin(), offenders.end(), label) == offenders.end()) {
                    offenders.push_back(label);
                }
                break;
            }
        }
    }

    return offenders;
}

}  // namespace
#endif

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

    // Re-enumeration must not append to prior results (interactive mode runs
    // this more than once).
    startup_entries_.clear();

    // HKCU Run keys are the most common persistence location, so both hives are
    // scanned through the same path -- including the same whitelist checks.
    const struct { HKEY root; const wchar_t* label; } hives[] = {
        { HKEY_LOCAL_MACHINE, L"HKLM\\" },
        { HKEY_CURRENT_USER,  L"HKCU\\" }
    };

    for (const auto& hive : hives) {
        for (const auto& key_path : startup_keys) {
            HKEY hKey;
            if (RegOpenKeyExW(hive.root, key_path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
                continue;
            }

            DWORD index = 0;
            wchar_t valueName[16384];
            wchar_t valueData[16384];

            while (true) {
                DWORD valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
                DWORD valueDataSize = sizeof(valueData);
                DWORD valueType = 0;

                LONG result = RegEnumValueW(hKey, index, valueName, &valueNameSize,
                                           nullptr, &valueType, (LPBYTE)valueData, &valueDataSize);
                if (result != ERROR_SUCCESS) {
                    break;
                }
                index++;

                // Registry values are attacker-controlled: a Run value may hold
                // any type and is not guaranteed to be NUL-terminated. Skip
                // anything that is not a string rather than reinterpreting it.
                if (valueType != REG_SZ && valueType != REG_EXPAND_SZ) {
                    continue;
                }
                if (valueDataSize < sizeof(wchar_t)) {
                    continue;
                }

                size_t chars = valueDataSize / sizeof(wchar_t);
                // Trim the terminator only if one is actually present.
                if (valueData[chars - 1] == L'\0') {
                    chars--;
                }

                StartupEntry entry;
                entry.name = String(valueName, valueNameSize);
                entry.command = String(valueData, chars);
                entry.location = String(hive.label) + key_path;
                entry.is_enabled = true;
                entry.is_signed = false;

                // Suppression requires the referenced image to actually live in
                // a system directory -- a trusted-looking name is not evidence.
                const String image_path = Core::Text::ExtractExecutablePath(entry.command);
                const bool is_known = Core::SystemWhitelist::Instance()
                                          .IsKnownPersistenceEntry(entry.name, image_path);
                const bool is_system_path = Core::SystemWhitelist::Instance()
                                          .IsSystemPath(image_path);

                entry.risk_level = (is_known || is_system_path) ? SecurityLevel::Low
                                                                : SecurityLevel::Medium;
                startup_entries_.push_back(entry);

                if (!is_known && !is_system_path) {
                    ScanResult scan_result;
                    scan_result.module_name = L"Registry";
                    scan_result.item_name = entry.name;
                    scan_result.description = L"Startup entry in: " + entry.location;
                    scan_result.details[L"Command"] = entry.command;
                    scan_result.details[L"Location"] = entry.location;
                    scan_result.details[L"Image Path"] = image_path.empty() ? L"(unresolved)" : image_path;
                    scan_result.details[L"Note"] = L"Third-party startup entry";
                    scan_result.risk_level = entry.risk_level;
                    scan_result.timestamp = std::chrono::system_clock::now();
                    scan_results_.push_back(scan_result);
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
        if (RegOpenKeyExW(root_key, subkey.c_str(), 0, READ_CONTROL, &hKey) != ERROR_SUCCESS) {
            continue;
        }

        DWORD sd_size = 0;
        SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        RegGetKeySecurity(hKey, si, NULL, &sd_size);

        if (sd_size > 0 && sd_size < 65536) {
            std::vector<BYTE> sd_buffer(sd_size);
            PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sd_buffer.data();

            if (RegGetKeySecurity(hKey, si, pSD, &sd_size) == ERROR_SUCCESS) {
                // The descriptor is now actually parsed. Previously it was
                // fetched and discarded, and every key produced a Low
                // "Accessible" finding that told the analyst nothing.
                const StringVector weak = FindWeakAcePrincipals(pSD);
                if (!weak.empty()) {
                    ScanResult result;
                    result.module_name = L"Registry Permissions";
                    result.item_name = subkey;
                    result.description = L"Non-administrative principals can modify a persistence-relevant key";
                    result.details[L"Key"] = subkey;
                    result.details[L"Principals"] = Core::Utils::Join(weak, L", ");
                    result.details[L"Technique"] = L"T1112 Modify Registry (weak ACL enables persistence)";
                    result.risk_level = SecurityLevel::High;
                    result.timestamp = std::chrono::system_clock::now();
                    scan_results_.push_back(result);
                }
            }
        }

        RegCloseKey(hKey);
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
    registry_entries_.clear();

    // Image File Execution Options is the one location here with an
    // unambiguous abuse signal, so it gets a real check below rather than a
    // finding for merely existing.
    const String ifeo_path =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

    // IFEO hijack (T1546.012): a Debugger value under an executable's subkey
    // makes Windows launch the debugger instead of that executable. The key
    // itself ships with every Windows install -- only a Debugger entry matters.
    // Previously this reported Medium simply because the key existed, which is
    // a guaranteed false positive on every host, as was the equivalent
    // Browser Helper Objects check (now removed: presence proves nothing).
    HKEY ifeo_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeo_path.c_str(), 0, KEY_READ, &ifeo_key) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t subkey_name[512];
        while (true) {
            DWORD name_size = sizeof(subkey_name) / sizeof(subkey_name[0]);
            if (RegEnumKeyExW(ifeo_key, index, subkey_name, &name_size,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                break;
            }
            index++;

            HKEY image_key;
            if (RegOpenKeyExW(ifeo_key, subkey_name, 0, KEY_READ, &image_key) != ERROR_SUCCESS) {
                continue;
            }

            wchar_t debugger[2048];
            DWORD debugger_size = sizeof(debugger);
            DWORD value_type = 0;
            LONG got = RegQueryValueExW(image_key, L"Debugger", nullptr, &value_type,
                                        (LPBYTE)debugger, &debugger_size);

            if (got == ERROR_SUCCESS &&
                (value_type == REG_SZ || value_type == REG_EXPAND_SZ) &&
                debugger_size >= sizeof(wchar_t)) {

                size_t chars = debugger_size / sizeof(wchar_t);
                if (debugger[chars - 1] == L'\0') {
                    chars--;
                }
                const String debugger_cmd(debugger, chars);

                RegistryEntry entry;
                entry.key_path = ifeo_path + L"\\" + subkey_name;
                entry.value_name = L"Debugger";
                entry.string_value = debugger_cmd;
                entry.value_type = value_type;
                entry.risk_level = SecurityLevel::High;
                registry_entries_.push_back(entry);

                ScanResult result;
                result.module_name = L"Registry";
                result.item_name = String(subkey_name);
                result.description = L"Image File Execution Options debugger set for an executable";
                result.details[L"Key"] = entry.key_path;
                result.details[L"Debugger"] = debugger_cmd;
                result.details[L"Technique"] = L"T1546.012 Image File Execution Options Injection";
                result.risk_level = SecurityLevel::High;
                result.timestamp = std::chrono::system_clock::now();
                scan_results_.push_back(result);
            }
            RegCloseKey(image_key);
        }
        RegCloseKey(ifeo_key);
    }

    // Operator-supplied keys from config.json. AddCustomKey existed and was
    // never called, so custom_keys was unreachable; the scan used a hardcoded
    // list instead and ignored the config entirely.
    for (const auto& subkey : custom_keys_) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            continue;
        }
        RegistryEntry entry;
        entry.key_path = subkey;
        entry.value_name = L"<key present>";
        entry.value_type = REG_NONE;
        entry.risk_level = SecurityLevel::Low;
        registry_entries_.push_back(entry);

        ScanResult result;
        result.module_name = L"Registry";
        result.item_name = subkey;
        result.description = L"Operator-specified registry key is present";
        result.details[L"Key"] = subkey;
        result.risk_level = SecurityLevel::Low;
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
        RegCloseKey(hKey);
    }

    SYSRECON_LOG_INFO(L"Custom key scan complete (" +
                      std::to_wstring(registry_entries_.size()) + L" entries of interest)");
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
