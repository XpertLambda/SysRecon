#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

struct RegistryEntry {
    HKEY root_key;
    String key_path;
    String value_name;
    DWORD value_type;
    String string_value;
    DWORD dword_value;
    ByteVector binary_value;
    std::chrono::system_clock::time_point last_modified;
    String description;
    SecurityLevel risk_level;
};

struct StartupEntry {
    String name;
    String command;
    String location;
    String file_path;
    bool is_enabled;
    bool is_signed;
    String company;
    String description;
    SecurityLevel risk_level;
};

struct PolicyEntry {
    String policy_name;
    String policy_path;
    String current_value;
    String recommended_value;
    String description;
    SecurityLevel risk_level;
};

enum class RegistryHive {
    ClassesRoot,
    CurrentUser,
    LocalMachine,
    Users,
    CurrentConfig
};

class RegistryAnalyzer {
public:
    RegistryAnalyzer();
    ~RegistryAnalyzer();
    
    // Main analysis methods
    bool Initialize();
    bool AnalyzeStartupKeys();
    bool AnalyzePolicies();
    bool AnalyzePermissions();
    bool ScanCustomKeys();
    void Cleanup();
    
    // Results access
    const std::vector<StartupEntry>& GetStartupEntries() const { return startup_entries_; }
    const std::vector<PolicyEntry>& GetPolicyEntries() const { return policy_entries_; }
    const std::vector<RegistryEntry>& GetRegistryEntries() const { return registry_entries_; }
    const ScanResults& GetScanResults() const { return scan_results_; }
    
    // Configuration
    void SetScanStartupKeys(bool enable) { scan_startup_keys_ = enable; }
    void SetAnalyzePolicies(bool enable) { analyze_policies_ = enable; }
    void SetCheckPermissions(bool enable) { check_permissions_ = enable; }
    void AddCustomKey(const String& key_path) { custom_keys_.push_back(key_path); }
    
    // Analysis methods
    SecurityLevel AssessStartupRisk(const StartupEntry& entry);
    SecurityLevel AssessPolicyRisk(const PolicyEntry& entry);
    SecurityLevel AssessRegistryRisk(const RegistryEntry& entry);
    
    StringVector FindSuspiciousStartup();
    StringVector FindWeakPolicies();
    StringVector FindSuspiciousValues();
    StringVector FindUnauthorizedModifications();
    
    // Registry operations
    bool ReadRegistryValue(HKEY root, const String& key_path, const String& value_name, RegistryEntry& entry);
    StringVector EnumerateSubkeys(HKEY root, const String& key_path);
    StringVector EnumerateValues(HKEY root, const String& key_path);
    bool KeyExists(HKEY root, const String& key_path);
    bool ValueExists(HKEY root, const String& key_path, const String& value_name);
    
private:
    // Startup analysis
    bool ScanRunKeys();
    bool ScanRunOnceKeys();
    bool ScanServicesKey();
    bool ScanWinlogonKey();
    bool ScanStartupFolders();
    bool ScanScheduledTasks();
    
    // Policy analysis
    bool ScanSecurityPolicies();
    bool ScanAuditPolicies();
    bool ScanUserRightsPolicies();
    bool ScanPasswordPolicies();
    bool ScanAccountLockoutPolicies();
    
    // Permission analysis
    bool CheckKeyPermissions(HKEY root, const String& key_path);
    bool GetKeyOwner(HKEY root, const String& key_path, String& owner);
    bool GetKeyPermissions(HKEY root, const String& key_path, StringVector& permissions);
    
    // Analysis helpers
    void AnalyzeStartupEntry(const StartupEntry& entry);
    void AnalyzePolicyEntry(const PolicyEntry& entry);
    void AnalyzeRegistryEntry(const RegistryEntry& entry);
    
    // Utility methods
    String HkeyToString(HKEY key);
    String RegTypeToString(DWORD type);
    String GetValueTypeDescription(DWORD type);
    bool IsStartupLocationSuspicious(const String& location);
    bool IsCommandSuspicious(const String& command);
    bool IsPolicyValueSecure(const String& policy_name, const String& value);
    
    // File analysis
    bool AnalyzeReferencedFile(const String& file_path, StartupEntry& entry);
    bool IsFileSigned(const String& file_path);
    String GetFileCompany(const String& file_path);
    String GetFileDescription(const String& file_path);
    
    // Well-known registry locations
    static const StringVector GetStartupKeys();
    static const StringVector GetPolicyKeys();
    static const StringVector GetSecurityKeys();
    
    // Configuration
    bool scan_startup_keys_;
    bool analyze_policies_;
    bool check_permissions_;
    StringVector custom_keys_;
    
    // Data storage
    std::vector<StartupEntry> startup_entries_;
    std::vector<PolicyEntry> policy_entries_;
    std::vector<RegistryEntry> registry_entries_;
    ScanResults scan_results_;
    
    // State
    bool initialized_;
    StringVector error_messages_;
    
    // Caches
    std::map<String, bool> file_signature_cache_;
    std::map<String, String> file_company_cache_;
};

} // namespace Modules
} // namespace SysRecon
