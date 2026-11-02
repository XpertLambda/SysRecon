#pragma once

#include "../sysrecon.h"

namespace SysRecon {
namespace Core {

// Only settings this build actually honours are represented here. Options that
// were parsed, validated and then ignored have been removed rather than left as
// decoration -- notably max_threads/timeout_seconds (the scan is entirely
// sequential and enforces no timeout) and the security block, where
// encrypt_output: true produced an unencrypted report with no warning and
// encryption_key sat in plaintext in config.json.
struct ScanConfig {
    // General settings
    bool verbose_output = false;
    bool stealth_mode = false;
    bool require_admin = true;

    // Module settings
    struct {
        bool enabled = true;
        bool enumerate_groups = true;
    } accounts;

    struct {
        bool enabled = true;
    } services;

    struct {
        bool enabled = true;
        bool check_dlls = true;
    } processes;
    
    struct {
        bool enabled = true;
        bool scan_listening_ports = true;
        bool analyze_connections = true;
    } network;
    
    struct {
        bool enabled = true;
        bool scan_startup_keys = true;
        bool analyze_policies = true;
        bool check_permissions = true;
        StringVector custom_keys;
    } registry;
    
    // Memory is off unless explicitly requested: it opens every non-system
    // process for reading, which EDR products treat as hostile. This default
    // also applies when no config file is found -- previously a missing
    // config.json silently turned the memory module on.
    struct {
        bool enabled = false;
        bool create_dumps = false;
        bool scan_for_malware = true;
        size_t max_dump_size_mb = 100;
    } memory;

    struct {
        bool enabled = true;
        bool check_services = true;      // unquoted paths, weak DACLs, writable binaries
        bool check_registry = true;      // AlwaysInstallElevated, UAC, autologon
        bool check_filesystem = true;    // writable PATH dirs, autorun targets
        bool check_credentials = true;   // stored creds, unattend files
        bool verify_signatures = true;   // Authenticode + SHA-256 on flagged binaries
        bool check_tokens = true;        // current-token integrity / dangerous privileges
        bool check_scheduled_tasks = true; // SYSTEM tasks with a writable binary
        bool check_patches = true;       // installed hotfixes vs known-LPE table
        bool check_defender = true;      // Defender status, exclusions, ASR rules
        bool check_hardening = true;     // SMB/LLMNR/NTLM/LAPS/PS-logging posture
    } privesc;
    
    // Output settings
    struct {
        String output_directory = L"./reports";
        bool generate_json = true;
        bool generate_csv = true;
        bool generate_html = true;
    } output;
};

class ConfigManager {
public:
    static ConfigManager& Instance();
    
    // Configuration management
    bool LoadFromFile(const String& filename);
    bool SaveToFile(const String& filename) const;
    bool LoadDefaults();
    
    // Getters
    const ScanConfig& GetConfig() const { return config_; }
    ScanConfig& GetConfig() { return config_; }
    
    // Specific getters
    bool IsModuleEnabled(ModuleType module) const;
    bool IsVerboseMode() const { return config_.verbose_output; }
    bool IsStealthMode() const { return config_.stealth_mode; }
    
    // Validation
    bool ValidateConfig() const;
    StringVector GetValidationErrors() const;

    // Non-fatal problems from the last load: unknown keys, including options
    // that existed in older versions and were removed because they did
    // nothing (security.*, max_threads, analyze_heap, ...). Reported so an
    // operator does not believe a setting is in effect when it is not.
    const StringVector& GetWarnings() const { return warnings_; }

private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    
    ScanConfig config_;
    mutable StringVector validation_errors_;
    StringVector warnings_;
};

} // namespace Core
} // namespace SysRecon
