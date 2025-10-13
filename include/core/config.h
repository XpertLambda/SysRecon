#pragma once

#include "../sysrecon.h"

namespace SysRecon {
namespace Core {

struct ScanConfig {
    // General settings
    bool verbose_output = false;
    bool stealth_mode = false;
    bool require_admin = true;
    int max_threads = 4;
    int timeout_seconds = 300;
    
    // Module settings
    struct {
        bool enabled = true;
        bool enumerate_groups = true;
        bool check_passwords = false;
        bool analyze_permissions = true;
    } accounts;
    
    struct {
        bool enabled = true;
        bool analyze_startup = true;
        bool check_dependencies = true;
        bool verify_signatures = false;
    } services;
    
    struct {
        bool enabled = true;
        bool analyze_memory = false;
        bool check_dlls = true;
        bool detect_injection = true;
    } processes;
    
    struct {
        bool enabled = true;
        bool scan_listening_ports = true;
        bool analyze_connections = true;
        bool resolve_hostnames = false;
    } network;
    
    struct {
        bool enabled = true;
        bool scan_startup_keys = true;
        bool analyze_policies = true;
        bool check_permissions = true;
        StringVector custom_keys;
    } registry;
    
    struct {
        bool enabled = false;
        bool create_dumps = false;
        bool analyze_heap = false;
        bool scan_for_malware = true;
        size_t max_dump_size_mb = 100;
    } memory;
    
    // Output settings
    struct {
        String output_directory = L"./reports";
        bool generate_json = true;
        bool generate_csv = true;
        bool generate_html = true;
        bool generate_pdf = false;
        bool compress_output = true;
    } output;
    
    // Security settings
    struct {
        bool encrypt_output = false;
        String encryption_key;
        bool sign_reports = false;
        String signing_cert;
    } security;
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
    int GetMaxThreads() const { return config_.max_threads; }
    int GetTimeoutSeconds() const { return config_.timeout_seconds; }
    bool IsVerboseMode() const { return config_.verbose_output; }
    bool IsStealthMode() const { return config_.stealth_mode; }
    
    // Validation
    bool ValidateConfig() const;
    StringVector GetValidationErrors() const;
    
    // Environment detection
    bool DetectEnvironment();
    void ApplyEnvironmentOptimizations();
    
private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    bool ParseConfigFile(const String& content);
    String SerializeConfig() const;
    
    ScanConfig config_;
    mutable StringVector validation_errors_;
};

} // namespace Core
} // namespace SysRecon
