#include "../include/core/config.h"
#include "../include/core/utils.h"

namespace SysRecon {
namespace Core {

ConfigManager& ConfigManager::Instance() {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::LoadFromFile(const String& filename) {
    if (!Utils::FileExists(filename)) {
        validation_errors_.push_back(L"Configuration file not found: " + filename);
        return false;
    }
    
    // For now, just load defaults and log that we would parse the file
    SYSRECON_LOG_INFO(L"Loading configuration from: " + filename);
    
    LoadDefaults();
    
    // TODO: Implement JSON parsing
    // This would parse the JSON configuration file and populate config_ structure
    
    return ValidateConfig();
}

bool ConfigManager::SaveToFile(const String& filename) const {
    // TODO: Implement JSON serialization
    SYSRECON_LOG_INFO(L"Saving configuration to: " + filename);
    
    return true;
}

bool ConfigManager::LoadDefaults() {
    SYSRECON_LOG_DEBUG(L"Loading default configuration");
    
    // General settings
    config_.verbose_output = false;
    config_.stealth_mode = false;
    config_.require_admin = true;
    config_.max_threads = 4;
    config_.timeout_seconds = 300;
    
    // Account module settings
    config_.accounts.enabled = true;
    config_.accounts.enumerate_groups = true;
    config_.accounts.check_passwords = false;
    config_.accounts.analyze_permissions = true;
    
    // Service module settings
    config_.services.enabled = true;
    config_.services.analyze_startup = true;
    config_.services.check_dependencies = true;
    config_.services.verify_signatures = false;
    
    // Process module settings
    config_.processes.enabled = true;
    config_.processes.analyze_memory = false;
    config_.processes.check_dlls = true;
    config_.processes.detect_injection = true;
    
    // Network module settings
    config_.network.enabled = true;
    config_.network.scan_listening_ports = true;
    config_.network.analyze_connections = true;
    config_.network.resolve_hostnames = false;
    
    // Registry module settings
    config_.registry.enabled = true;
    config_.registry.scan_startup_keys = true;
    config_.registry.analyze_policies = true;
    config_.registry.check_permissions = true;
    
    // Memory module settings
    config_.memory.enabled = false; // Disabled by default due to resource usage
    config_.memory.create_dumps = false;
    config_.memory.analyze_heap = false;
    config_.memory.scan_for_malware = true;
    config_.memory.max_dump_size_mb = 100;
    
    // Output settings
    config_.output.output_directory = L"./reports";
    config_.output.generate_json = true;
    config_.output.generate_csv = true;
    config_.output.generate_html = true;
    config_.output.generate_pdf = false;
    config_.output.compress_output = true;
    
    // Security settings
    config_.security.encrypt_output = false;
    config_.security.sign_reports = false;
    
    return true;
}

bool ConfigManager::IsModuleEnabled(ModuleType module) const {
    switch (module) {
        case ModuleType::Accounts:
            return config_.accounts.enabled;
        case ModuleType::Services:
            return config_.services.enabled;
        case ModuleType::Processes:
            return config_.processes.enabled;
        case ModuleType::Network:
            return config_.network.enabled;
        case ModuleType::Registry:
            return config_.registry.enabled;
        case ModuleType::Memory:
            return config_.memory.enabled;
        default:
            return false;
    }
}

bool ConfigManager::ValidateConfig() const {
    validation_errors_.clear();
    
    // Validate general settings
    if (config_.max_threads < 1 || config_.max_threads > 32) {
        validation_errors_.push_back(L"max_threads must be between 1 and 32");
    }
    
    if (config_.timeout_seconds < 10 || config_.timeout_seconds > 3600) {
        validation_errors_.push_back(L"timeout_seconds must be between 10 and 3600");
    }
    
    // Validate output directory
    if (config_.output.output_directory.empty()) {
        validation_errors_.push_back(L"output_directory cannot be empty");
    }
    
    // Validate memory settings
    if (config_.memory.max_dump_size_mb > 1024) {
        validation_errors_.push_back(L"max_dump_size_mb should not exceed 1024 MB");
    }
    
    // Check if at least one module is enabled
    bool any_module_enabled = config_.accounts.enabled ||
                             config_.services.enabled ||
                             config_.processes.enabled ||
                             config_.network.enabled ||
                             config_.registry.enabled ||
                             config_.memory.enabled;
    
    if (!any_module_enabled) {
        validation_errors_.push_back(L"At least one module must be enabled");
    }
    
    // Check if at least one output format is enabled
    bool any_output_enabled = config_.output.generate_json ||
                             config_.output.generate_csv ||
                             config_.output.generate_html ||
                             config_.output.generate_pdf;
    
    if (!any_output_enabled) {
        validation_errors_.push_back(L"At least one output format must be enabled");
    }
    
    return validation_errors_.empty();
}

StringVector ConfigManager::GetValidationErrors() const {
    return validation_errors_;
}

bool ConfigManager::DetectEnvironment() {
#ifdef _WIN32
    SYSRECON_LOG_DEBUG(L"Detecting Windows environment");
    
    // Detect Windows version
    String windows_version = Utils::GetWindowsVersion();
    SYSRECON_LOG_INFO(L"Detected Windows version: " + windows_version);
    
    // Detect if running as admin
    bool is_admin = Utils::IsRunningAsAdmin();
    SYSRECON_LOG_INFO(is_admin ? L"Running with administrator privileges" : L"Running with limited privileges");
    
    // Detect if in domain environment
    // TODO: Implement domain detection
    
    return true;
#else
    SYSRECON_LOG_DEBUG(L"Cross-compilation environment detected");
    return false;
#endif
}

void ConfigManager::ApplyEnvironmentOptimizations() {
    SYSRECON_LOG_DEBUG(L"Applying environment-specific optimizations");
    
#ifdef _WIN32
    // Adjust thread count based on system capabilities
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    int optimal_threads = std::min(static_cast<int>(sys_info.dwNumberOfProcessors), 8);
    if (config_.max_threads > optimal_threads) {
        config_.max_threads = optimal_threads;
        SYSRECON_LOG_INFO(L"Adjusted max_threads to: " + std::to_wstring(optimal_threads));
    }
    
    // Disable memory analysis on systems with low memory
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        SIZE_T total_memory_gb = mem_status.ullTotalPhys / (1024 * 1024 * 1024);
        if (total_memory_gb < 4 && config_.memory.enabled) {
            config_.memory.enabled = false;
            SYSRECON_LOG_WARNING(L"Disabled memory analysis due to low system memory");
        }
    }
#endif
}

} // namespace Core
} // namespace SysRecon
