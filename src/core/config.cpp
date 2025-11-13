#include "../include/core/config.h"
#include "../include/core/utils.h"
#include <json/json.hpp>
#include <fstream>

using json = nlohmann::json;

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
    
    SYSRECON_LOG_INFO(L"Loading configuration from: " + filename);
    
    // Load defaults first
    LoadDefaults();
    
    try {
        // Read JSON file
        std::ifstream file(Utils::WideToUtf8(filename));
        if (!file.is_open()) {
            validation_errors_.push_back(L"Failed to open configuration file");
            return false;
        }
        
        json j;
        file >> j;
        
        // Parse general settings
        if (j.contains("general")) {
            auto& gen = j["general"];
            if (gen.contains("verbose_output")) config_.verbose_output = gen["verbose_output"];
            if (gen.contains("stealth_mode")) config_.stealth_mode = gen["stealth_mode"];
            if (gen.contains("require_admin")) config_.require_admin = gen["require_admin"];
            if (gen.contains("max_threads")) config_.max_threads = gen["max_threads"];
            if (gen.contains("timeout_seconds")) config_.timeout_seconds = gen["timeout_seconds"];
        }
        
        // Parse module settings
        if (j.contains("modules")) {
            auto& modules = j["modules"];
            
            if (modules.contains("accounts")) {
                auto& acc = modules["accounts"];
                if (acc.contains("enabled")) config_.accounts.enabled = acc["enabled"];
                if (acc.contains("enumerate_groups")) config_.accounts.enumerate_groups = acc["enumerate_groups"];
                if (acc.contains("check_passwords")) config_.accounts.check_passwords = acc["check_passwords"];
                if (acc.contains("analyze_permissions")) config_.accounts.analyze_permissions = acc["analyze_permissions"];
            }
            
            if (modules.contains("services")) {
                auto& svc = modules["services"];
                if (svc.contains("enabled")) config_.services.enabled = svc["enabled"];
                if (svc.contains("analyze_startup")) config_.services.analyze_startup = svc["analyze_startup"];
                if (svc.contains("check_dependencies")) config_.services.check_dependencies = svc["check_dependencies"];
                if (svc.contains("verify_signatures")) config_.services.verify_signatures = svc["verify_signatures"];
            }
            
            if (modules.contains("processes")) {
                auto& proc = modules["processes"];
                if (proc.contains("enabled")) config_.processes.enabled = proc["enabled"];
                if (proc.contains("analyze_memory")) config_.processes.analyze_memory = proc["analyze_memory"];
                if (proc.contains("check_dlls")) config_.processes.check_dlls = proc["check_dlls"];
                if (proc.contains("detect_injection")) config_.processes.detect_injection = proc["detect_injection"];
            }
            
            if (modules.contains("network")) {
                auto& net = modules["network"];
                if (net.contains("enabled")) config_.network.enabled = net["enabled"];
                if (net.contains("scan_listening_ports")) config_.network.scan_listening_ports = net["scan_listening_ports"];
                if (net.contains("analyze_connections")) config_.network.analyze_connections = net["analyze_connections"];
                if (net.contains("resolve_hostnames")) config_.network.resolve_hostnames = net["resolve_hostnames"];
            }
            
            if (modules.contains("registry")) {
                auto& reg = modules["registry"];
                if (reg.contains("enabled")) config_.registry.enabled = reg["enabled"];
                if (reg.contains("scan_startup_keys")) config_.registry.scan_startup_keys = reg["scan_startup_keys"];
                if (reg.contains("analyze_policies")) config_.registry.analyze_policies = reg["analyze_policies"];
                if (reg.contains("check_permissions")) config_.registry.check_permissions = reg["check_permissions"];
                
                if (reg.contains("custom_keys")) {
                    config_.registry.custom_keys.clear();
                    for (const auto& key : reg["custom_keys"]) {
                        config_.registry.custom_keys.push_back(Utils::Utf8ToWide(key.get<std::string>()));
                    }
                }
            }
            
            if (modules.contains("memory")) {
                auto& mem = modules["memory"];
                if (mem.contains("enabled")) config_.memory.enabled = mem["enabled"];
                if (mem.contains("create_dumps")) config_.memory.create_dumps = mem["create_dumps"];
                if (mem.contains("analyze_heap")) config_.memory.analyze_heap = mem["analyze_heap"];
                if (mem.contains("scan_for_malware")) config_.memory.scan_for_malware = mem["scan_for_malware"];
                if (mem.contains("max_dump_size_mb")) config_.memory.max_dump_size_mb = mem["max_dump_size_mb"];
            }
        }
        
        // Parse output settings
        if (j.contains("output")) {
            auto& out = j["output"];
            if (out.contains("output_directory")) {
                config_.output.output_directory = Utils::Utf8ToWide(out["output_directory"].get<std::string>());
            }
            if (out.contains("generate_json")) config_.output.generate_json = out["generate_json"];
            if (out.contains("generate_csv")) config_.output.generate_csv = out["generate_csv"];
            if (out.contains("generate_html")) config_.output.generate_html = out["generate_html"];
            if (out.contains("generate_pdf")) config_.output.generate_pdf = out["generate_pdf"];
            if (out.contains("compress_output")) config_.output.compress_output = out["compress_output"];
        }
        
        // Parse security settings
        if (j.contains("security")) {
            auto& sec = j["security"];
            if (sec.contains("encrypt_output")) config_.security.encrypt_output = sec["encrypt_output"];
            if (sec.contains("encryption_key")) {
                config_.security.encryption_key = Utils::Utf8ToWide(sec["encryption_key"].get<std::string>());
            }
            if (sec.contains("sign_reports")) config_.security.sign_reports = sec["sign_reports"];
            if (sec.contains("signing_cert")) {
                config_.security.signing_cert = Utils::Utf8ToWide(sec["signing_cert"].get<std::string>());
            }
        }
        
        SYSRECON_LOG_INFO(L"Configuration loaded successfully");
        
    } catch (const json::exception& e) {
        validation_errors_.push_back(L"JSON parsing error: " + Utils::Utf8ToWide(e.what()));
        SYSRECON_LOG_ERROR(L"Failed to parse configuration: " + Utils::Utf8ToWide(e.what()));
        return false;
    } catch (const std::exception& e) {
        validation_errors_.push_back(L"Configuration loading error: " + Utils::Utf8ToWide(e.what()));
        SYSRECON_LOG_ERROR(L"Failed to load configuration: " + Utils::Utf8ToWide(e.what()));
        return false;
    }
    
    return ValidateConfig();
}

bool ConfigManager::SaveToFile(const String& filename) const {
    SYSRECON_LOG_INFO(L"Saving configuration to: " + filename);
    
    try {
        json j;
        
        // General settings
        j["general"]["verbose_output"] = config_.verbose_output;
        j["general"]["stealth_mode"] = config_.stealth_mode;
        j["general"]["require_admin"] = config_.require_admin;
        j["general"]["max_threads"] = config_.max_threads;
        j["general"]["timeout_seconds"] = config_.timeout_seconds;
        
        // Module settings
        j["modules"]["accounts"]["enabled"] = config_.accounts.enabled;
        j["modules"]["accounts"]["enumerate_groups"] = config_.accounts.enumerate_groups;
        j["modules"]["accounts"]["check_passwords"] = config_.accounts.check_passwords;
        j["modules"]["accounts"]["analyze_permissions"] = config_.accounts.analyze_permissions;
        
        j["modules"]["services"]["enabled"] = config_.services.enabled;
        j["modules"]["services"]["analyze_startup"] = config_.services.analyze_startup;
        j["modules"]["services"]["check_dependencies"] = config_.services.check_dependencies;
        j["modules"]["services"]["verify_signatures"] = config_.services.verify_signatures;
        
        j["modules"]["processes"]["enabled"] = config_.processes.enabled;
        j["modules"]["processes"]["analyze_memory"] = config_.processes.analyze_memory;
        j["modules"]["processes"]["check_dlls"] = config_.processes.check_dlls;
        j["modules"]["processes"]["detect_injection"] = config_.processes.detect_injection;
        
        j["modules"]["network"]["enabled"] = config_.network.enabled;
        j["modules"]["network"]["scan_listening_ports"] = config_.network.scan_listening_ports;
        j["modules"]["network"]["analyze_connections"] = config_.network.analyze_connections;
        j["modules"]["network"]["resolve_hostnames"] = config_.network.resolve_hostnames;
        
        j["modules"]["registry"]["enabled"] = config_.registry.enabled;
        j["modules"]["registry"]["scan_startup_keys"] = config_.registry.scan_startup_keys;
        j["modules"]["registry"]["analyze_policies"] = config_.registry.analyze_policies;
        j["modules"]["registry"]["check_permissions"] = config_.registry.check_permissions;
        j["modules"]["registry"]["custom_keys"] = json::array();
        for (const auto& key : config_.registry.custom_keys) {
            j["modules"]["registry"]["custom_keys"].push_back(Utils::WideToUtf8(key));
        }
        
        j["modules"]["memory"]["enabled"] = config_.memory.enabled;
        j["modules"]["memory"]["create_dumps"] = config_.memory.create_dumps;
        j["modules"]["memory"]["analyze_heap"] = config_.memory.analyze_heap;
        j["modules"]["memory"]["scan_for_malware"] = config_.memory.scan_for_malware;
        j["modules"]["memory"]["max_dump_size_mb"] = config_.memory.max_dump_size_mb;
        
        // Output settings
        j["output"]["output_directory"] = Utils::WideToUtf8(config_.output.output_directory);
        j["output"]["generate_json"] = config_.output.generate_json;
        j["output"]["generate_csv"] = config_.output.generate_csv;
        j["output"]["generate_html"] = config_.output.generate_html;
        j["output"]["generate_pdf"] = config_.output.generate_pdf;
        j["output"]["compress_output"] = config_.output.compress_output;
        
        // Security settings
        j["security"]["encrypt_output"] = config_.security.encrypt_output;
        j["security"]["encryption_key"] = Utils::WideToUtf8(config_.security.encryption_key);
        j["security"]["sign_reports"] = config_.security.sign_reports;
        j["security"]["signing_cert"] = Utils::WideToUtf8(config_.security.signing_cert);
        
        // Write to file
        std::ofstream file(Utils::WideToUtf8(filename));
        if (!file.is_open()) {
            SYSRECON_LOG_ERROR(L"Failed to open file for writing: " + filename);
            return false;
        }
        
        file << j.dump(4);  // Pretty print with 4-space indentation
        file.close();
        
        SYSRECON_LOG_INFO(L"Configuration saved successfully");
        return true;
        
    } catch (const std::exception& e) {
        SYSRECON_LOG_ERROR(L"Failed to save configuration: " + Utils::Utf8ToWide(e.what()));
        return false;
    }
}

bool ConfigManager::LoadDefaults() {
    SYSRECON_LOG_DEBUG(L"Loading default configuration");
    
    config_.verbose_output = false;
    config_.stealth_mode = false;
    config_.require_admin = true;
    config_.max_threads = 4;
    config_.timeout_seconds = 300;
    
    config_.accounts.enabled = true;
    config_.accounts.enumerate_groups = true;
    config_.accounts.check_passwords = false;
    config_.accounts.analyze_permissions = true;
    
    config_.services.enabled = true;
    config_.services.analyze_startup = true;
    config_.services.check_dependencies = true;
    config_.services.verify_signatures = false;
    
    config_.processes.enabled = true;
    config_.processes.analyze_memory = false;
    config_.processes.check_dlls = true;
    config_.processes.detect_injection = true;
    
    config_.network.enabled = true;
    config_.network.scan_listening_ports = true;
    config_.network.analyze_connections = true;
    config_.network.resolve_hostnames = false;
    
    config_.registry.enabled = true;
    config_.registry.scan_startup_keys = true;
    config_.registry.analyze_policies = true;
    config_.registry.check_permissions = true;
    
    config_.memory.enabled = false;
    config_.memory.create_dumps = false;
    config_.memory.analyze_heap = false;
    config_.memory.scan_for_malware = true;
    config_.memory.max_dump_size_mb = 100;
    
    config_.output.output_directory = L"./reports";
    config_.output.generate_json = true;
    config_.output.generate_csv = true;
    config_.output.generate_html = true;
    config_.output.generate_pdf = false;
    config_.output.compress_output = true;
    
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
    
    if (config_.max_threads < 1 || config_.max_threads > 32) {
        validation_errors_.push_back(L"max_threads must be between 1 and 32");
    }
    
    if (config_.timeout_seconds < 10 || config_.timeout_seconds > 3600) {
        validation_errors_.push_back(L"timeout_seconds must be between 10 and 3600");
    }
    
    if (config_.output.output_directory.empty()) {
        validation_errors_.push_back(L"output_directory cannot be empty");
    }
    
    if (config_.memory.max_dump_size_mb > 1024) {
        validation_errors_.push_back(L"max_dump_size_mb should not exceed 1024 MB");
    }
    
    bool any_module_enabled = config_.accounts.enabled ||
                             config_.services.enabled ||
                             config_.processes.enabled ||
                             config_.network.enabled ||
                             config_.registry.enabled ||
                             config_.memory.enabled;
    
    if (!any_module_enabled) {
        validation_errors_.push_back(L"At least one module must be enabled");
    }
    
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
    
    String windows_version = Utils::GetWindowsVersion();
    SYSRECON_LOG_INFO(L"Detected Windows version: " + windows_version);
    
    bool is_admin = Utils::IsRunningAsAdmin();
    SYSRECON_LOG_INFO(is_admin ? L"Running with administrator privileges" : L"Running with limited privileges");
    
    return true;
#else
    SYSRECON_LOG_DEBUG(L"Cross-compilation environment detected");
    return false;
#endif
}

void ConfigManager::ApplyEnvironmentOptimizations() {
    SYSRECON_LOG_DEBUG(L"Applying environment-specific optimizations");
    
#ifdef _WIN32
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    int optimal_threads = std::min(static_cast<int>(sys_info.dwNumberOfProcessors), 8);
    if (config_.max_threads > optimal_threads) {
        config_.max_threads = optimal_threads;
        SYSRECON_LOG_INFO(L"Adjusted max_threads to: " + std::to_wstring(optimal_threads));
    }
    
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

}
}
