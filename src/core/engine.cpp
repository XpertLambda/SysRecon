#include "../include/core/engine.h"
#include "../include/core/config.h"

namespace SysRecon {
namespace Core {

ScanEngine& ScanEngine::Instance() {
    static ScanEngine instance;
    return instance;
}

void ScanEngine::LoadConfig(const String& config_file) {
    ConfigManager& config_mgr = ConfigManager::Instance();
    if (config_mgr.LoadFromFile(config_file)) {
        SYSRECON_LOG_INFO(L"Configuration loaded from: " + config_file);
    } else {
        SYSRECON_LOG_WARNING(L"Failed to load configuration, using defaults");
    }
}

void ScanEngine::SetOutputDirectory(const String& output_dir) {
    output_directory_ = output_dir;
    if (!Core::Utils::DirectoryExists(output_dir)) {
        if (Core::Utils::CreateDirectory(output_dir)) {
            SYSRECON_LOG_INFO(L"Created output directory: " + output_dir);
        } else {
            SYSRECON_LOG_ERROR(L"Failed to create output directory: " + output_dir);
        }
    }
}

void ScanEngine::SetVerboseMode(bool verbose) {
    verbose_mode_ = verbose;
    Logger::Instance().SetLogLevel(verbose ? LogLevel::Debug : LogLevel::Info);
}

void ScanEngine::SetStealthMode(bool stealth) {
    stealth_mode_ = stealth;
    if (stealth) {
        Logger::Instance().SetConsoleOutput(false);
        SYSRECON_LOG_INFO(L"Stealth mode enabled");
    }
}

void ScanEngine::EnableModule(ModuleType module) {
    enabled_modules_[module] = true;
}

void ScanEngine::DisableModule(ModuleType module) {
    enabled_modules_[module] = false;
}

bool ScanEngine::IsModuleEnabled(ModuleType module) const {
    auto it = enabled_modules_.find(module);
    return (it != enabled_modules_.end()) ? it->second : true;
}

bool ScanEngine::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing SysRecon scan engine");
    
    if (!CheckPrivileges()) {
        SYSRECON_LOG_WARNING(L"Insufficient privileges detected");
    }
    
    if (output_directory_.empty()) {
        output_directory_ = L"./reports";
        SetOutputDirectory(output_directory_);
    }
    
    if (!InitializeModules()) {
        SYSRECON_LOG_ERROR(L"Failed to initialize modules");
        return false;
    }
    
    SYSRECON_LOG_INFO(L"Scan engine initialized successfully");
    return true;
}

bool ScanEngine::RunFullScan() {
    if (is_scanning_.load()) {
        SYSRECON_LOG_WARNING(L"Scan already in progress");
        return false;
    }
    
    is_scanning_.store(true);
    progress_.store(0.0f);
    ClearResults();
    
    SYSRECON_LOG_INFO(L"Starting full system scan");
    
    try {
        float step_progress = 100.0f / 6.0f;
        float current_progress = 0.0f;
        
        if (IsModuleEnabled(ModuleType::Accounts)) {
            UpdateProgress(current_progress, L"User Accounts");
            if (user_enum_ && !RunModuleScan(ModuleType::Accounts)) {
                SYSRECON_LOG_ERROR(L"User account enumeration failed");
            }
            current_progress += step_progress;
        }
        
        if (IsModuleEnabled(ModuleType::Services)) {
            UpdateProgress(current_progress, L"Services");
            if (service_enum_ && !RunModuleScan(ModuleType::Services)) {
                SYSRECON_LOG_ERROR(L"Service enumeration failed");
            }
            current_progress += step_progress;
        }
        
        if (IsModuleEnabled(ModuleType::Processes)) {
            UpdateProgress(current_progress, L"Processes");
            if (process_enum_ && !RunModuleScan(ModuleType::Processes)) {
                SYSRECON_LOG_ERROR(L"Process enumeration failed");
            }
            current_progress += step_progress;
        }
        
        if (IsModuleEnabled(ModuleType::Network)) {
            UpdateProgress(current_progress, L"Network");
            if (network_enum_ && !RunModuleScan(ModuleType::Network)) {
                SYSRECON_LOG_ERROR(L"Network enumeration failed");
            }
            current_progress += step_progress;
        }
        
        if (IsModuleEnabled(ModuleType::Registry)) {
            UpdateProgress(current_progress, L"Registry");
            if (registry_analyzer_ && !RunModuleScan(ModuleType::Registry)) {
                SYSRECON_LOG_ERROR(L"Registry analysis failed");
            }
            current_progress += step_progress;
        }
        
        if (IsModuleEnabled(ModuleType::Memory)) {
            UpdateProgress(current_progress, L"Memory");
            if (memory_analyzer_ && !RunModuleScan(ModuleType::Memory)) {
                SYSRECON_LOG_ERROR(L"Memory analysis failed");
            }
            current_progress += step_progress;
        }
        
        UpdateProgress(100.0f, L"Complete");
        
    } catch (const std::exception& e) {
        SYSRECON_LOG_ERROR(L"Scan failed with exception: " + Core::Utils::Utf8ToWide(e.what()));
        is_scanning_.store(false);
        return false;
    }
    
    is_scanning_.store(false);
    SYSRECON_LOG_INFO(L"Full scan completed successfully");
    return true;
}

bool ScanEngine::RunQuickScan() {
    SYSRECON_LOG_INFO(L"Starting quick scan (essential checks only)");
    
    bool success = true;
    
    if (IsModuleEnabled(ModuleType::Accounts) && user_enum_) {
        success &= user_enum_->EnumerateUsers();
    }
    
    if (IsModuleEnabled(ModuleType::Services) && service_enum_) {
        success &= service_enum_->EnumerateServices();
    }
    
    if (IsModuleEnabled(ModuleType::Network) && network_enum_) {
        success &= network_enum_->EnumerateListeningPorts();
    }
    
    if (IsModuleEnabled(ModuleType::Registry) && registry_analyzer_) {
        success &= registry_analyzer_->AnalyzeStartupKeys();
    }
    
    return success;
}

bool ScanEngine::RunModuleScan(ModuleType module) {
    switch (module) {
        case ModuleType::Accounts:
            if (user_enum_) {
                return user_enum_->EnumerateUsers() && 
                       user_enum_->EnumerateGroups() &&
                       user_enum_->AnalyzePermissions();
            }
            break;
            
        case ModuleType::Services:
            if (service_enum_) {
                return service_enum_->EnumerateServices() &&
                       service_enum_->AnalyzeStartupServices();
            }
            break;
            
        case ModuleType::Processes:
            if (process_enum_) {
                return process_enum_->EnumerateProcesses() &&
                       process_enum_->CheckLoadedModules();
            }
            break;
            
        case ModuleType::Network:
            if (network_enum_) {
                return network_enum_->EnumerateConnections() &&
                       network_enum_->EnumerateListeningPorts() &&
                       network_enum_->EnumerateInterfaces();
            }
            break;
            
        case ModuleType::Registry:
            if (registry_analyzer_) {
                return registry_analyzer_->AnalyzeStartupKeys() &&
                       registry_analyzer_->AnalyzePolicies();
            }
            break;
            
        case ModuleType::Memory:
            if (memory_analyzer_) {
                return memory_analyzer_->ScanForMalware() &&
                       memory_analyzer_->DetectInjection();
            }
            break;
            
        default:
            return false;
    }
    
    return false;
}

void ScanEngine::Cleanup() {
    SYSRECON_LOG_INFO(L"Cleaning up scan engine resources");
    
    if (user_enum_) user_enum_->Cleanup();
    if (service_enum_) service_enum_->Cleanup();
    if (process_enum_) process_enum_->Cleanup();
    if (network_enum_) network_enum_->Cleanup();
    if (registry_analyzer_) registry_analyzer_->Cleanup();
    if (memory_analyzer_) memory_analyzer_->Cleanup();
    
    ClearResults();
}

void ScanEngine::ClearResults() {
    std::lock_guard<std::mutex> lock(results_mutex_);
    scan_results_.clear();
}

bool ScanEngine::ExportResults(const String& format, const String& filename) {
    if (!report_generator_) {
        SYSRECON_LOG_ERROR(L"Report generator not initialized");
        return false;
    }
    
    SYSRECON_LOG_INFO(L"Exporting results to: " + filename);
    
    std::lock_guard<std::mutex> lock(results_mutex_);
    scan_results_.clear();
    
    if (user_enum_) {
        auto module_results = user_enum_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
    }
    
    if (service_enum_) {
        auto module_results = service_enum_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
    }
    
    report_generator_->SetScanResults(scan_results_);
    
    if (format == L"json") {
        return report_generator_->GenerateJSON(filename);
    } else if (format == L"csv") {
        return report_generator_->GenerateCSV(filename);
    } else if (format == L"html") {
        return report_generator_->GenerateHTML(filename);
    } else if (format == L"pdf") {
        return report_generator_->GeneratePDF(filename);
    } else {
        SYSRECON_LOG_ERROR(L"Unsupported format: " + format);
        return false;
    }
}

bool ScanEngine::CheckPrivileges() {
#ifdef _WIN32
    return Core::Utils::IsRunningAsAdmin();
#else
    return true;
#endif
}

bool ScanEngine::InitializeModules() {
    SYSRECON_LOG_DEBUG(L"Initializing scan modules");
    
    if (IsModuleEnabled(ModuleType::Accounts)) {
        user_enum_ = std::make_unique<Modules::UserEnumerator>();
        if (!user_enum_->Initialize()) {
            SYSRECON_LOG_ERROR(L"Failed to initialize user enumeration module");
            return false;
        }
    }
    
    return true;
}

void ScanEngine::UpdateProgress(float progress, const String& module) {
    progress_.store(progress);
    current_module_ = module;
    
    if (verbose_mode_) {
        SYSRECON_LOG_DEBUG(L"Progress: " + std::to_wstring(static_cast<int>(progress)) + L"% - " + module);
    }
}

void ScanEngine::AddError(const String& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_messages_.push_back(error);
    SYSRECON_LOG_ERROR(error);
}

}
}
