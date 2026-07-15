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
    if (!config_mgr.LoadFromFile(config_file)) {
        SYSRECON_LOG_WARNING(L"Failed to load configuration, using defaults");
        return;
    }
    SYSRECON_LOG_INFO(L"Configuration loaded from: " + config_file);

    // Apply the file's module selection to the engine. Nothing did this
    // before: config.json was parsed and then entirely ignored, while the
    // engine consulted only its own default-true map. Must run before
    // Initialize(), which constructs modules based on this selection.
    const ScanConfig& cfg = config_mgr.GetConfig();

    auto select = [this](ModuleType type, bool enabled) {
        if (enabled) {
            EnableModule(type);
        } else {
            DisableModule(type);
        }
    };
    select(ModuleType::Accounts,  cfg.accounts.enabled);
    select(ModuleType::Services,  cfg.services.enabled);
    select(ModuleType::Processes, cfg.processes.enabled);
    select(ModuleType::Network,   cfg.network.enabled);
    select(ModuleType::Registry,  cfg.registry.enabled);
    select(ModuleType::Memory,    cfg.memory.enabled);

    if (!cfg.output.output_directory.empty()) {
        SetOutputDirectory(cfg.output.output_directory);
    }
    SetStealthMode(cfg.stealth_mode);
    SetVerboseMode(cfg.verbose_output);
}

void ScanEngine::ApplyConfigToModules() {
    const ScanConfig& cfg = ConfigManager::Instance().GetConfig();

    // Module setters existed but were never called from anywhere, so every
    // per-module option in config.json was decoration.
    if (process_enum_) {
        process_enum_->SetCheckDlls(cfg.processes.check_dlls);
    }
    if (registry_analyzer_) {
        registry_analyzer_->SetScanStartupKeys(cfg.registry.scan_startup_keys);
        registry_analyzer_->SetAnalyzePolicies(cfg.registry.analyze_policies);
        registry_analyzer_->SetCheckPermissions(cfg.registry.check_permissions);
        for (const auto& key : cfg.registry.custom_keys) {
            registry_analyzer_->AddCustomKey(key);
        }
    }
    if (memory_analyzer_) {
        memory_analyzer_->SetCreateDumps(cfg.memory.create_dumps);
        memory_analyzer_->SetAnalyzeHeap(cfg.memory.analyze_heap);
        memory_analyzer_->SetMaxDumpSize(cfg.memory.max_dump_size_mb * 1024 * 1024);
    }
    if (user_enum_) {
        user_enum_->SetEnumerateGroups(cfg.accounts.enumerate_groups);
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

    // A failure in one module must not discard the findings of the others --
    // the earlier `success &= ...` meant a single failing check (e.g.
    // NetUserEnum on a host with no local accounts) threw away the whole scan
    // and produced no report at all. Failures are recorded and surfaced via
    // GetErrors(); the scan itself succeeds if it ran to completion. This
    // matches RunFullScan's contract.
    if (IsModuleEnabled(ModuleType::Accounts) && user_enum_) {
        if (!user_enum_->EnumerateUsers()) {
            AddError(L"Quick scan: user enumeration failed");
        }
    }

    if (IsModuleEnabled(ModuleType::Services) && service_enum_) {
        if (!service_enum_->EnumerateServices()) {
            AddError(L"Quick scan: service enumeration failed");
        }
    }

    if (IsModuleEnabled(ModuleType::Network) && network_enum_) {
        if (!network_enum_->EnumerateListeningPorts()) {
            AddError(L"Quick scan: listening port enumeration failed");
        }
    }

    if (IsModuleEnabled(ModuleType::Registry) && registry_analyzer_) {
        if (!registry_analyzer_->AnalyzeStartupKeys()) {
            AddError(L"Quick scan: registry startup analysis failed");
        }
    }

    return true;
}

bool ScanEngine::RunModuleScan(ModuleType module) {
    // Each step runs independently and every failure is recorded. These were
    // previously chained with &&, so one failing check silently skipped the
    // rest -- e.g. a failed EnumerateConnections() meant listening ports and
    // interfaces were never enumerated at all.
    auto run_all = [this](const String& module_label,
                          std::initializer_list<std::pair<const wchar_t*, std::function<bool()>>> steps) {
        bool all_ok = true;
        for (const auto& step : steps) {
            if (!step.second()) {
                AddError(module_label + L": " + step.first + L" failed");
                all_ok = false;
            }
        }
        return all_ok;
    };

    switch (module) {
        case ModuleType::Accounts:
            if (user_enum_) {
                return run_all(L"Accounts", {
                    {L"user enumeration",  [&] { return user_enum_->EnumerateUsers(); }},
                    {L"group enumeration", [&] { return user_enum_->EnumerateGroups(); }},
                });
            }
            break;

        case ModuleType::Services:
            if (service_enum_) {
                return run_all(L"Services", {
                    {L"service enumeration", [&] { return service_enum_->EnumerateServices(); }},
                });
            }
            break;

        case ModuleType::Processes:
            if (process_enum_) {
                return run_all(L"Processes", {
                    {L"process enumeration", [&] { return process_enum_->EnumerateProcesses(); }},
                    {L"module inspection",   [&] { return process_enum_->CheckLoadedModules(); }},
                });
            }
            break;

        case ModuleType::Network:
            if (network_enum_) {
                return run_all(L"Network", {
                    {L"connection enumeration", [&] { return network_enum_->EnumerateConnections(); }},
                    {L"listening ports",        [&] { return network_enum_->EnumerateListeningPorts(); }},
                    {L"interfaces",             [&] { return network_enum_->EnumerateInterfaces(); }},
                    {L"shares",                 [&] { return network_enum_->EnumerateShares(); }},
                    {L"firewall",               [&] { return network_enum_->AnalyzeFirewall(); }},
                });
            }
            break;

        case ModuleType::Registry:
            if (registry_analyzer_) {
                return run_all(L"Registry", {
                    {L"startup key analysis", [&] { return registry_analyzer_->AnalyzeStartupKeys(); }},
                    {L"policy analysis",      [&] { return registry_analyzer_->AnalyzePolicies(); }},
                });
            }
            break;

        case ModuleType::Memory:
            if (memory_analyzer_) {
                return run_all(L"Memory", {
                    {L"malware scan",      [&] { return memory_analyzer_->ScanForMalware(); }},
                    {L"injection detection", [&] { return memory_analyzer_->DetectInjection(); }},
                });
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
    
    // Collect results from all modules
    if (user_enum_) {
        auto module_results = user_enum_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
        SYSRECON_LOG_DEBUG(L"Collected " + std::to_wstring(module_results.size()) + L" user results");
    }
    
    if (service_enum_) {
        auto module_results = service_enum_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
        SYSRECON_LOG_DEBUG(L"Collected " + std::to_wstring(module_results.size()) + L" service results");
    }
    
    if (process_enum_) {
        auto module_results = process_enum_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
        SYSRECON_LOG_DEBUG(L"Collected " + std::to_wstring(module_results.size()) + L" process results");
    }
    
    if (network_enum_) {
        auto module_results = network_enum_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
        SYSRECON_LOG_DEBUG(L"Collected " + std::to_wstring(module_results.size()) + L" network results");
    }
    
    if (registry_analyzer_) {
        auto module_results = registry_analyzer_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
        SYSRECON_LOG_DEBUG(L"Collected " + std::to_wstring(module_results.size()) + L" registry results");
    }
    
    if (memory_analyzer_) {
        auto module_results = memory_analyzer_->GetScanResults();
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
        SYSRECON_LOG_DEBUG(L"Collected " + std::to_wstring(module_results.size()) + L" memory results");
    }
    
    SYSRECON_LOG_INFO(L"Total scan results collected: " + std::to_wstring(scan_results_.size()));
    
    report_generator_->SetScanResults(scan_results_);
    
    // Set system info
    Modules::SystemInfo sys_info;
    sys_info.computer_name = Core::Utils::GetComputerName();
    sys_info.os_version = Core::Utils::GetWindowsVersion();
    sys_info.architecture = Core::Utils::IsWow64Process() ? L"x86" : L"x64";
    sys_info.scan_time = std::chrono::system_clock::now();
    sys_info.sysrecon_version = SYSRECON_VERSION;
    report_generator_->SetSystemInfo(sys_info);
    
    if (format == L"json") {
        return report_generator_->GenerateJSON(filename);
    } else if (format == L"csv") {
        return report_generator_->GenerateCSV(filename);
    } else if (format == L"html") {
        return report_generator_->GenerateHTML(filename);
    } else if (format == L"pdf") {
        return report_generator_->GeneratePDF(filename);
    } else if (format == L"all") {
        // Generate all formats
        String base_name = filename.substr(0, filename.find_last_of(L'.'));
        bool success = true;
        success &= report_generator_->GenerateJSON(base_name + L".json");
        success &= report_generator_->GenerateCSV(base_name + L".csv");
        success &= report_generator_->GenerateHTML(base_name + L".html");
        return success;
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
    
    bool all_success = true;
    
    if (IsModuleEnabled(ModuleType::Accounts)) {
        user_enum_ = std::make_unique<Modules::UserEnumerator>();
        if (!user_enum_->Initialize()) {
            SYSRECON_LOG_ERROR(L"Failed to initialize user enumeration module");
            all_success = false;
        } else {
            SYSRECON_LOG_DEBUG(L"User enumeration module initialized");
        }
    }
    
    if (IsModuleEnabled(ModuleType::Services)) {
        service_enum_ = std::make_unique<Modules::ServiceEnumerator>();
        if (!service_enum_->Initialize()) {
            SYSRECON_LOG_ERROR(L"Failed to initialize service enumeration module");
            all_success = false;
        } else {
            SYSRECON_LOG_DEBUG(L"Service enumeration module initialized");
        }
    }
    
    if (IsModuleEnabled(ModuleType::Processes)) {
        process_enum_ = std::make_unique<Modules::ProcessEnumerator>();
        if (!process_enum_->Initialize()) {
            SYSRECON_LOG_ERROR(L"Failed to initialize process enumeration module");
            all_success = false;
        } else {
            SYSRECON_LOG_DEBUG(L"Process enumeration module initialized");
        }
    }
    
    if (IsModuleEnabled(ModuleType::Network)) {
        network_enum_ = std::make_unique<Modules::NetworkEnumerator>();
        if (!network_enum_->Initialize()) {
            SYSRECON_LOG_ERROR(L"Failed to initialize network enumeration module");
            all_success = false;
        } else {
            SYSRECON_LOG_DEBUG(L"Network enumeration module initialized");
        }
    }
    
    if (IsModuleEnabled(ModuleType::Registry)) {
        registry_analyzer_ = std::make_unique<Modules::RegistryAnalyzer>();
        if (!registry_analyzer_->Initialize()) {
            SYSRECON_LOG_ERROR(L"Failed to initialize registry analyzer module");
            all_success = false;
        } else {
            SYSRECON_LOG_DEBUG(L"Registry analyzer module initialized");
        }
    }
    
    if (IsModuleEnabled(ModuleType::Memory)) {
        memory_analyzer_ = std::make_unique<Modules::MemoryAnalyzer>();
        if (!memory_analyzer_->Initialize()) {
            SYSRECON_LOG_ERROR(L"Failed to initialize memory analyzer module");
            all_success = false;
        } else {
            SYSRECON_LOG_DEBUG(L"Memory analyzer module initialized");
        }
    }
    
    // Always initialize report generator
    report_generator_ = std::make_unique<Modules::ReportGenerator>();
    SYSRECON_LOG_DEBUG(L"Report generator initialized");
    
    return all_success;
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
