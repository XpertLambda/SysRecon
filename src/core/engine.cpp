#include "../../include/core/engine.h"
#include "../../include/core/config.h"

namespace SysRecon {
namespace Core {

ScanEngine& ScanEngine::Instance() {
    static ScanEngine instance;
    return instance;
}

void ScanEngine::Reset() {
    DestroyModules();
    ConfigManager::Instance().LoadDefaults();
    config_loaded_ = false;
    config_path_.clear();
    output_directory_.clear();
    stealth_mode_ = false;
    min_severity_ = SecurityLevel::Low;
    selection_ = ModuleSelection::FromConfig(ScanConfig{});
    progress_.store(0.0f);
    current_module_.clear();
    ClearResults();
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_messages_.clear();
}

bool ScanEngine::LoadConfig(const String& config_file) {
    ConfigManager& config_mgr = ConfigManager::Instance();
    if (!config_mgr.LoadFromFile(config_file)) {
        for (const auto& err : config_mgr.GetValidationErrors()) {
            SYSRECON_LOG_WARNING(L"Config: " + err);
        }
        SYSRECON_LOG_WARNING(L"Failed to load configuration from " + config_file +
                             L"; using built-in defaults");
        return false;
    }
    SYSRECON_LOG_INFO(L"Configuration loaded from: " + config_file);

    config_path_ = config_file;
    config_loaded_ = true;

    const ScanConfig& cfg = config_mgr.GetConfig();
    selection_ = ModuleSelection::FromConfig(cfg);

    // A relative output_directory is relative to the config file, not to the
    // process's working directory. An elevated prompt starts in System32, so
    // "./reports" previously meant C:\Windows\System32\reports.
    const String config_dir = ParentDirectory(config_file);
    SetOutputDirectory(ResolveAgainst(config_dir, cfg.output.output_directory));
    // The config can turn stealth on but never off: `stealth_mode: false`
    // must not re-enable console logging that --stealth already silenced.
    if (cfg.stealth_mode) {
        SetStealthMode(true);
    }
    return true;
}

void ScanEngine::SetModuleSelection(const ModuleSelection& selection) {
    selection_ = selection;
}

void ScanEngine::EnableModule(ModuleType module) {
    selection_.Set(module, true);
}

void ScanEngine::DisableModule(ModuleType module) {
    selection_.Set(module, false);
}

bool ScanEngine::IsModuleEnabled(ModuleType module) const {
    return selection_.IsEnabled(module);
}

void ScanEngine::ApplyConfigToModules() {
    const ScanConfig& cfg = ConfigManager::Instance().GetConfig();

    if (process_enum_) {
        // Per-process module snapshots open a handle to every process; stealth
        // mode skips them.
        process_enum_->SetCheckDlls(cfg.processes.check_dlls && !stealth_mode_);
    }
    if (registry_analyzer_) {
        registry_analyzer_->SetScanStartupKeys(cfg.registry.scan_startup_keys);
        registry_analyzer_->SetAnalyzePolicies(cfg.registry.analyze_policies);
        registry_analyzer_->SetCheckPermissions(cfg.registry.check_permissions);
        for (const auto& key : cfg.registry.custom_keys) {
            registry_analyzer_->AddCustomKey(key);
        }
    }
    if (network_enum_) {
        // These two were parsed from config.json and never passed on at all.
        network_enum_->SetScanListeningPorts(cfg.network.scan_listening_ports);
        network_enum_->SetAnalyzeConnections(cfg.network.analyze_connections);
    }
    if (memory_analyzer_) {
        memory_analyzer_->SetScanForMalware(cfg.memory.scan_for_malware);
        memory_analyzer_->SetCreateDumps(cfg.memory.create_dumps);
        memory_analyzer_->SetMaxDumpSize(cfg.memory.max_dump_size_mb * 1024 * 1024);
    }
    if (user_enum_) {
        user_enum_->SetEnumerateGroups(cfg.accounts.enumerate_groups);
    }
    if (privesc_analyzer_) {
        privesc_analyzer_->SetCheckServices(cfg.privesc.check_services);
        privesc_analyzer_->SetCheckRegistry(cfg.privesc.check_registry);
        privesc_analyzer_->SetCheckFilesystem(cfg.privesc.check_filesystem);
        privesc_analyzer_->SetCheckCredentials(cfg.privesc.check_credentials);
        privesc_analyzer_->SetVerifySignatures(cfg.privesc.verify_signatures);
        privesc_analyzer_->SetCheckTokens(cfg.privesc.check_tokens);
        privesc_analyzer_->SetCheckScheduledTasks(cfg.privesc.check_scheduled_tasks);
        privesc_analyzer_->SetCheckPatches(cfg.privesc.check_patches);
        privesc_analyzer_->SetCheckDefender(cfg.privesc.check_defender);
        privesc_analyzer_->SetCheckHardening(cfg.privesc.check_hardening);
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

void ScanEngine::SetStealthMode(bool stealth) {
    stealth_mode_ = stealth;
    Logger::Instance().SetConsoleOutput(!stealth);
    if (stealth) {
        SYSRECON_LOG_INFO(L"Stealth mode enabled");
    }
}

bool ScanEngine::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing SysRecon scan engine");

    is_elevated_ = CheckPrivileges();
    if (!is_elevated_) {
        SYSRECON_LOG_WARNING(L"Not running as Administrator: results will be incomplete");
    }

    // require_admin is only honoured when a config file was actually loaded:
    // the in-code default is true, so enforcing it unconditionally would abort
    // every non-admin run even with no config file present.
    if (config_loaded_ && ConfigManager::Instance().GetConfig().require_admin && !is_elevated_) {
        SYSRECON_LOG_ERROR(L"Configuration requires Administrator privileges "
                           L"(general.require_admin); aborting");
        return false;
    }

    if (!selection_.Any()) {
        SYSRECON_LOG_ERROR(L"No scan modules selected");
        return false;
    }

#ifdef _WIN32
    // SE_DEBUG_NAME is process-wide and is needed by the process and memory
    // modules to open other processes.
    if (selection_.processes || selection_.memory) {
        if (!Core::Utils::EnableDebugPrivilege()) {
            SYSRECON_LOG_WARNING(L"Could not enable SeDebugPrivilege: "
                                 L"process and memory inspection will be limited");
        }
    }
#endif

    if (output_directory_.empty()) {
        SetOutputDirectory(L"./reports");
    }

    if (!InitializeModules()) {
        SYSRECON_LOG_ERROR(L"Failed to initialize modules");
        return false;
    }

    SYSRECON_LOG_INFO(L"Scan engine initialized (" + Utils::Join(selection_.Names(), L", ") + L")");
    return true;
}

bool ScanEngine::RunFullScan() {
    if (is_scanning_.exchange(true)) {
        SYSRECON_LOG_WARNING(L"Scan already in progress");
        return false;
    }

    progress_.store(0.0f);
    ClearResults();

    SYSRECON_LOG_INFO(L"Starting full system scan");

    try {
        struct Step {
            ModuleType type;
            const wchar_t* label;
            bool constructed;
        };
        const Step steps[] = {
            { ModuleType::Accounts,  L"User Accounts", user_enum_ != nullptr },
            { ModuleType::Services,  L"Services",      service_enum_ != nullptr },
            { ModuleType::Processes, L"Processes",     process_enum_ != nullptr },
            { ModuleType::Network,   L"Network",       network_enum_ != nullptr },
            { ModuleType::Registry,  L"Registry",      registry_analyzer_ != nullptr },
            { ModuleType::Memory,    L"Memory",        memory_analyzer_ != nullptr },
            { ModuleType::PrivEsc,   L"Privilege Escalation", privesc_analyzer_ != nullptr },
            { ModuleType::Domain,    L"Domain",        domain_recon_ != nullptr },
        };

        // Divide progress across the modules that will actually run.
        const size_t enabled_count = selection_.Count();
        const float step_progress = enabled_count > 0 ? (100.0f / enabled_count) : 100.0f;
        float current_progress = 0.0f;

        for (const auto& step : steps) {
            if (!IsModuleEnabled(step.type)) {
                continue;
            }
            UpdateProgress(current_progress, step.label);
            if (!step.constructed) {
                // Cannot happen with the documented lifecycle; if it does, say
                // so instead of reporting a clean scan of a module that never ran.
                AddError(String(step.label) + L": module was selected but not initialized");
            } else if (!RunModuleScan(step.type)) {
                SYSRECON_LOG_WARNING(String(step.label) + L": one or more checks did not complete");
            }
            current_progress += step_progress;
        }

        UpdateProgress(100.0f, L"Complete");

    } catch (const std::exception& e) {
        AddError(L"Scan aborted with exception: " + Core::Utils::Utf8ToWide(e.what()));
        is_scanning_.store(false);
        return false;
    }

    is_scanning_.store(false);
    SYSRECON_LOG_INFO(L"Full scan completed");
    return true;
}

bool ScanEngine::RunQuickScan() {
    if (is_scanning_.exchange(true)) {
        SYSRECON_LOG_WARNING(L"Scan already in progress");
        return false;
    }
    ClearResults();
    SYSRECON_LOG_INFO(L"Starting quick scan (essential checks only)");

    // A failure in one module must not discard the findings of the others:
    // failures are recorded and surfaced via GetErrors(); the scan itself
    // succeeds if it ran to completion. This matches RunFullScan's contract.
    try {
        if (IsModuleEnabled(ModuleType::Accounts) && user_enum_) {
            UpdateProgress(0.0f, L"User Accounts");
            if (!user_enum_->EnumerateUsers()) {
                AddError(L"Quick scan: user enumeration failed");
            }
        }
        if (IsModuleEnabled(ModuleType::Services) && service_enum_) {
            UpdateProgress(25.0f, L"Services");
            if (!service_enum_->EnumerateServices()) {
                AddError(L"Quick scan: service enumeration failed");
            }
        }
        if (IsModuleEnabled(ModuleType::Network) && network_enum_) {
            UpdateProgress(50.0f, L"Network");
            // EnumerateListeningPorts now loads the TCP/UDP tables itself;
            // before, the quick scan never called EnumerateConnections and so
            // always reported zero listening ports.
            if (!network_enum_->EnumerateListeningPorts()) {
                AddError(L"Quick scan: listening port enumeration failed");
            }
            if (!network_enum_->AnalyzeFirewall()) {
                AddError(L"Quick scan: firewall analysis failed");
            }
        }
        if (IsModuleEnabled(ModuleType::Registry) && registry_analyzer_) {
            UpdateProgress(75.0f, L"Registry");
            if (!registry_analyzer_->AnalyzeStartupKeys()) {
                AddError(L"Quick scan: registry startup analysis failed");
            }
        }
        if (IsModuleEnabled(ModuleType::PrivEsc) && privesc_analyzer_) {
            UpdateProgress(90.0f, L"Privilege Escalation");
            if (!privesc_analyzer_->RunAllChecks()) {
                AddError(L"Quick scan: privilege-escalation checks did not fully complete");
            }
        }
        if (IsModuleEnabled(ModuleType::Processes) || IsModuleEnabled(ModuleType::Memory)) {
            SYSRECON_LOG_INFO(L"Quick scan skips the Processes and Memory modules");
        }
        UpdateProgress(100.0f, L"Complete");
    } catch (const std::exception& e) {
        AddError(L"Quick scan aborted with exception: " + Core::Utils::Utf8ToWide(e.what()));
        is_scanning_.store(false);
        return false;
    }

    is_scanning_.store(false);
    return true;
}

bool ScanEngine::RunModuleScan(ModuleType module) {
    // Each step runs independently and every failure is recorded, so one
    // failing check never silently skips the rest.
    auto run_all = [this](const String& module_label,
                          std::initializer_list<std::pair<const wchar_t*, std::function<bool()>>> steps) {
        bool all_ok = true;
        for (const auto& step : steps) {
            bool ok = false;
            try {
                ok = step.second();
            } catch (const std::exception& e) {
                AddError(module_label + L": " + step.first + L" threw: " + Utils::Utf8ToWide(e.what()));
                all_ok = false;
                continue;
            }
            if (!ok) {
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
                    {L"password policy",   [&] { return user_enum_->AnalyzePasswordPolicy(); }},
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
                    {L"permission analysis",  [&] { return registry_analyzer_->AnalyzePermissions(); }},
                    {L"custom key scan",      [&] { return registry_analyzer_->ScanCustomKeys(); }},
                });
            }
            break;

        case ModuleType::Memory:
            if (memory_analyzer_) {
                // Unchanged in this revision (see CHANGELOG "Known limitations":
                // the malware scan still has no populated process inventory).
                return run_all(L"Memory", {
                    {L"malware scan",        [&] { return memory_analyzer_->ScanForMalware(); }},
                    {L"injection detection", [&] { return memory_analyzer_->DetectInjection(); }},
                });
            }
            break;

        case ModuleType::PrivEsc:
            if (privesc_analyzer_) {
                return run_all(L"Privilege Escalation", {
                    {L"privilege-escalation checks", [&] { return privesc_analyzer_->RunAllChecks(); }},
                });
            }
            break;

        case ModuleType::Domain:
            if (domain_recon_) {
                return run_all(L"Domain", {
                    {L"domain reconnaissance", [&] { return domain_recon_->RunAllChecks(); }},
                });
            }
            break;

        default:
            return false;
    }

    return false;
}

void ScanEngine::DestroyModules() {
    user_enum_.reset();
    service_enum_.reset();
    process_enum_.reset();
    network_enum_.reset();
    registry_analyzer_.reset();
    memory_analyzer_.reset();
    privesc_analyzer_.reset();
    domain_recon_.reset();
    report_generator_.reset();
}

void ScanEngine::Cleanup() {
    SYSRECON_LOG_INFO(L"Cleaning up scan engine resources");
    DestroyModules();
    ClearResults();
}

void ScanEngine::ClearResults() {
    std::lock_guard<std::mutex> lock(results_mutex_);
    scan_results_.clear();
}

void ScanEngine::CollectResults() {
    scan_results_.clear();

    auto collect = [this](const ScanResults& module_results, const wchar_t* label) {
        scan_results_.insert(scan_results_.end(), module_results.begin(), module_results.end());
        SYSRECON_LOG_DEBUG(L"Collected " + std::to_wstring(module_results.size()) + L" " + label + L" results");
    };
    if (user_enum_)         collect(user_enum_->GetScanResults(), L"account");
    if (service_enum_)      collect(service_enum_->GetScanResults(), L"service");
    if (process_enum_)      collect(process_enum_->GetScanResults(), L"process");
    if (network_enum_)      collect(network_enum_->GetScanResults(), L"network");
    if (registry_analyzer_) collect(registry_analyzer_->GetScanResults(), L"registry");
    if (memory_analyzer_)   collect(memory_analyzer_->GetScanResults(), L"memory");
    if (privesc_analyzer_)  collect(privesc_analyzer_->GetScanResults(), L"privilege-escalation");
    if (domain_recon_)      collect(domain_recon_->GetScanResults(), L"domain");

    // Drop anything below the configured minimum severity (CLI --min-severity).
    if (min_severity_ != SecurityLevel::Low) {
        const size_t before = scan_results_.size();
        scan_results_.erase(
            std::remove_if(scan_results_.begin(), scan_results_.end(),
                [this](const ScanResult& r) { return r.risk_level < min_severity_; }),
            scan_results_.end());
        if (before != scan_results_.size()) {
            SYSRECON_LOG_INFO(L"Filtered out " + std::to_wstring(before - scan_results_.size()) +
                              L" finding(s) below the minimum severity");
        }
    }

    // Highest risk first, so the top of every report is what matters most.
    std::stable_sort(scan_results_.begin(), scan_results_.end(),
                     [](const ScanResult& a, const ScanResult& b) { return a.risk_level > b.risk_level; });

    SYSRECON_LOG_INFO(L"Total scan results collected: " + std::to_wstring(scan_results_.size()));
}

bool ScanEngine::ExportResults(const String& format, const String& filename) {
    if (!report_generator_) {
        SYSRECON_LOG_ERROR(L"Report generator not initialized");
        return false;
    }

    SYSRECON_LOG_INFO(L"Exporting results to: " + filename);

    std::lock_guard<std::mutex> lock(results_mutex_);
    CollectResults();
    report_generator_->SetScanResults(scan_results_);

    Modules::SystemInfo sys_info;
    sys_info.computer_name = Core::Utils::GetComputerName();
    sys_info.os_version = Core::Utils::GetWindowsVersion();
    sys_info.architecture = Core::Utils::IsWow64Process() ? L"x86 (WOW64)" : L"x64";
    sys_info.scan_time = std::chrono::system_clock::now();
    sys_info.sysrecon_version = SYSRECON_VERSION;
    sys_info.elevated = is_elevated_;
    sys_info.stealth = stealth_mode_;
    sys_info.modules = selection_.Names();
    sys_info.config_path = config_loaded_ ? config_path_ : String(L"(built-in defaults)");
    report_generator_->SetSystemInfo(sys_info);

    {
        // Checks that did not complete belong in the report, not only on a
        // console that has scrolled away: a clean-looking report from a scan
        // that could not read half the system is misleading.
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        StringVector notes = error_messages_;
        if (!is_elevated_) {
            notes.insert(notes.begin(), L"Scan ran without Administrator privileges; many checks see only part of the system");
        }
        report_generator_->SetIncompleteChecks(notes);
    }

    if (format == L"json") {
        return report_generator_->GenerateJSON(filename);
    } else if (format == L"csv") {
        return report_generator_->GenerateCSV(filename);
    } else if (format == L"html") {
        return report_generator_->GenerateHTML(filename);
    } else if (format == L"sarif") {
        return report_generator_->GenerateSARIF(filename);
    } else if (format == L"navigator") {
        return report_generator_->GenerateAttackNavigatorLayer(filename);
    }
    SYSRECON_LOG_ERROR(L"Unsupported format: " + format);
    return false;
}

SecurityLevel ScanEngine::GetMaxSeverity() const {
    SecurityLevel max = SecurityLevel::Low;
    for (const auto& r : scan_results_) {
        if (r.risk_level > max) max = r.risk_level;
    }
    return max;
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

    // Construct exactly the selected set. Stale objects from a previous
    // interactive run would otherwise keep contributing to reports.
    DestroyModules();

    bool all_success = true;
    auto init = [&](auto& ptr, const wchar_t* label) {
        if (!ptr->Initialize()) {
            SYSRECON_LOG_ERROR(String(L"Failed to initialize ") + label + L" module");
            AddError(String(label) + L": module failed to initialize");
            all_success = false;
            ptr.reset();
        }
    };

    if (selection_.accounts)  { user_enum_ = std::make_unique<Modules::UserEnumerator>();          init(user_enum_, L"Accounts"); }
    if (selection_.services)  { service_enum_ = std::make_unique<Modules::ServiceEnumerator>();    init(service_enum_, L"Services"); }
    if (selection_.processes) { process_enum_ = std::make_unique<Modules::ProcessEnumerator>();    init(process_enum_, L"Processes"); }
    if (selection_.network)   { network_enum_ = std::make_unique<Modules::NetworkEnumerator>();    init(network_enum_, L"Network"); }
    if (selection_.registry)  { registry_analyzer_ = std::make_unique<Modules::RegistryAnalyzer>(); init(registry_analyzer_, L"Registry"); }
    if (selection_.memory)    { memory_analyzer_ = std::make_unique<Modules::MemoryAnalyzer>();    init(memory_analyzer_, L"Memory"); }
    if (selection_.privesc)   { privesc_analyzer_ = std::make_unique<Modules::PrivEscAnalyzer>(); init(privesc_analyzer_, L"Privilege Escalation"); }
    if (selection_.domain)    { domain_recon_ = std::make_unique<Modules::DomainReconAnalyzer>(); init(domain_recon_, L"Domain"); }

    report_generator_ = std::make_unique<Modules::ReportGenerator>();
    return all_success;
}

void ScanEngine::UpdateProgress(float progress, const String& module) {
    progress_.store(progress);
    current_module_ = module;
    SYSRECON_LOG_DEBUG(L"Progress: " + std::to_wstring(static_cast<int>(progress)) + L"% - " + module);
}

void ScanEngine::AddError(const String& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_messages_.push_back(error);
    SYSRECON_LOG_ERROR(error);
}

}
}
