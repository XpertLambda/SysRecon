#pragma once

#include "../sysrecon.h"
#include "../modules/accounts/user_enum.h"
#include "../modules/services/service_enum.h"
#include "../modules/processes/process_enum.h"
#include "../modules/network/network_enum.h"
#include "../modules/registry/registry_analyzer.h"
#include "../modules/memory/memory_analyzer.h"
#include "../modules/reporting/report_generator.h"

namespace SysRecon {
namespace Core {

class ScanEngine {
public:
    static ScanEngine& Instance();
    
    // Configuration
    void LoadConfig(const String& config_file);
    void SetOutputDirectory(const String& output_dir);
    void SetVerboseMode(bool verbose);
    void SetStealthMode(bool stealth);
    
    // Module management
    void EnableModule(ModuleType module);
    void DisableModule(ModuleType module);
    bool IsModuleEnabled(ModuleType module) const;
    
    // Scanning operations
    bool Initialize();
    bool RunFullScan();
    bool RunQuickScan();
    bool RunModuleScan(ModuleType module);
    void Cleanup();
    
    // Results management
    const ScanResults& GetResults() const { return scan_results_; }
    void ClearResults();
    bool ExportResults(const String& format, const String& filename);
    
    // Status and progress
    bool IsScanning() const { return is_scanning_; }
    float GetProgress() const { return progress_; }
    String GetCurrentModule() const { return current_module_; }
    
    // Error handling
    bool HasErrors() const { return !error_messages_.empty(); }
    const StringVector& GetErrors() const { return error_messages_; }
    
private:
    ScanEngine() = default;
    ~ScanEngine() = default;
    ScanEngine(const ScanEngine&) = delete;
    ScanEngine& operator=(const ScanEngine&) = delete;
    
    // Internal methods
    bool CheckPrivileges();
    bool InitializeModules();
    void UpdateProgress(float progress, const String& module);
    void AddError(const String& error);
    
    // Module instances
    std::unique_ptr<Modules::UserEnumerator> user_enum_;
    std::unique_ptr<Modules::ServiceEnumerator> service_enum_;
    std::unique_ptr<Modules::ProcessEnumerator> process_enum_;
    std::unique_ptr<Modules::NetworkEnumerator> network_enum_;
    std::unique_ptr<Modules::RegistryAnalyzer> registry_analyzer_;
    std::unique_ptr<Modules::MemoryAnalyzer> memory_analyzer_;
    std::unique_ptr<Modules::ReportGenerator> report_generator_;
    
    // Configuration
    String output_directory_;
    bool verbose_mode_ = false;
    bool stealth_mode_ = false;
    std::map<ModuleType, bool> enabled_modules_;
    
    // State
    std::atomic<bool> is_scanning_{false};
    std::atomic<float> progress_{0.0f};
    String current_module_;
    ScanResults scan_results_;
    StringVector error_messages_;
    
    // Synchronization
    mutable std::mutex results_mutex_;
    mutable std::mutex error_mutex_;
};

} // namespace Core
} // namespace SysRecon
