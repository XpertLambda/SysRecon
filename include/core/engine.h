#pragma once

#include "../sysrecon.h"
#include "scan_plan.h"
#include "../modules/accounts/user_enum.h"
#include "../modules/services/service_enum.h"
#include "../modules/processes/process_enum.h"
#include "../modules/network/network_enum.h"
#include "../modules/registry/registry_analyzer.h"
#include "../modules/memory/memory_analyzer.h"
#include "../modules/privesc/privesc_analyzer.h"
#include "../modules/domain/domain_recon.h"
#include "../modules/reporting/report_generator.h"

namespace SysRecon {
namespace Core {

// Lifecycle of one run (main.cpp follows exactly this order):
//
//   Reset()                       -- forget everything from a previous run
//   LoadConfig(path)              -- optional
//   SetModuleSelection(...)       -- the *resolved* selection (scan_plan.h)
//   SetOutputDirectory / SetStealthMode
//   Initialize()                  -- constructs exactly the selected modules
//   ApplyConfigToModules()
//   RunFullScan() / RunQuickScan()
//   ExportResults(...)
//   Cleanup()
//
// The selection must be final before Initialize(): modules that are not
// selected are not constructed, and a module enabled afterwards would have no
// object to run. That ordering mistake is what made `--memory` a silent no-op.
class ScanEngine {
public:
    static ScanEngine& Instance();

    // Clears results, errors, selection, config state and modules, so
    // consecutive interactive scans cannot leak into one another (errors from
    // the first scan used to be reported again by every later one).
    void Reset();

    // Loads config.json. Returns false (keeping the built-in defaults) if the
    // file could not be loaded. Relative output_directory values are resolved
    // against the config file's directory.
    bool LoadConfig(const String& config_file);
    bool IsConfigLoaded() const { return config_loaded_; }
    const String& GetConfigPath() const { return config_path_; }

    void SetModuleSelection(const ModuleSelection& selection);
    const ModuleSelection& GetModuleSelection() const { return selection_; }
    void EnableModule(ModuleType module);
    void DisableModule(ModuleType module);
    bool IsModuleEnabled(ModuleType module) const;

    // Pushes per-module options from the loaded config into the module objects.
    // Call after Initialize(), once the modules exist.
    void ApplyConfigToModules();

    void SetOutputDirectory(const String& output_dir);

    // The effective output directory after config file and CLI flags have been
    // resolved. Callers must use this rather than re-deriving a path, or the
    // two disagree and reports land somewhere the user did not ask for.
    const String& GetOutputDirectory() const { return output_directory_; }

    // Low-footprint mode: no console logging, no per-process module
    // snapshots, no memory module. See README "Stealth Mode".
    void SetStealthMode(bool stealth);
    bool IsStealthMode() const { return stealth_mode_; }

    bool Initialize();
    bool RunFullScan();
    bool RunQuickScan();
    bool RunModuleScan(ModuleType module);
    void Cleanup();

    const ScanResults& GetResults() const { return scan_results_; }
    void ClearResults();
    bool ExportResults(const String& format, const String& filename);

    // Findings below this severity are dropped from the collected results and
    // from every report (CLI --min-severity). Default Low keeps everything.
    void SetMinSeverity(SecurityLevel level) { min_severity_ = level; }
    // Highest severity among the collected results, or Low when there are none.
    // Used by the CLI to derive a severity-based process exit code.
    SecurityLevel GetMaxSeverity() const;

    bool IsScanning() const { return is_scanning_; }
    float GetProgress() const { return progress_; }
    String GetCurrentModule() const { return current_module_; }

    bool HasErrors() const { return !error_messages_.empty(); }
    const StringVector& GetErrors() const { return error_messages_; }
    bool IsElevated() const { return is_elevated_; }

private:
    ScanEngine() = default;
    ~ScanEngine() = default;
    ScanEngine(const ScanEngine&) = delete;
    ScanEngine& operator=(const ScanEngine&) = delete;

    bool CheckPrivileges();
    bool InitializeModules();
    void DestroyModules();
    void CollectResults();
    void UpdateProgress(float progress, const String& module);
    void AddError(const String& error);

    std::unique_ptr<Modules::UserEnumerator> user_enum_;
    std::unique_ptr<Modules::ServiceEnumerator> service_enum_;
    std::unique_ptr<Modules::ProcessEnumerator> process_enum_;
    std::unique_ptr<Modules::NetworkEnumerator> network_enum_;
    std::unique_ptr<Modules::RegistryAnalyzer> registry_analyzer_;
    std::unique_ptr<Modules::MemoryAnalyzer> memory_analyzer_;
    std::unique_ptr<Modules::PrivEscAnalyzer> privesc_analyzer_;
    std::unique_ptr<Modules::DomainReconAnalyzer> domain_recon_;
    std::unique_ptr<Modules::ReportGenerator> report_generator_;

    String output_directory_;
    String config_path_;
    // True once a config file has been successfully loaded. Guards settings
    // whose in-code default would otherwise change behaviour with no config.
    bool config_loaded_ = false;
    bool stealth_mode_ = false;
    bool is_elevated_ = false;
    SecurityLevel min_severity_ = SecurityLevel::Low;
    ModuleSelection selection_ = ModuleSelection::FromConfig(ScanConfig{});

    std::atomic<bool> is_scanning_{false};
    std::atomic<float> progress_{0.0f};
    String current_module_;
    ScanResults scan_results_;
    StringVector error_messages_;

    mutable std::mutex results_mutex_;
    mutable std::mutex error_mutex_;
};

}
}
