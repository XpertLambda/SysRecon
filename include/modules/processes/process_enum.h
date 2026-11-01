#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

// Members are default-initialised: these structs are filled in field by field
// from Win32 calls that can fail, and previously shipped garbage (e.g. an
// unset risk_level) into public results when they did.
struct ProcessInfo {
    DWORD process_id = 0;
    DWORD parent_process_id = 0;
    String process_name;
    String executable_path;
    DWORD thread_count = 0;
    SIZE_T working_set_size = 0;
    SIZE_T page_file_usage = 0;
    SecurityLevel risk_level = SecurityLevel::Low;
};

struct ModuleInfo {
    String module_name;
    String module_path;
    DWORD_PTR base_address = 0;
    DWORD module_size = 0;
    bool is_signed = false;
    SecurityLevel risk_level = SecurityLevel::Low;
};

class ProcessEnumerator {
public:
    ProcessEnumerator();
    ~ProcessEnumerator();
    
    // Main enumeration methods
    bool Initialize();
    bool EnumerateProcesses();
    bool CheckLoadedModules();
    void Cleanup();

    // Results access
    const std::vector<ProcessInfo>& GetProcesses() const { return processes_; }
    const std::map<DWORD, std::vector<ModuleInfo>>& GetModules() const { return process_modules_; }
    const ScanResults& GetScanResults() const { return scan_results_; }

    // Configuration
    void SetCheckDlls(bool enable) { check_dlls_ = enable; }

private:
    // Emits findings for a single process: masquerading (a Windows system name
    // running from a non-system path) and execution from user-writable
    // locations. Updates proc.risk_level.
    void AnalyzeProcess(ProcessInfo& proc);

    bool check_dlls_;

    std::vector<ProcessInfo> processes_;
    std::map<DWORD, std::vector<ModuleInfo>> process_modules_;
    ScanResults scan_results_;

    bool initialized_;
};

} // namespace Modules
} // namespace SysRecon
