#include "../../include/modules/processes/process_enum.h"
#include "../../include/core/whitelist.h"
#include "../../include/core/text_utils.h"

namespace SysRecon {
namespace Modules {

ProcessEnumerator::ProcessEnumerator()
    : check_dlls_(true)
    , initialized_(false) {
}

ProcessEnumerator::~ProcessEnumerator() {
    Cleanup();
}

bool ProcessEnumerator::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Process Enumeration module");
    initialized_ = true;
    return true;
}

bool ProcessEnumerator::EnumerateProcesses() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating running processes...");
    
#ifdef _WIN32
    // Re-enumeration must not append to prior results.
    processes_.clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        SYSRECON_LOG_ERROR(L"Failed to create process snapshot: " +
                           Core::Utils::GetLastErrorString());
        return false;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            ProcessInfo proc;
            proc.process_id = entry.th32ProcessID;
            proc.process_name = String(entry.szExeFile);
            proc.parent_process_id = entry.th32ParentProcessID;
            proc.thread_count = entry.cntThreads;
            proc.risk_level = SecurityLevel::Low;

            // PROCESS_QUERY_LIMITED_INFORMATION is all the calls below need and
            // it succeeds against protected processes, where the old
            // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ request failed and
            // silently left the image path empty.
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                          entry.th32ProcessID);
            if (hProcess) {
                wchar_t path[MAX_PATH];
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize)) {
                    proc.executable_path.assign(path, pathSize);
                }

                PROCESS_MEMORY_COUNTERS pmc = {};
                pmc.cb = sizeof(pmc);
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    proc.working_set_size = pmc.WorkingSetSize;
                    proc.page_file_usage = pmc.PagefileUsage;
                }

                CloseHandle(hProcess);
            }

            AnalyzeProcess(proc);
            processes_.push_back(proc);

        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    SYSRECON_LOG_INFO(L"Enumerated " + std::to_wstring(processes_.size()) + L" processes");
    return true;
#else
    SYSRECON_LOG_INFO(L"Cross-compilation stub - feature available only on Windows");
    return true;
#endif
}

void ProcessEnumerator::AnalyzeProcess(ProcessInfo& proc) {
#ifdef _WIN32
    auto& whitelist = Core::SystemWhitelist::Instance();

    // A process we could not open tells us nothing; do not invent a finding.
    if (proc.executable_path.empty()) {
        return;
    }

    const bool system_name = whitelist.IsSystemProcessName(proc.process_name);
    const bool system_path = whitelist.IsSystemPath(proc.executable_path);

    // Masquerading (MITRE T1036.005): a process carrying a well-known Windows
    // name that is NOT running from a Windows directory. This is the reason the
    // whitelist is path-aware -- name-only matching would have exempted it.
    if (system_name && !system_path) {
        ScanResult result;
        result.module_name = L"Processes";
        result.item_name = proc.process_name;
        result.description = L"Process uses a Windows system name but runs from a non-system path";
        result.details[L"PID"] = std::to_wstring(proc.process_id);
        result.details[L"Image Path"] = proc.executable_path;
        result.details[L"Parent PID"] = std::to_wstring(proc.parent_process_id);
        result.details[L"Technique"] = L"T1036.005 Masquerading: Match Legitimate Name or Location";
        result.risk_level = SecurityLevel::High;
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
        proc.risk_level = SecurityLevel::High;
        return;
    }

    // Execution from a location any user can write to. Legitimate installers
    // and updaters do this, so it is Medium on its own -- a lead, not a verdict.
    if (!system_path && Core::Text::IsUserWritableExecutionPath(proc.executable_path)) {
        ScanResult result;
        result.module_name = L"Processes";
        result.item_name = proc.process_name;
        result.description = L"Process runs from a user-writable location";
        result.details[L"PID"] = std::to_wstring(proc.process_id);
        result.details[L"Image Path"] = proc.executable_path;
        result.details[L"Parent PID"] = std::to_wstring(proc.parent_process_id);
        result.risk_level = SecurityLevel::Medium;
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
        proc.risk_level = SecurityLevel::Medium;
    }
#else
    (void)proc;
#endif
}

bool ProcessEnumerator::CheckLoadedModules() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Checking loaded modules...");
    
#ifdef _WIN32
    process_modules_.clear();
    auto& whitelist = Core::SystemWhitelist::Instance();

    for (const auto& proc : processes_) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc.process_id);
        if (snapshot == INVALID_HANDLE_VALUE) {
            continue;
        }

        MODULEENTRY32W module = {};
        module.dwSize = sizeof(MODULEENTRY32W);

        std::vector<ModuleInfo> modules;
        if (Module32FirstW(snapshot, &module)) {
            do {
                ModuleInfo modInfo;
                modInfo.module_name = String(module.szModule);
                modInfo.module_path = String(module.szExePath);
                modInfo.base_address = (DWORD_PTR)module.modBaseAddr;
                modInfo.module_size = module.modBaseSize;
                modInfo.is_signed = false;
                modInfo.risk_level = SecurityLevel::Low;

                // DLL sideloading (T1574.002): a module carrying a core Windows
                // DLL name that is loaded from outside a system directory. The
                // real ntdll.dll only ever lives under %SystemRoot%.
                if (whitelist.IsSystemDllName(modInfo.module_name) &&
                    !modInfo.module_path.empty() &&
                    !whitelist.IsSystemPath(modInfo.module_path)) {
                    modInfo.risk_level = SecurityLevel::High;

                    ScanResult result;
                    result.module_name = L"Processes";
                    result.item_name = modInfo.module_name;
                    result.description = L"System DLL name loaded from a non-system path";
                    result.details[L"Process"] = proc.process_name;
                    result.details[L"PID"] = std::to_wstring(proc.process_id);
                    result.details[L"Module Path"] = modInfo.module_path;
                    result.details[L"Technique"] = L"T1574.002 DLL Side-Loading";
                    result.risk_level = SecurityLevel::High;
                    result.timestamp = std::chrono::system_clock::now();
                    scan_results_.push_back(result);
                }

                modules.push_back(modInfo);
            } while (Module32NextW(snapshot, &module));
        }

        process_modules_[proc.process_id] = modules;
        CloseHandle(snapshot);
    }

    SYSRECON_LOG_INFO(L"Checked loaded modules for " +
                      std::to_wstring(process_modules_.size()) + L" processes");
    return true;
#else
    return true;
#endif
}

void ProcessEnumerator::Cleanup() {
    processes_.clear();
    process_modules_.clear();
    scan_results_.clear();
    initialized_ = false;
}

}
}
