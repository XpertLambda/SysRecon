#include "../../include/modules/processes/process_enum.h"
#include "../../include/core/utils.h"
#include "../../include/core/whitelist.h"

namespace SysRecon {
namespace Modules {

ProcessEnumerator::ProcessEnumerator() 
    : analyze_memory_(false)
    , check_dlls_(true)
    , detect_injection_(true)
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
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        SYSRECON_LOG_ERROR(L"Failed to create process snapshot");
        return false;
    }
    
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &entry)) {
        do {
            ProcessInfo proc;
            proc.process_id = entry.th32ProcessID;
            proc.process_name = String(entry.szExeFile);
            proc.parent_process_id = entry.th32ParentProcessID;
            proc.thread_count = entry.cntThreads;
            proc.risk_level = SecurityLevel::Low;
            
            // Get additional process information
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (hProcess) {
                // Get process path
                wchar_t path[MAX_PATH];
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize)) {
                    proc.executable_path = String(path);
                }
                
                // Get process memory info
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    proc.working_set_size = pmc.WorkingSetSize;
                    proc.page_file_usage = pmc.PagefileUsage;
                }
                
                CloseHandle(hProcess);
            }
            
            processes_.push_back(proc);
            AnalyzeProcessInfo(proc);

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

bool ProcessEnumerator::AnalyzeMemory() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing process memory...");
    return true;
}

bool ProcessEnumerator::CheckLoadedModules() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Checking loaded modules...");
    
#ifdef _WIN32
    for (const auto& proc : processes_) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc.process_id);
        if (snapshot == INVALID_HANDLE_VALUE) {
            continue;
        }
        
        MODULEENTRY32W module;
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
                modules.push_back(modInfo);
            } while (Module32NextW(snapshot, &module));
        }
        
        process_modules_[proc.process_id] = modules;
        CloseHandle(snapshot);
    }
    
    return true;
#else
    return true;
#endif
}

bool ProcessEnumerator::DetectInjection() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Detecting code injection...");
    return true;
}

void ProcessEnumerator::AnalyzeProcessInfo(const ProcessInfo& process) {
    if (process.executable_path.empty()) {
        return; // Protected/system process we could not open; nothing to assess.
    }

    String lower = Core::Utils::ToLower(process.executable_path);

    // Flag binaries running from user-writable / temporary locations, which is a
    // common staging pattern for malware and attacker tooling on an engagement.
    struct Marker { const wchar_t* needle; const wchar_t* label; };
    const Marker markers[] = {
        { L"\\temp\\",           L"Temp directory" },
        { L"\\appdata\\local\\temp\\", L"AppData Local Temp" },
        { L"\\appdata\\",        L"AppData" },
        { L"\\downloads\\",      L"Downloads folder" },
        { L"\\public\\",         L"Public user folder" },
        { L"\\programdata\\",    L"ProgramData" },
        { L"\\$recycle.bin\\",   L"Recycle Bin" },
    };

    const wchar_t* matched = nullptr;
    for (const auto& m : markers) {
        if (lower.find(m.needle) != String::npos) { matched = m.label; break; }
    }
    if (!matched) return;

#ifdef _WIN32
    // Confirm the binary itself is writable by a non-admin for higher confidence.
    StringVector who;
    bool writable = Core::Utils::IsWritableByNonAdmin(process.executable_path, &who);
#else
    bool writable = false;
    StringVector who;
#endif

    ScanResult result;
    result.module_name = L"Processes";
    result.item_name = process.process_name;
    result.description = L"Process is running from a user-writable / transient location (" +
                         String(matched) + L"), which is uncommon for legitimate "
                         L"system software and warrants review.";
    result.risk_level = writable ? SecurityLevel::High : SecurityLevel::Medium;
    result.details[L"PID"] = std::to_wstring(process.process_id);
    result.details[L"Path"] = process.executable_path;
    result.details[L"Location"] = matched;
    if (writable) {
        result.details[L"Writable By"] = Core::Utils::Join(who, L", ");
    }
    result.remediation = L"Verify the process is expected. Confirm the publisher/"
        L"digital signature, correlate with change tickets, and remove or quarantine "
        L"the binary if unrecognised. Restrict write access to the hosting directory.";
    result.reference = L"MITRE ATT&CK T1036 (Masquerading) / T1074 (Data Staged)";
    result.timestamp = std::chrono::system_clock::now();
    scan_results_.push_back(result);
}

void ProcessEnumerator::Cleanup() {
    processes_.clear();
    process_modules_.clear();
    scan_results_.clear();
    initialized_ = false;
}

}
}
