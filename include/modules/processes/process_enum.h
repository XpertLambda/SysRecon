#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

struct ProcessInfo {
    DWORD process_id;
    DWORD parent_process_id;
    String process_name;
    String executable_path;
    String command_line;
    String current_directory;
    String owner;
    DWORD session_id;
    DWORD thread_count;
    DWORD handle_count;
    SIZE_T working_set_size;
    SIZE_T page_file_usage;
    SIZE_T virtual_size;
    std::chrono::system_clock::time_point creation_time;
    double cpu_usage;
    StringVector loaded_modules;
    StringVector network_connections;
    bool is_64bit;
    bool is_signed;
    String integrity_level;
    SecurityLevel risk_level;
};

struct ModuleInfo {
    String module_name;
    String module_path;
    DWORD_PTR base_address;
    DWORD module_size;
    String version;
    String company;
    bool is_signed;
    SecurityLevel risk_level;
};

struct ThreadInfo {
    DWORD thread_id;
    DWORD process_id;
    std::chrono::system_clock::time_point creation_time;
    DWORD start_address;
    String state;
    LONG priority;
};

class ProcessEnumerator {
public:
    ProcessEnumerator();
    ~ProcessEnumerator();
    
    // Main enumeration methods
    bool Initialize();
    bool EnumerateProcesses();
    bool AnalyzeMemory();
    bool CheckLoadedModules();
    bool DetectInjection();
    void Cleanup();
    
    // Results access
    const std::vector<ProcessInfo>& GetProcesses() const { return processes_; }
    const std::map<DWORD, std::vector<ModuleInfo>>& GetModules() const { return process_modules_; }
    const ScanResults& GetScanResults() const { return scan_results_; }
    
    // Configuration
    void SetAnalyzeMemory(bool enable) { analyze_memory_ = enable; }
    void SetCheckDlls(bool enable) { check_dlls_ = enable; }
    void SetDetectInjection(bool enable) { detect_injection_ = enable; }
    
    // Analysis methods
    SecurityLevel AssessProcessRisk(const ProcessInfo& process);
    StringVector FindSuspiciousProcesses();
    StringVector FindUnsignedProcesses();
    StringVector FindHollowedProcesses();
    StringVector FindInjectedProcesses();
    StringVector FindProcessesWithSuspiciousModules();
    
    // Process analysis
    bool AnalyzeProcess(DWORD process_id);
    bool GetProcessModules(DWORD process_id, std::vector<ModuleInfo>& modules);
    bool GetProcessThreads(DWORD process_id, std::vector<ThreadInfo>& threads);
    bool CheckProcessIntegrity(DWORD process_id);
    
    // Memory analysis
    bool ScanProcessMemory(DWORD process_id);
    bool DetectCodeInjection(DWORD process_id);
    bool DetectHollowing(DWORD process_id);
    ByteVector DumpProcessMemory(DWORD process_id, SIZE_T max_size = 0);
    
private:
    // Internal enumeration methods
    bool EnumerateAllProcesses();
    bool GetProcessDetails(DWORD process_id, ProcessInfo& process);
    bool GetProcessCommandLine(DWORD process_id, String& command_line);
    bool GetProcessOwner(DWORD process_id, String& owner);
    bool GetProcessModuleList(DWORD process_id, StringVector& modules);
    
    // Analysis helpers
    void AnalyzeProcessInfo(const ProcessInfo& process);
    void CheckProcessPath(const ProcessInfo& process);
    void CheckProcessSignature(const ProcessInfo& process);
    void CheckProcessLocation(const ProcessInfo& process);
    void CheckParentProcess(const ProcessInfo& process);
    
    // Memory analysis helpers
    bool ScanMemoryRegions(HANDLE process_handle);
    bool CheckMemoryRegion(HANDLE process_handle, MEMORY_BASIC_INFORMATION& mbi);
    bool DetectShellcode(const ByteVector& memory_data);
    bool DetectPeInjection(const ByteVector& memory_data);
    
    // Utility methods
    String GetProcessIntegrityLevel(HANDLE process_handle);
    bool IsProcess64Bit(HANDLE process_handle);
    bool IsProcessSigned(const String& executable_path);
    String GetProcessDescription(const String& executable_path);
    double CalculateCpuUsage(DWORD process_id);
    
    // Configuration
    bool analyze_memory_;
    bool check_dlls_;
    bool detect_injection_;
    
    // Data storage
    std::vector<ProcessInfo> processes_;
    std::map<DWORD, std::vector<ModuleInfo>> process_modules_;
    std::map<DWORD, std::vector<ThreadInfo>> process_threads_;
    ScanResults scan_results_;
    
    // State
    bool initialized_;
    StringVector error_messages_;
    
    // Performance monitoring
    std::map<DWORD, ULARGE_INTEGER> previous_cpu_times_;
    ULARGE_INTEGER previous_system_time_;
};

} // namespace Modules
} // namespace SysRecon
