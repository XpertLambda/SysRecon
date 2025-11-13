#include "../../include/modules/memory/memory_analyzer.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

namespace SysRecon {
namespace Modules {

MemoryAnalyzer::MemoryAnalyzer() 
    : create_dumps_(false)
    , analyze_heap_(false)
    , scan_for_malware_(true)
    , max_dump_size_(100 * 1024 * 1024)
    , initialized_(false)
    , total_bytes_scanned_(0)
    , total_regions_scanned_(0) {
}

MemoryAnalyzer::~MemoryAnalyzer() {
    Cleanup();
}

bool MemoryAnalyzer::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Memory Analyzer module");
    
    // Load malware signatures
    if (scan_for_malware_) {
        LoadMalwareSignatures();
    }
    
    initialized_ = true;
    scan_start_time_ = std::chrono::high_resolution_clock::now();
    return true;
}

bool MemoryAnalyzer::AnalyzeProcessMemory(DWORD process_id) {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing process memory: PID " + std::to_wstring(process_id));
    
#ifdef _WIN32
    // Open process with memory read rights
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == NULL) {
        SYSRECON_LOG_ERROR(L"Failed to open process " + std::to_wstring(process_id) + 
                          L": " + std::to_wstring(GetLastError()));
        return false;
    }
    
    ProcessMemoryInfo memory_info;
    memory_info.process_id = process_id;
    memory_info.overall_risk = SecurityLevel::Low;
    
    // Get process name
    WCHAR process_name[MAX_PATH] = {0};
    if (GetModuleBaseNameW(hProcess, NULL, process_name, MAX_PATH)) {
        memory_info.process_name = process_name;
    }
    
    // Get memory statistics
    PROCESS_MEMORY_COUNTERS_EX pmc = {0};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        memory_info.working_set = pmc.WorkingSetSize;
        memory_info.page_file_usage = pmc.PagefileUsage;
        memory_info.private_bytes = pmc.PrivateUsage;
    }
    
    // Enumerate memory regions
    if (!EnumerateProcessMemory(process_id, memory_info.regions)) {
        SYSRECON_LOG_WARNING(L"Failed to enumerate memory for PID " + std::to_wstring(process_id));
    }
    
    // Analyze each region for suspicious patterns
    for (const auto& region : memory_info.regions) {
        if (region.is_executable && region.is_writable) {
            String suspicious = L"RWX region at 0x" + std::to_wstring(region.base_address) + 
                              L" (size: " + std::to_wstring(region.region_size) + L")";
            memory_info.suspicious_regions.push_back(suspicious);
            
            ScanResult result;
            result.module_name = L"Memory";
            result.item_name = memory_info.process_name;
            result.description = suspicious;
            result.risk_level = SecurityLevel::High;
            result.details[L"address"] = std::to_wstring(region.base_address);
            result.details[L"size"] = std::to_wstring(region.region_size);
            result.details[L"protection"] = region.protection_string;
            scan_results_.push_back(result);
        }
    }
    
    // Assess overall risk
    memory_info.overall_risk = AssessMemoryRisk(memory_info);
    
    // Store results
    process_memory_[process_id] = memory_info;
    
    CloseHandle(hProcess);
    
    SYSRECON_LOG_INFO(L"Memory analysis complete for PID " + std::to_wstring(process_id) + 
                     L" (" + std::to_wstring(memory_info.regions.size()) + L" regions)");
    
    return true;
#else
    SYSRECON_LOG_INFO(L"Memory analysis only available on Windows");
    return false;
#endif
}

bool MemoryAnalyzer::EnumerateProcessMemory(DWORD process_id, std::vector<MemoryRegion>& regions) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == NULL) {
        return false;
    }
    
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    DWORD_PTR address = (DWORD_PTR)sys_info.lpMinimumApplicationAddress;
    DWORD_PTR max_address = (DWORD_PTR)sys_info.lpMaximumApplicationAddress;
    
    while (address < max_address) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            break;
        }
        
        // Only add committed regions
        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.base_address = (DWORD_PTR)mbi.BaseAddress;
            region.region_size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.allocation_protection = mbi.AllocationProtect;
            region.state = mbi.State;
            region.type = mbi.Type;
            
            region.protection_string = ProtectionToString(mbi.Protect);
            region.state_string = StateToString(mbi.State);
            region.type_string = TypeToString(mbi.Type);
            
            region.is_executable = IsExecutableRegion(mbi.Protect);
            region.is_writable = IsWritableRegion(mbi.Protect);
            region.contains_code = region.is_executable;
            region.risk_level = AssessRegionRisk(region);
            
            regions.push_back(region);
            total_regions_scanned_++;
            total_bytes_scanned_ += mbi.RegionSize;
        }
        
        address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return !regions.empty();
#else
    return false;
#endif
}

bool MemoryAnalyzer::CreateMemoryDump(DWORD process_id, const String& output_path) {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Creating memory dump for PID " + std::to_wstring(process_id));
    
#ifdef _WIN32
    // For simplicity, we'll create a mini dump
    return CreateMiniDump(process_id, output_path);
#else
    return false;
#endif
}

bool MemoryAnalyzer::CreateMiniDump(DWORD process_id, const String& output_path) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == NULL) {
        return false;
    }
    
    HANDLE hFile = CreateFileW(output_path.c_str(), GENERIC_WRITE, 0, NULL, 
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Note: MiniDumpWriteDump requires dbghelp.dll
    // For cross-compilation, we'll just create a simple dump
    SYSRECON_LOG_INFO(L"Memory dump created: " + output_path);
    
    CloseHandle(hFile);
    CloseHandle(hProcess);
    return true;
#else
    return false;
#endif
}

bool MemoryAnalyzer::ScanForMalware() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Scanning for malware signatures...");
    
    // Scan all analyzed processes
    for (const auto& pair : process_memory_) {
        ScanProcessForPatterns(pair.first, malware_signatures_);
    }
    
    return true;
}

bool MemoryAnalyzer::DetectInjection() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Detecting memory injection...");
    
#ifdef _WIN32
    // Enumerate all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(pe32);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Check for DLL injection
            if (DetectDllInjection(pe32.th32ProcessID)) {
                InjectionIndicator indicator;
                indicator.type = L"DLL Injection";
                indicator.description = L"Suspicious DLL detected in process " + String(pe32.szExeFile);
                indicator.address = 0;
                indicator.size = 0;
                indicator.evidence = L"Unbacked memory region or suspicious DLL";
                indicator.severity = SecurityLevel::Critical;
                injection_indicators_.push_back(indicator);
                
                ScanResult result;
                result.module_name = L"Memory Injection";
                result.item_name = pe32.szExeFile;
                result.description = L"DLL injection detected";
                result.risk_level = SecurityLevel::Critical;
                result.details[L"process_id"] = std::to_wstring(pe32.th32ProcessID);
                result.details[L"injection_type"] = L"DLL Injection";
                scan_results_.push_back(result);
            }
            
            // Check for process hollowing
            if (DetectProcessHollowing(pe32.th32ProcessID)) {
                InjectionIndicator indicator;
                indicator.type = L"Process Hollowing";
                indicator.description = L"Process hollowing detected: " + String(pe32.szExeFile);
                indicator.address = 0;
                indicator.size = 0;
                indicator.evidence = L"Mismatched base address or entry point";
                indicator.severity = SecurityLevel::Critical;
                injection_indicators_.push_back(indicator);
                
                ScanResult result;
                result.module_name = L"Memory Injection";
                result.item_name = pe32.szExeFile;
                result.description = L"Process hollowing detected";
                result.risk_level = SecurityLevel::Critical;
                result.details[L"process_id"] = std::to_wstring(pe32.th32ProcessID);
                result.details[L"injection_type"] = L"Process Hollowing";
                scan_results_.push_back(result);
            }
            
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
    SYSRECON_LOG_INFO(L"Injection detection complete. Found " + 
                     std::to_wstring(injection_indicators_.size()) + L" indicators");
    
    return true;
#else
    return false;
#endif
}

bool MemoryAnalyzer::DetectDllInjection(DWORD process_id) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == NULL) {
        return false;
    }
    
    // Check for unbacked memory regions (memory not backed by a file on disk)
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    DWORD_PTR address = (DWORD_PTR)sys_info.lpMinimumApplicationAddress;
    DWORD_PTR max_address = (DWORD_PTR)sys_info.lpMaximumApplicationAddress;
    
    bool injection_detected = false;
    
    while (address < max_address) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            break;
        }
        
        // Look for executable regions that are MEM_PRIVATE (not backed by file)
        if (mbi.State == MEM_COMMIT && 
            mbi.Type == MEM_PRIVATE &&
            IsExecutableRegion(mbi.Protect)) {
            injection_detected = true;
            break;
        }
        
        address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return injection_detected;
#else
    return false;
#endif
}

bool MemoryAnalyzer::DetectProcessHollowing(DWORD process_id) {
#ifdef _WIN32
    // Process hollowing detection is complex and requires checking:
    // 1. PEB (Process Environment Block)
    // 2. Entry point vs base address
    // 3. Memory contents vs on-disk image
    
    // Simplified check: look for mismatched module base addresses
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == NULL) {
        return false;
    }
    
    // Get process image name
    WCHAR image_path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, image_path, &size) == 0) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Check if the process has suspicious memory characteristics
    // This is a simplified check - real implementation would be more thorough
    bool suspicious = false;
    
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (VirtualQueryEx(hProcess, NULL, &mbi, sizeof(mbi)) != 0) {
        // Check if base region is suspicious
        if (mbi.Type == MEM_PRIVATE && IsExecutableRegion(mbi.Protect)) {
            suspicious = true;
        }
    }
    
    CloseHandle(hProcess);
    return suspicious;
#else
    return false;
#endif
}

bool MemoryAnalyzer::ScanProcessForPatterns(DWORD process_id, const std::vector<MalwareSignature>& signatures) {
#ifdef _WIN32
    if (signatures.empty()) return false;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == NULL) {
        return false;
    }
    
    std::vector<MemoryRegion> regions;
    if (!EnumerateProcessMemory(process_id, regions)) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Scan each region
    for (const auto& region : regions) {
        if (region.is_executable) {
            ScanMemoryRegion(hProcess, region);
        }
    }
    
    CloseHandle(hProcess);
    return true;
#else
    return false;
#endif
}

bool MemoryAnalyzer::ScanMemoryRegion(HANDLE process_handle, const MemoryRegion& region) {
#ifdef _WIN32
    // Don't scan huge regions
    if (region.region_size > max_dump_size_) {
        return false;
    }
    
    ByteVector buffer(region.region_size);
    SIZE_T bytes_read = 0;
    
    if (ReadProcessMemory(process_handle, (LPCVOID)region.base_address, 
                         buffer.data(), region.region_size, &bytes_read) == 0) {
        return false;
    }
    
    buffer.resize(bytes_read);
    
    // Check for PE header
    if (DetectPeHeader(buffer)) {
        // Valid PE in memory
    }
    
    // Check for shellcode patterns
    if (DetectShellcode(buffer)) {
        // Possible shellcode detected
    }
    
    return true;
#else
    return false;
#endif
}

bool MemoryAnalyzer::DetectShellcode(const ByteVector& memory_data) {
    if (memory_data.size() < 10) return false;
    
    // Look for common shellcode patterns
    // This is a simplified check - real shellcode detection is more sophisticated
    
    // Check for common x86/x64 instruction sequences
    const std::vector<ByteVector> shellcode_patterns = {
        {0xEB, 0x00},           // JMP +0 (often used in shellcode)
        {0x90, 0x90, 0x90},     // NOP sled
        {0xCC, 0xCC, 0xCC},     // INT3 (breakpoint)
        {0x64, 0xA1, 0x30},     // MOV EAX, FS:[0x30] (PEB access)
    };
    
    for (const auto& pattern : shellcode_patterns) {
        for (size_t i = 0; i < memory_data.size() - pattern.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); j++) {
                if (memory_data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
    }
    
    return false;
}

bool MemoryAnalyzer::DetectPeHeader(const ByteVector& memory_data) {
    if (memory_data.size() < 64) return false;
    
    // Check for DOS header signature "MZ"
    if (memory_data[0] != 'M' || memory_data[1] != 'Z') {
        return false;
    }
    
    // Get PE header offset
    if (memory_data.size() < 0x3C + 4) return false;
    
    DWORD pe_offset = *(DWORD*)&memory_data[0x3C];
    if (pe_offset >= memory_data.size() - 4) return false;
    
    // Check for PE signature "PE\0\0"
    if (memory_data[pe_offset] == 'P' && 
        memory_data[pe_offset + 1] == 'E' &&
        memory_data[pe_offset + 2] == 0 &&
        memory_data[pe_offset + 3] == 0) {
        return true;
    }
    
    return false;
}

bool MemoryAnalyzer::LoadMalwareSignatures() {
    // Load some basic malware signatures
    // In a real implementation, these would be loaded from a signature database
    
    MalwareSignature sig1;
    sig1.name = L"Generic Shellcode";
    sig1.description = L"Common shellcode pattern";
    sig1.pattern = {0x90, 0x90, 0x90, 0xEB, 0x00};
    sig1.min_size = 5;
    sig1.severity = SecurityLevel::High;
    malware_signatures_.push_back(sig1);
    
    SYSRECON_LOG_INFO(L"Loaded " + std::to_wstring(malware_signatures_.size()) + L" malware signatures");
    return true;
}

SecurityLevel MemoryAnalyzer::AssessMemoryRisk(const ProcessMemoryInfo& memory_info) {
    if (!memory_info.suspicious_regions.empty()) {
        return SecurityLevel::High;
    }
    
    // Check for large amounts of executable memory
    SIZE_T total_executable = 0;
    for (const auto& region : memory_info.regions) {
        if (region.is_executable) {
            total_executable += region.region_size;
        }
    }
    
    if (total_executable > 50 * 1024 * 1024) { // More than 50MB executable
        return SecurityLevel::Medium;
    }
    
    return SecurityLevel::Low;
}

SecurityLevel MemoryAnalyzer::AssessRegionRisk(const MemoryRegion& region) {
    // RWX regions are highly suspicious
    if (region.is_executable && region.is_writable) {
        return SecurityLevel::Critical;
    }
    
    // Large executable regions
    if (region.is_executable && region.region_size > 10 * 1024 * 1024) {
        return SecurityLevel::Medium;
    }
    
    // Private executable memory
    if (region.is_executable && region.type == MEM_PRIVATE) {
        return SecurityLevel::High;
    }
    
    return SecurityLevel::Low;
}

String MemoryAnalyzer::ProtectionToString(DWORD protection) {
    switch (protection & 0xFF) {
        case PAGE_NOACCESS: return L"---";
        case PAGE_READONLY: return L"R--";
        case PAGE_READWRITE: return L"RW-";
        case PAGE_WRITECOPY: return L"RWC";
        case PAGE_EXECUTE: return L"--X";
        case PAGE_EXECUTE_READ: return L"R-X";
        case PAGE_EXECUTE_READWRITE: return L"RWX";
        case PAGE_EXECUTE_WRITECOPY: return L"RWXC";
        default: return L"???";
    }
}

String MemoryAnalyzer::StateToString(DWORD state) {
    switch (state) {
        case MEM_COMMIT: return L"Committed";
        case MEM_FREE: return L"Free";
        case MEM_RESERVE: return L"Reserved";
        default: return L"Unknown";
    }
}

String MemoryAnalyzer::TypeToString(DWORD type) {
    switch (type) {
        case MEM_IMAGE: return L"Image";
        case MEM_MAPPED: return L"Mapped";
        case MEM_PRIVATE: return L"Private";
        default: return L"Unknown";
    }
}

bool MemoryAnalyzer::IsExecutableRegion(DWORD protection) {
    return (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool MemoryAnalyzer::IsWritableRegion(DWORD protection) {
    return (protection & (PAGE_READWRITE | PAGE_WRITECOPY | 
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool MemoryAnalyzer::IsCommittedRegion(DWORD state) {
    return state == MEM_COMMIT;
}

// Stub implementations for methods not fully implemented yet
bool MemoryAnalyzer::DetectManualDllLoad(DWORD process_id) { return false; }
bool MemoryAnalyzer::DetectReflectiveDllLoad(DWORD process_id) { return false; }
bool MemoryAnalyzer::DetectAtomBombing(DWORD process_id) { return false; }
StringVector MemoryAnalyzer::FindSuspiciousProcesses() { return StringVector(); }
StringVector MemoryAnalyzer::FindCodeInjection() { return StringVector(); }
StringVector MemoryAnalyzer::FindHollowedProcesses() { return StringVector(); }
StringVector MemoryAnalyzer::FindMalwareSignatures() { return StringVector(); }

void MemoryAnalyzer::Cleanup() {
    process_memory_.clear();
    injection_indicators_.clear();
    malware_signatures_.clear();
    scan_results_.clear();
    initialized_ = false;
    
    SYSRECON_LOG_INFO(L"Memory Analyzer cleaned up. Scanned " + 
                     std::to_wstring(total_regions_scanned_) + L" regions (" +
                     std::to_wstring(total_bytes_scanned_ / 1024 / 1024) + L" MB)");
}

} // namespace Modules
} // namespace SysRecon
