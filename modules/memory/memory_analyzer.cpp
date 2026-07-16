#include "../../include/modules/memory/memory_analyzer.h"
#include "../../include/core/whitelist.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <cstring>

namespace SysRecon {
namespace Modules {

namespace {

// Formats an address as real hex. std::to_wstring produces decimal, so
// L"0x" + std::to_wstring(addr) printed a decimal number behind a hex prefix.
String FormatHexAddress(DWORD_PTR address) {
    wchar_t buffer[32];
    swprintf(buffer, 32, L"0x%016llX", static_cast<unsigned long long>(address));
    return String(buffer);
}

// Resolves the full image path for a PID. Whitelist decisions must never be
// made on a process name alone -- an implant can call itself csrss.exe.
// Returns an empty string on failure, which callers treat as "not verified".
String GetProcessImagePath(DWORD process_id) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
    if (hProcess == NULL) {
        return String();
    }
    WCHAR buffer[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    String path;
    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
        path.assign(buffer, size);
    }
    CloseHandle(hProcess);
    return path;
#else
    (void)process_id;
    return String();
#endif
}

}  // namespace

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
    memory_info.image_path = GetProcessImagePath(process_id);
    
    // Get memory statistics
    PROCESS_MEMORY_COUNTERS_EX pmc = {};
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
            // Check if this is a system process before flagging RWX regions
            bool is_system = Core::SystemWhitelist::Instance()
                                 .IsSystemProcess(memory_info.process_name, memory_info.image_path);
            
            // Only flag RWX regions as high risk for non-system processes
            // or if the region is unusually large
            SecurityLevel region_risk = SecurityLevel::Low;
            
            if (!is_system && region.region_size > 0x1000) {  // Larger than 4KB
                region_risk = SecurityLevel::Medium;
            }
            
            if (!is_system && region.region_size > 0x100000) {  // Larger than 1MB
                region_risk = SecurityLevel::High;
            }
            
            String suspicious = L"RWX (Read-Write-Execute) memory region at " +
                              FormatHexAddress(region.base_address) +
                              L" (size: " + std::to_wstring(region.region_size / 1024) + L" KB)";
            
            if (region_risk >= SecurityLevel::Medium) {
                memory_info.suspicious_regions.push_back(suspicious);
                
                ScanResult result;
                result.module_name = L"Memory";
                result.item_name = memory_info.process_name;
                result.description = suspicious;
                result.risk_level = region_risk;
                result.details[L"address"] = FormatHexAddress(region.base_address);
                result.details[L"size"] = std::to_wstring(region.region_size);
                result.details[L"size_kb"] = std::to_wstring(region.region_size / 1024);
                result.details[L"protection"] = region.protection_string;
                result.details[L"note"] = is_system ? L"System process - may be normal" : L"Non-system process";
                scan_results_.push_back(result);
            }
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
        MEMORY_BASIC_INFORMATION mbi = {};
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
    // MiniDumpWriteDump needs both of these rights; the previous
    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ was not sufficient.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  FALSE, process_id);
    if (hProcess == NULL) {
        SYSRECON_LOG_ERROR(L"Dump: cannot open PID " + std::to_wstring(process_id) +
                           L": " + Core::Utils::GetLastErrorString());
        return false;
    }

    HANDLE hFile = CreateFileW(output_path.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SYSRECON_LOG_ERROR(L"Dump: cannot create " + output_path + L": " +
                           Core::Utils::GetLastErrorString());
        CloseHandle(hProcess);
        return false;
    }

    // Actually write the dump. This previously logged "Memory dump created"
    // and returned true having written zero bytes -- a forensics tool must
    // never report a successful capture it did not perform.
    MINIDUMP_EXCEPTION_INFORMATION* exception_info = nullptr;
    const MINIDUMP_TYPE dump_type = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithThreadInfo);

    BOOL written = MiniDumpWriteDump(hProcess, process_id, hFile, dump_type,
                                     exception_info, NULL, NULL);
    if (!written) {
        const String err = Core::Utils::GetLastErrorString();
        CloseHandle(hFile);
        CloseHandle(hProcess);
        DeleteFileW(output_path.c_str());  // Do not leave a truncated dump behind.
        SYSRECON_LOG_ERROR(L"Dump: MiniDumpWriteDump failed for PID " +
                           std::to_wstring(process_id) + L": " + err);
        return false;
    }

    LARGE_INTEGER size = {};
    GetFileSizeEx(hFile, &size);

    CloseHandle(hFile);
    CloseHandle(hProcess);

    SYSRECON_LOG_INFO(L"Memory dump written: " + output_path + L" (" +
                      std::to_wstring(size.QuadPart) + L" bytes)");
    return true;
#else
    (void)process_id; (void)output_path;
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
    
    PROCESSENTRY32W pe32 = {};
    pe32.dwSize = sizeof(pe32);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Skip verified system processes to reduce false positives. The
            // whitelist is consulted BEFORE the address-space walk: that walk is
            // expensive, and running it against lsass.exe only to discard the
            // result is the canonical credential-dumping signature.
            String proc_name = pe32.szExeFile;
            String proc_path = GetProcessImagePath(pe32.th32ProcessID);
            bool is_system = Core::SystemWhitelist::Instance()
                                 .IsSystemProcess(proc_name, proc_path);
            if (is_system) {
                continue;
            }

            if (DetectDllInjection(pe32.th32ProcessID)) {

                InjectionIndicator indicator;
                indicator.type = L"Possible DLL Injection";
                indicator.description = L"Suspicious unbacked executable memory in process: " + String(pe32.szExeFile);
                indicator.address = 0;
                indicator.size = 0;
                indicator.evidence = L"Private executable memory region (may be normal for .NET/JIT processes)";
                indicator.severity = SecurityLevel::Medium;  // Reduced from Critical
                injection_indicators_.push_back(indicator);
                
                ScanResult result;
                result.module_name = L"Memory Injection";
                result.item_name = pe32.szExeFile;
                result.description = L"Possible DLL injection detected (unbacked executable memory)";
                result.risk_level = SecurityLevel::Medium;  // Reduced from Critical
                result.details[L"process_id"] = std::to_wstring(pe32.th32ProcessID);
                result.details[L"injection_type"] = L"Possible DLL Injection";
                result.details[L"note"] = L"May be false positive for .NET/JIT compiled processes";
                scan_results_.push_back(result);
            }
            
            // Check for process hollowing (keep this check more strict)
            if (!is_system && DetectProcessHollowing(pe32.th32ProcessID)) {
                InjectionIndicator indicator;
                indicator.type = L"Possible Process Hollowing";
                indicator.description = L"Process hollowing indicators detected: " + String(pe32.szExeFile);
                indicator.address = 0;
                indicator.size = 0;
                indicator.evidence = L"Suspicious memory characteristics";
                indicator.severity = SecurityLevel::High;  // Reduced from Critical
                injection_indicators_.push_back(indicator);
                
                ScanResult result;
                result.module_name = L"Memory Injection";
                result.item_name = pe32.szExeFile;
                result.description = L"Possible process hollowing detected";
                result.risk_level = SecurityLevel::High;  // Reduced from Critical
                result.details[L"process_id"] = std::to_wstring(pe32.th32ProcessID);
                result.details[L"injection_type"] = L"Possible Process Hollowing";
                result.details[L"note"] = L"Requires manual verification";
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
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        // Unbacked executable memory alone is NOT evidence of injection: every
        // .NET, Java and JavaScript process JITs code into private executable
        // pages, so flagging that produced a finding for most of the machine.
        // Require an actual PE image mapped into private memory, which is the
        // signature of a reflectively loaded / manually mapped module.
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            IsExecutableRegion(mbi.Protect)) {

            // Only the header is needed to decide, so read a page at most.
            const SIZE_T probe = mbi.RegionSize < 0x1000 ? mbi.RegionSize : 0x1000;
            ByteVector header(probe);
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, header.data(), probe, &bytes_read)
                && bytes_read > 0) {
                header.resize(bytes_read);
                if (DetectPeHeader(header)) {
                    injection_detected = true;
                    break;
                }
            }
        }

        // Guard against a zero RegionSize stalling the walk.
        DWORD_PTR next = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }

    CloseHandle(hProcess);
    return injection_detected;
#else
    return false;
#endif
}

bool MemoryAnalyzer::DetectProcessHollowing(DWORD process_id) {
#ifdef _WIN32
    // Process hollowing (T1055.012): the loader maps an executable's main image
    // as MEM_IMAGE, backed by the file on disk. If a process was hollowed --
    // its image unmapped and replaced with attacker code -- the region at the
    // image base is MEM_PRIVATE instead, because it no longer corresponds to
    // any file.
    //
    // This previously queried address 0, which is always free/reserved and
    // never MEM_PRIVATE+executable, so the check could never return true. The
    // fix is to query the actual image base.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == NULL) {
        return false;
    }

    // The first module returned by EnumProcessModules is the process image.
    HMODULE main_module = NULL;
    DWORD bytes_needed = 0;
    if (!EnumProcessModules(hProcess, &main_module, sizeof(main_module), &bytes_needed) ||
        main_module == NULL) {
        CloseHandle(hProcess);
        return false;
    }

    MODULEINFO mod_info = {};
    if (!GetModuleInformation(hProcess, main_module, &mod_info, sizeof(mod_info))) {
        CloseHandle(hProcess);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    bool hollowed = false;
    if (VirtualQueryEx(hProcess, mod_info.lpBaseOfDll, &mbi, sizeof(mbi)) != 0) {
        // A legitimately loaded image is MEM_IMAGE. MEM_PRIVATE at the image
        // base means the mapping was replaced.
        hollowed = (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE);
    }

    CloseHandle(hProcess);
    return hollowed;
#else
    (void)process_id;
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

    // Both detector results were previously discarded into empty if-bodies, so
    // the malware scan could never report anything. Only unbacked (MEM_PRIVATE)
    // executable regions are reported: a PE header or shellcode inside a
    // normal file-backed image is just... the image.
    const bool unbacked = (region.type == MEM_PRIVATE);
    if (!unbacked) {
        return true;
    }

    auto add_finding = [&](const String& item, const String& description,
                           const String& technique, SecurityLevel level) {
        ScanResult result;
        result.module_name = L"Memory";
        result.item_name = item;
        result.description = description;
        result.details[L"Region Base"] = FormatHexAddress(region.base_address);
        result.details[L"Region Size"] = std::to_wstring(region.region_size);
        result.details[L"Protection"] = region.protection_string;
        result.details[L"Technique"] = technique;
        result.risk_level = level;
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
    };

    if (DetectPeHeader(buffer)) {
        // A mapped PE living in private memory is the signature of a
        // reflectively loaded / manually mapped module.
        add_finding(L"Unbacked PE image",
                    L"PE header found in private executable memory (not file-backed)",
                    L"T1620 Reflective Code Loading",
                    SecurityLevel::High);
    } else if (DetectShellcode(buffer)) {
        add_finding(L"Shellcode pattern",
                    L"Shellcode-like byte pattern in private executable memory",
                    L"T1055 Process Injection",
                    SecurityLevel::Medium);
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
        if (pattern.empty() || memory_data.size() < pattern.size()) {
            continue;
        }
        // Additive bound: `size() - pattern.size()` underflows to SIZE_MAX when
        // the pattern is longer than the buffer, turning this into an OOB read.
        for (size_t i = 0; i + pattern.size() <= memory_data.size(); i++) {
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

    // memcpy rather than *(DWORD*)&buf[0x3C]: this reads attacker-controlled
    // process memory at an arbitrary offset, so the cast is both a
    // strict-aliasing violation and potentially unaligned.
    DWORD pe_offset = 0;
    std::memcpy(&pe_offset, &memory_data[0x3C], sizeof(pe_offset));

    // Bound additively so a huge pe_offset cannot wrap the comparison.
    if (static_cast<size_t>(pe_offset) + 4 > memory_data.size()) return false;
    
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
