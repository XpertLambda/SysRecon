#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

struct MemoryRegion {
    DWORD_PTR base_address;
    SIZE_T region_size;
    DWORD protection;
    DWORD allocation_protection;
    DWORD state;
    DWORD type;
    String protection_string;
    String state_string;
    String type_string;
    bool is_executable;
    bool is_writable;
    bool contains_code;
    SecurityLevel risk_level;
};

struct ProcessMemoryInfo {
    DWORD process_id;
    String process_name;
    // Full path to the running image. Required to tell a genuine
    // C:\Windows\System32\svchost.exe from an implant of the same name.
    String image_path;
    SIZE_T working_set;
    SIZE_T page_file_usage;
    SIZE_T virtual_size;
    SIZE_T private_bytes;
    std::vector<MemoryRegion> regions;
    StringVector suspicious_regions;
    SecurityLevel overall_risk;
};

struct MalwareSignature {
    String name;
    String description;
    ByteVector pattern;
    ByteVector mask;
    size_t min_size;
    SecurityLevel severity;
};

struct InjectionIndicator {
    String type;
    String description;
    DWORD_PTR address;
    SIZE_T size;
    String evidence;
    SecurityLevel severity;
};

class MemoryAnalyzer {
public:
    MemoryAnalyzer();
    ~MemoryAnalyzer();
    
    // Main analysis methods
    bool Initialize();
    bool AnalyzeProcessMemory(DWORD process_id);
    bool CreateMemoryDump(DWORD process_id, const String& output_path);
    bool ScanForMalware();
    bool DetectInjection();
    void Cleanup();
    
    // Results access
    const std::map<DWORD, ProcessMemoryInfo>& GetProcessMemory() const { return process_memory_; }
    const std::vector<InjectionIndicator>& GetInjectionIndicators() const { return injection_indicators_; }
    const ScanResults& GetScanResults() const { return scan_results_; }
    
    // Configuration
    void SetCreateDumps(bool enable) { create_dumps_ = enable; }
    void SetAnalyzeHeap(bool enable) { analyze_heap_ = enable; }
    void SetScanForMalware(bool enable) { scan_for_malware_ = enable; }
    void SetMaxDumpSize(SIZE_T max_size) { max_dump_size_ = max_size; }
    
    // Analysis methods
    SecurityLevel AssessMemoryRisk(const ProcessMemoryInfo& memory_info);
    SecurityLevel AssessRegionRisk(const MemoryRegion& region);
    
    
    // Memory scanning
    bool ScanProcessForPatterns(DWORD process_id, const std::vector<MalwareSignature>& signatures);
    bool ScanMemoryRegion(HANDLE process_handle, const MemoryRegion& region);
    bool DetectShellcode(const ByteVector& memory_data);
    bool DetectPeHeader(const ByteVector& memory_data);
    
    // Injection detection
    bool DetectDllInjection(DWORD process_id);
    bool DetectProcessHollowing(DWORD process_id);

private:
    // Memory enumeration
    bool EnumerateProcessMemory(DWORD process_id, std::vector<MemoryRegion>& regions);

    // Pattern matching
    bool LoadMalwareSignatures();

    // Dump creation
    bool CreateMiniDump(DWORD process_id, const String& output_path);

    // Utility methods
    String ProtectionToString(DWORD protection);
    String StateToString(DWORD state);
    String TypeToString(DWORD type);
    bool IsExecutableRegion(DWORD protection);
    bool IsWritableRegion(DWORD protection);
    bool IsCommittedRegion(DWORD state);
    
    // Configuration
    bool create_dumps_;
    bool analyze_heap_;
    bool scan_for_malware_;
    SIZE_T max_dump_size_;
    
    // Data storage
    std::map<DWORD, ProcessMemoryInfo> process_memory_;
    std::vector<InjectionIndicator> injection_indicators_;
    std::vector<MalwareSignature> malware_signatures_;
    ScanResults scan_results_;
    
    // State
    bool initialized_;
    StringVector error_messages_;
    
    // Performance
    std::chrono::high_resolution_clock::time_point scan_start_time_;
    size_t total_bytes_scanned_;
    size_t total_regions_scanned_;
};

} // namespace Modules
} // namespace SysRecon
