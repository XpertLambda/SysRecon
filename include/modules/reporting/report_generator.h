#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

// PDF/XML/TXT are deliberately absent: their generators logged "Generating..."
// and then returned false without writing anything. Only the three formats
// this build actually produces are offered.
enum class ReportFormat {
    JSON,
    CSV,
    HTML
};

struct ReportConfig {
    String output_directory;
    String report_title;
    String company_name;
    String author;
    bool include_system_info = true;
};

struct SystemInfo {
    String computer_name;
    String domain_name;
    String os_version;
    String os_build;
    String architecture;
    String processor;
    String memory_total;
    String uptime;
    std::chrono::system_clock::time_point scan_time;
    String sysrecon_version;
};

class ReportGenerator {
public:
    ReportGenerator();
    ~ReportGenerator();
    
    // Configuration
    void SetConfig(const ReportConfig& config);
    const ReportConfig& GetConfig() const { return config_; }
    
    // Data input
    void SetScanResults(const ScanResults& results);
    void SetSystemInfo(const SystemInfo& system_info);
    void AddCustomSection(const String& title, const String& content);
    
    // Report generation
    bool GenerateReport(ReportFormat format, const String& filename);
    bool GenerateAllFormats(const String& base_filename);
    
    // Specific format generators
    bool GenerateJSON(const String& filename);
    bool GenerateCSV(const String& filename);
    bool GenerateHTML(const String& filename);

private:
    ReportConfig config_;

    ScanResults scan_results_;
    SystemInfo system_info_;
    std::map<String, String> custom_sections_;

    bool results_processed_;
};

} // namespace Modules
} // namespace SysRecon
