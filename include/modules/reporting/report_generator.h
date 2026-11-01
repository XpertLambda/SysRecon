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
    // Run context: an analyst reading a report later needs to know how much of
    // the system the scan could actually see.
    bool elevated = false;
    bool stealth = false;
    StringVector modules;
    String config_path;
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
    // Checks that failed or could not run. Rendered in every report format so
    // a partial scan is never mistaken for a clean one.
    void SetIncompleteChecks(const StringVector& notes) { incomplete_checks_ = notes; }
    
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
    StringVector incomplete_checks_;

    bool results_processed_;
};

} // namespace Modules
} // namespace SysRecon
