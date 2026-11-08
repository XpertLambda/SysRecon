#pragma once

#include "../../sysrecon.h"
#include "../../core/findings.h"
#include "../../core/scoring.h"

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
    String os_version;      // Display string, e.g. "Windows 11 (Build 26200)".
    String os_name;         // "Windows 11", "Windows Server 2025", ...
    String os_family;       // client | server | domain_controller | unknown
    String os_build;
    uint32_t os_ubr = 0;    // Update Build Revision (26200.<ubr>); 0 = unknown.
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
    // --baseline comparison: rendered as a "baseline" section (JSON) or a
    // summary box (HTML) listing resolved findings.
    void SetBaseline(const String& source, const String& baseline_timestamp,
                     const Core::Findings::BaselineDiff& diff, bool new_only) {
        has_baseline_ = true;
        baseline_source_ = source;
        baseline_timestamp_ = baseline_timestamp;
        baseline_diff_ = diff;
        baseline_new_only_ = new_only;
    }
    
    // Report generation
    bool GenerateReport(ReportFormat format, const String& filename);
    bool GenerateAllFormats(const String& base_filename);
    
    // Specific format generators
    bool GenerateJSON(const String& filename);
    bool GenerateCSV(const String& filename);
    bool GenerateHTML(const String& filename);
    // Machine-readable outputs for pipelines / triage.
    bool GenerateSARIF(const String& filename);              // SARIF 2.1.0
    bool GenerateAttackNavigatorLayer(const String& filename); // MITRE ATT&CK Navigator layer

    // Host risk score (0-100) and rating, scoring model v2 (see core/scoring.h):
    // the rating is the worst effective severity tier present and the score
    // stays inside that tier's band. Shared by the summary of every format.
    Core::Scoring::Result RiskAssessment() const;

private:
    ReportConfig config_;

    ScanResults scan_results_;
    SystemInfo system_info_;
    std::map<String, String> custom_sections_;
    StringVector incomplete_checks_;
    bool has_baseline_ = false;
    bool baseline_new_only_ = false;
    String baseline_source_;
    String baseline_timestamp_;
    Core::Findings::BaselineDiff baseline_diff_;

    bool results_processed_;
};

} // namespace Modules
} // namespace SysRecon
