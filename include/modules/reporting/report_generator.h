#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

enum class ReportFormat {
    JSON,
    CSV,
    HTML,
    PDF,
    XML,
    TXT
};

struct ReportConfig {
    String output_directory;
    String report_title;
    String company_name;
    String author;
    bool include_system_info = true;
    bool include_executive_summary = true;
    bool include_detailed_findings = true;
    bool include_recommendations = true;
    bool include_raw_data = false;
    bool compress_output = false;
    bool encrypt_output = false;
    String encryption_password;
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

struct ExecutiveSummary {
    size_t total_findings;
    size_t critical_findings;
    size_t high_findings;
    size_t medium_findings;
    size_t low_findings;
    double overall_risk_score;
    StringVector top_risks;
    StringVector key_recommendations;
};

struct Finding {
    String id;
    String title;
    String description;
    SecurityLevel severity;
    String category;
    String module;
    StringVector evidence;
    StringVector recommendations;
    StringMap metadata;
    std::chrono::system_clock::time_point discovered_time;
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
    bool GeneratePDF(const String& filename);
    bool GenerateXML(const String& filename);
    bool GenerateText(const String& filename);
    
    // Report components
    bool GenerateExecutiveSummary();
    bool GenerateFindings();
    bool GenerateRecommendations();
    bool GenerateSystemInfoSection();
    
    // Analysis and scoring
    double CalculateRiskScore();
    StringVector GetTopRisks(size_t count = 5);
    StringVector GenerateRecommendationsList();
    
    // Utility methods
    String GetReportTemplate(ReportFormat format);
    String FormatFinding(const Finding& finding, ReportFormat format);
    String FormatSeverity(SecurityLevel severity);
    String FormatTimestamp(const std::chrono::system_clock::time_point& time);
    
private:
    // Report processing
    void ProcessScanResults();
    void CategorizeFindingsByModule();
    void CategorizeFindingsBySeverity();
    void GenerateFindingIds();
    
    // Template processing
    String ProcessTemplate(const String& template_content);
    String ReplaceVariables(const String& content);
    
    // JSON generation
    String GenerateJSONSystemInfo();
    String GenerateJSONExecutiveSummary();
    String GenerateJSONFindings();
    String GenerateJSONRecommendations();
    
    // CSV generation
    String GenerateCSVHeader();
    String GenerateCSVRow(const Finding& finding);
    
    // HTML generation
    String GenerateHTMLHeader();
    String GenerateHTMLSystemInfo();
    String GenerateHTMLExecutiveSummary();
    String GenerateHTMLFindings();
    String GenerateHTMLRecommendations();
    String GenerateHTMLFooter();
    String GenerateHTMLChart(const String& chart_type, const StringMap& data);
    
    // PDF generation (requires external library or HTML to PDF conversion)
    bool ConvertHTMLToPDF(const String& html_content, const String& pdf_filename);
    
    // XML generation
    String GenerateXMLHeader();
    String GenerateXMLSystemInfo();
    String GenerateXMLFindings();
    String GenerateXMLFooter();
    
    // Text generation
    String GenerateTextHeader();
    String GenerateTextSystemInfo();
    String GenerateTextExecutiveSummary();
    String GenerateTextFindings();
    String GenerateTextRecommendations();
    
    // Security and compression
    bool CompressReport(const String& filename);
    bool EncryptReport(const String& filename);
    String GenerateReportHash(const String& filename);
    
    // File operations
    bool WriteToFile(const String& filename, const String& content);
    bool WriteToFile(const String& filename, const ByteVector& data);
    String ReadFromFile(const String& filename);
    
    // Configuration
    ReportConfig config_;
    
    // Data
    ScanResults scan_results_;
    SystemInfo system_info_;
    std::vector<Finding> findings_;
    ExecutiveSummary executive_summary_;
    std::map<String, String> custom_sections_;
    
    // Organization
    std::map<SecurityLevel, std::vector<Finding>> findings_by_severity_;
    std::map<String, std::vector<Finding>> findings_by_module_;
    std::map<String, std::vector<Finding>> findings_by_category_;
    
    // Templates
    static const String JSON_TEMPLATE;
    static const String HTML_TEMPLATE;
    static const String XML_TEMPLATE;
    static const String TEXT_TEMPLATE;
    
    // State
    bool results_processed_;
    StringVector error_messages_;
};

} // namespace Modules
} // namespace SysRecon
