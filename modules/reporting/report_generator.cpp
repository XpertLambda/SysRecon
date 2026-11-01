#include "../../include/modules/reporting/report_generator.h"
#include <json/json.hpp>

using json = nlohmann::json;

namespace SysRecon {
namespace Modules {

ReportGenerator::ReportGenerator() 
    : results_processed_(false) {
}

ReportGenerator::~ReportGenerator() {
}

void ReportGenerator::SetConfig(const ReportConfig& config) {
    config_ = config;
}

void ReportGenerator::SetScanResults(const ScanResults& results) {
    scan_results_ = results;
    results_processed_ = false;
}

void ReportGenerator::SetSystemInfo(const SystemInfo& system_info) {
    system_info_ = system_info;
}

void ReportGenerator::AddCustomSection(const String& title, const String& content) {
    custom_sections_[title] = content;
}

bool ReportGenerator::GenerateReport(ReportFormat format, const String& filename) {
    SYSRECON_LOG_INFO(L"Generating report: " + filename);
    
    switch (format) {
        case ReportFormat::JSON:
            return GenerateJSON(filename);
        case ReportFormat::CSV:
            return GenerateCSV(filename);
        case ReportFormat::HTML:
            return GenerateHTML(filename);
        case ReportFormat::PDF:
            return GeneratePDF(filename);
        default:
            SYSRECON_LOG_ERROR(L"Unsupported report format");
            return false;
    }
}

bool ReportGenerator::GenerateJSON(const String& filename) {
    SYSRECON_LOG_INFO(L"Generating JSON report...");
    
    try {
        nlohmann::json j;

        // Scan information
        j["scan_info"]["version"] = SYSRECON_VERSION;
        j["scan_info"]["timestamp"] = Core::Utils::WideToUtf8(Core::Utils::GetCurrentTimestamp());
        j["scan_info"]["hostname"] = Core::Utils::WideToUtf8(Core::Utils::GetComputerName());
        j["scan_info"]["os_version"] = Core::Utils::WideToUtf8(Core::Utils::GetWindowsVersion());
        j["scan_info"]["current_user"] = Core::Utils::WideToUtf8(Core::Utils::GetCurrentUserName());
        j["scan_info"]["total_findings"] = scan_results_.size();

        // System information
        j["system_info"]["computer_name"] = Core::Utils::WideToUtf8(system_info_.computer_name);
        j["system_info"]["domain_name"] = Core::Utils::WideToUtf8(system_info_.domain_name);
        j["system_info"]["os_version"] = Core::Utils::WideToUtf8(system_info_.os_version);
        j["system_info"]["architecture"] = Core::Utils::WideToUtf8(system_info_.architecture);
        j["system_info"]["processor"] = Core::Utils::WideToUtf8(system_info_.processor);
        j["system_info"]["memory_total"] = Core::Utils::WideToUtf8(system_info_.memory_total);
        j["system_info"]["uptime"] = Core::Utils::WideToUtf8(system_info_.uptime);

        // Scan results
        j["results"] = nlohmann::json::array();

        int critical_count = 0, high_count = 0, medium_count = 0, low_count = 0;

        for (const auto& result : scan_results_) {
            nlohmann::json result_obj;
            result_obj["module"] = Core::Utils::WideToUtf8(result.module_name);
            result_obj["item"] = Core::Utils::WideToUtf8(result.item_name);
            result_obj["description"] = Core::Utils::WideToUtf8(result.description);

            // Risk level
            String risk_str;
            switch (result.risk_level) {
                case SecurityLevel::Critical: risk_str = L"Critical"; critical_count++; break;
                case SecurityLevel::High: risk_str = L"High"; high_count++; break;
                case SecurityLevel::Medium: risk_str = L"Medium"; medium_count++; break;
                case SecurityLevel::Low: risk_str = L"Low"; low_count++; break;
            }
            result_obj["risk_level"] = Core::Utils::WideToUtf8(risk_str);

            // Phase 2: first-class remediation / reference for tooling.
            if (!result.remediation.empty())
                result_obj["remediation"] = Core::Utils::WideToUtf8(result.remediation);
            if (!result.reference.empty())
                result_obj["reference"] = Core::Utils::WideToUtf8(result.reference);

            // Details
            result_obj["details"] = nlohmann::json::object();
            for (const auto& detail : result.details) {
                result_obj["details"][Core::Utils::WideToUtf8(detail.first)] = Core::Utils::WideToUtf8(detail.second);
            }

            j["results"].push_back(result_obj);
        }

        // Summary + weighted risk score (0-100) and rating.
        int risk_score = critical_count * 25 + high_count * 10 + medium_count * 4 + low_count;
        if (risk_score > 100) risk_score = 100;
        std::string rating = "Minimal";
        if (critical_count > 0 || risk_score >= 60)      rating = "Critical";
        else if (high_count > 0 || risk_score >= 30)     rating = "High";
        else if (medium_count > 0 || risk_score >= 10)   rating = "Moderate";
        else if (risk_score > 0)                         rating = "Low";

        j["summary"]["critical"] = critical_count;
        j["summary"]["high"] = high_count;
        j["summary"]["medium"] = medium_count;
        j["summary"]["low"] = low_count;
        j["summary"]["total"] = scan_results_.size();
        j["summary"]["risk_score"] = risk_score;
        j["summary"]["rating"] = rating;
        
        // Write to file
        std::ofstream file(Core::Utils::WideToUtf8(filename));
        if (!file.is_open()) {
            SYSRECON_LOG_ERROR(L"Failed to create report file");
            return false;
        }
        
        file << j.dump(4);
        file.close();
        
        SYSRECON_LOG_INFO(L"JSON report generated successfully");
        return true;
        
    } catch (const std::exception& e) {
        SYSRECON_LOG_ERROR(L"Failed to generate JSON report: " + Core::Utils::Utf8ToWide(e.what()));
        return false;
    }
}

bool ReportGenerator::GenerateCSV(const String& filename) {
    SYSRECON_LOG_INFO(L"Generating CSV report...");
    
    std::ofstream file(Core::Utils::WideToUtf8(filename));
    if (!file.is_open()) {
        SYSRECON_LOG_ERROR(L"Failed to create CSV file");
        return false;
    }
    
    // Escapes embedded double-quotes so fields stay valid CSV.
    auto csv = [](const String& w) {
        std::string s = Core::Utils::WideToUtf8(w);
        std::string out;
        out.reserve(s.size());
        for (char c : s) { if (c == '"') out += '"'; out += c; }
        return out;
    };

    // Header
    file << "Module,Item,Risk Level,Description,Remediation,Reference,Details\n";

    // Results
    for (const auto& result : scan_results_) {
        file << "\"" << csv(result.module_name) << "\",";
        file << "\"" << csv(result.item_name) << "\",";

        // Risk level
        String risk_str;
        switch (result.risk_level) {
            case SecurityLevel::Critical: risk_str = L"Critical"; break;
            case SecurityLevel::High: risk_str = L"High"; break;
            case SecurityLevel::Medium: risk_str = L"Medium"; break;
            case SecurityLevel::Low: risk_str = L"Low"; break;
        }
        file << "\"" << csv(risk_str) << "\",";
        file << "\"" << csv(result.description) << "\",";
        file << "\"" << csv(result.remediation) << "\",";
        file << "\"" << csv(result.reference) << "\",";

        // Concatenate details
        std::string details_str;
        for (const auto& detail : result.details) {
            if (detail.first == L"Remediation" || detail.first == L"Reference") continue;
            if (!details_str.empty()) details_str += "; ";
            details_str += csv(detail.first) + ": " + csv(detail.second);
        }
        file << "\"" << details_str << "\"\n";
    }
    
    file.close();
    SYSRECON_LOG_INFO(L"CSV report generated successfully");
    return true;
}

bool ReportGenerator::GenerateHTML(const String& filename) {
    SYSRECON_LOG_INFO(L"Generating HTML report...");
    
    std::wstringstream html;
    
    html << L"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n";
    html << L"<meta charset=\"UTF-8\">\n";
    html << L"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html << L"<title>SysRecon Security Report</title>\n";
    html << L"<style>\n";
    html << L"body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }\n";
    html << L"h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }\n";
    html << L"h2 { color: #555; margin-top: 30px; }\n";
    html << L".info-box { background: white; padding: 15px; border-radius: 5px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n";
    html << L".finding { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #ccc; border-radius: 3px; }\n";
    html << L".finding.critical { border-left-color: #dc3545; }\n";
    html << L".finding.high { border-left-color: #fd7e14; }\n";
    html << L".finding.medium { border-left-color: #ffc107; }\n";
    html << L".finding.low { border-left-color: #28a745; }\n";
    html << L".risk-critical { color: #dc3545; font-weight: bold; }\n";
    html << L".risk-high { color: #fd7e14; font-weight: bold; }\n";
    html << L".risk-medium { color: #ffc107; font-weight: bold; }\n";
    html << L".risk-low { color: #28a745; font-weight: bold; }\n";
    html << L"table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; }\n";
    html << L"th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n";
    html << L"th { background-color: #007bff; color: white; }\n";
    html << L".details { margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 3px; }\n";
    html << L".remediation { margin-top: 10px; padding: 10px; background: #e7f5e9; border-left: 4px solid #28a745; border-radius: 3px; }\n";
    html << L".reference { margin-top: 8px; color: #555; font-size: 0.9em; }\n";
    html << L"</style>\n";
    html << L"</head>\n<body>\n";
    
    // Header
    html << L"<h1>🔒 SysRecon Security Assessment Report</h1>\n";
    html << L"<div class=\"info-box\">\n";
    html << L"<p><strong>Generated:</strong> " << Core::Utils::GetCurrentTimestamp() << L"</p>\n";
    html << L"<p><strong>SysRecon Version:</strong> " << Core::Utils::Utf8ToWide(SYSRECON_VERSION) << L"</p>\n";
    html << L"<p><strong>System:</strong> " << Core::Utils::GetComputerName();
    if (!system_info_.domain_name.empty()) html << L" (" << system_info_.domain_name << L")";
    html << L"</p>\n";
    html << L"<p><strong>OS Version:</strong> " << Core::Utils::GetWindowsVersion() << L"</p>\n";
    if (!system_info_.processor.empty())
        html << L"<p><strong>Processor:</strong> " << system_info_.processor << L"</p>\n";
    if (!system_info_.memory_total.empty())
        html << L"<p><strong>Total Memory:</strong> " << system_info_.memory_total << L"</p>\n";
    if (!system_info_.uptime.empty())
        html << L"<p><strong>Uptime:</strong> " << system_info_.uptime << L"</p>\n";
    html << L"<p><strong>User:</strong> " << Core::Utils::GetCurrentUserName() << L"</p>\n";
    html << L"<p><strong>Total Findings:</strong> " << scan_results_.size() << L"</p>\n";
    html << L"</div>\n";
    
    // Count findings by severity
    int critical = 0, high = 0, medium = 0, low = 0;
    for (const auto& result : scan_results_) {
        switch (result.risk_level) {
            case SecurityLevel::Critical: critical++; break;
            case SecurityLevel::High: high++; break;
            case SecurityLevel::Medium: medium++; break;
            case SecurityLevel::Low: low++; break;
        }
    }
    
    // Executive summary + weighted risk score / rating.
    int risk_score = critical * 25 + high * 10 + medium * 4 + low;
    if (risk_score > 100) risk_score = 100;
    String rating = L"Minimal"; String rating_class = L"low";
    if (critical > 0 || risk_score >= 60)      { rating = L"Critical"; rating_class = L"critical"; }
    else if (high > 0 || risk_score >= 30)     { rating = L"High"; rating_class = L"high"; }
    else if (medium > 0 || risk_score >= 10)   { rating = L"Moderate"; rating_class = L"medium"; }
    else if (risk_score > 0)                   { rating = L"Low"; rating_class = L"low"; }

    html << L"<h2>📊 Executive Summary</h2>\n";
    html << L"<div class=\"info-box\">\n";
    html << L"<p><strong>Overall Risk Rating:</strong> <span class=\"risk-" << rating_class
         << L"\">" << rating << L"</span> (score " << risk_score << L"/100)</p>\n";
    html << L"<table>\n<tr><th>Severity</th><th>Count</th></tr>\n";
    html << L"<tr><td><span class=\"risk-critical\">Critical</span></td><td>" << critical << L"</td></tr>\n";
    html << L"<tr><td><span class=\"risk-high\">High</span></td><td>" << high << L"</td></tr>\n";
    html << L"<tr><td><span class=\"risk-medium\">Medium</span></td><td>" << medium << L"</td></tr>\n";
    html << L"<tr><td><span class=\"risk-low\">Low</span></td><td>" << low << L"</td></tr>\n";
    html << L"</table>\n</div>\n";

    // Findings, ordered most-severe first so remediation effort can be triaged.
    html << L"<h2>🔍 Detailed Findings</h2>\n";

    std::vector<const ScanResult*> ordered;
    ordered.reserve(scan_results_.size());
    for (const auto& r : scan_results_) ordered.push_back(&r);
    std::sort(ordered.begin(), ordered.end(), [](const ScanResult* a, const ScanResult* b) {
        return static_cast<int>(a->risk_level) > static_cast<int>(b->risk_level);
    });

    for (const auto* resultPtr : ordered) {
        const ScanResult& result = *resultPtr;
        String risk_class, risk_str;
        switch (result.risk_level) {
            case SecurityLevel::Critical: risk_class = L"critical"; risk_str = L"Critical"; break;
            case SecurityLevel::High: risk_class = L"high"; risk_str = L"High"; break;
            case SecurityLevel::Medium: risk_class = L"medium"; risk_str = L"Medium"; break;
            case SecurityLevel::Low: risk_class = L"low"; risk_str = L"Low"; break;
        }

        html << L"<div class=\"finding " << risk_class << L"\">\n";
        html << L"<h3>" << result.module_name << L" - " << result.item_name << L"</h3>\n";
        html << L"<p><strong>Risk:</strong> <span class=\"risk-" << risk_class << L"\">" << risk_str << L"</span></p>\n";
        html << L"<p>" << result.description << L"</p>\n";

        // Details (remediation/reference are rendered separately below).
        bool has_detail = false;
        for (const auto& detail : result.details) {
            if (detail.first == L"Remediation" || detail.first == L"Reference") continue;
            if (!has_detail) { html << L"<div class=\"details\">\n<strong>Details:</strong><br>\n"; has_detail = true; }
            html << L"<strong>" << detail.first << L":</strong> " << detail.second << L"<br>\n";
        }
        if (has_detail) html << L"</div>\n";

        String remediation = result.remediation;
        String reference = result.reference;
        if (remediation.empty()) { auto it = result.details.find(L"Remediation"); if (it != result.details.end()) remediation = it->second; }
        if (reference.empty())   { auto it = result.details.find(L"Reference");   if (it != result.details.end()) reference = it->second; }

        if (!remediation.empty()) {
            html << L"<div class=\"remediation\"><strong>✔ Remediation:</strong> " << remediation << L"</div>\n";
        }
        if (!reference.empty()) {
            html << L"<p class=\"reference\"><strong>Reference:</strong> " << reference << L"</p>\n";
        }

        html << L"</div>\n";
    }
    
    html << L"</body>\n</html>\n";
    
    std::ofstream file(Core::Utils::WideToUtf8(filename));
    if (!file.is_open()) {
        SYSRECON_LOG_ERROR(L"Failed to create HTML file");
        return false;
    }
    
    file << Core::Utils::WideToUtf8(html.str());
    file.close();
    
    SYSRECON_LOG_INFO(L"HTML report generated successfully");
    return true;
}

bool ReportGenerator::GeneratePDF(const String& filename) {
    SYSRECON_LOG_WARNING(L"PDF generation not yet implemented");
    return false;
}

bool ReportGenerator::GenerateXML(const String& filename) {
    SYSRECON_LOG_INFO(L"Generating XML report...");
    return false;
}

bool ReportGenerator::GenerateText(const String& filename) {
    SYSRECON_LOG_INFO(L"Generating text report...");
    return false;
}

bool ReportGenerator::GenerateAllFormats(const String& base_filename) {
    bool success = true;
    success &= GenerateJSON(base_filename + L".json");
    success &= GenerateCSV(base_filename + L".csv");
    success &= GenerateHTML(base_filename + L".html");
    return success;
}

bool ReportGenerator::GenerateExecutiveSummary() {
    return true;
}

bool ReportGenerator::GenerateFindings() {
    return true;
}

bool ReportGenerator::GenerateRecommendations() {
    return true;
}

bool ReportGenerator::GenerateSystemInfoSection() {
    return true;
}

double ReportGenerator::CalculateRiskScore() {
    return 0.0;
}

StringVector ReportGenerator::GetTopRisks(size_t count) {
    return StringVector();
}

StringVector ReportGenerator::GenerateRecommendationsList() {
    return StringVector();
}

}
}
