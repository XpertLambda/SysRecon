#include "../../include/modules/reporting/report_generator.h"
#include "../../include/core/text_utils.h"
#include <json/json.hpp>

using json = nlohmann::json;

namespace {
// Every value below originates from the scanned system (registry Run value
// names, service display names, process names) and is therefore
// attacker-controlled. Reports must be inert.
inline SysRecon::String H(const SysRecon::String& v) {
    return SysRecon::Core::Text::HtmlEscape(v);
}
}  // namespace

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
        j["scan_info"]["version"] = Core::Utils::WideToUtf8(SYSRECON_VERSION);
        j["scan_info"]["timestamp"] = Core::Utils::WideToUtf8(Core::Utils::GetCurrentTimestamp());
        j["scan_info"]["hostname"] = Core::Utils::WideToUtf8(Core::Utils::GetComputerName());
        j["scan_info"]["os_version"] = Core::Utils::WideToUtf8(Core::Utils::GetWindowsVersion());
        j["scan_info"]["current_user"] = Core::Utils::WideToUtf8(Core::Utils::GetCurrentUserName());
        j["scan_info"]["total_findings"] = scan_results_.size();
        
        // System information
        j["system_info"]["computer_name"] = Core::Utils::WideToUtf8(system_info_.computer_name);
        j["system_info"]["os_version"] = Core::Utils::WideToUtf8(system_info_.os_version);
        j["system_info"]["architecture"] = Core::Utils::WideToUtf8(system_info_.architecture);

        j["scan_info"]["elevated"] = system_info_.elevated;
        j["scan_info"]["stealth_mode"] = system_info_.stealth;
        j["scan_info"]["config"] = Core::Utils::WideToUtf8(system_info_.config_path);
        j["scan_info"]["modules"] = nlohmann::json::array();
        for (const auto& m : system_info_.modules) {
            j["scan_info"]["modules"].push_back(Core::Utils::WideToUtf8(m));
        }
        j["incomplete_checks"] = nlohmann::json::array();
        for (const auto& note : incomplete_checks_) {
            j["incomplete_checks"].push_back(Core::Utils::WideToUtf8(note));
        }
        
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
        
        // Summary
        j["summary"]["critical"] = critical_count;
        j["summary"]["high"] = high_count;
        j["summary"]["medium"] = medium_count;
        j["summary"]["low"] = low_count;
        j["summary"]["total"] = scan_results_.size();
        const int score = CalculateRiskScore();
        j["summary"]["risk_score"] = score;
        j["summary"]["rating"] = Core::Utils::WideToUtf8(RiskRating(score));
        
        // Wide path: narrowing to the ANSI codepage made any non-ASCII output
        // directory fail to open. std::filesystem::path preserves it.
        std::ofstream file{std::filesystem::path(filename)};
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
    
    // Wide path: narrowing to the ANSI codepage made any non-ASCII output
    // directory fail to open. std::filesystem::path preserves it.
    std::ofstream file{std::filesystem::path(filename)};
    if (!file.is_open()) {
        SYSRECON_LOG_ERROR(L"Failed to create CSV file");
        return false;
    }
    
    // BOM, so Excel reads the file as UTF-8 rather than the ANSI codepage.
    file << "\xEF\xBB\xBF";

    // Header
    file << "Module,Item,Risk Level,Description,Remediation,Reference,Details\n";

    // Every field goes through CsvEscape: it doubles embedded quotes per
    // RFC 4180 (service binary paths routinely contain them) and neutralises
    // spreadsheet formula injection, so naming a service "=cmd|'/c calc'!A1"
    // cannot execute code when the analyst opens the report.
    auto csv = [](const String& v) {
        return Core::Utils::WideToUtf8(Core::Text::CsvEscape(v));
    };

    for (const auto& result : scan_results_) {
        file << csv(result.module_name) << ",";
        file << csv(result.item_name) << ",";

        String risk_str;
        switch (result.risk_level) {
            case SecurityLevel::Critical: risk_str = L"Critical"; break;
            case SecurityLevel::High: risk_str = L"High"; break;
            case SecurityLevel::Medium: risk_str = L"Medium"; break;
            case SecurityLevel::Low: risk_str = L"Low"; break;
        }
        file << csv(risk_str) << ",";
        file << csv(result.description) << ",";
        file << csv(result.remediation) << ",";
        file << csv(result.reference) << ",";

        String details_str;
        for (const auto& detail : result.details) {
            if (!details_str.empty()) details_str += L"; ";
            details_str += detail.first + L": " + detail.second;
        }
        file << csv(details_str) << "\n";
    }

    // Incomplete checks as rows of their own, so a spreadsheet user sees them.
    for (const auto& note : incomplete_checks_) {
        file << csv(L"SysRecon") << "," << csv(L"Incomplete check") << ","
             << csv(L"Info") << "," << csv(note) << "," << csv(L"") << "\n";
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
    html << L".details { margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 3px; word-break: break-all; }\n";
    html << L".remediation { margin-top: 10px; padding: 10px; background: #e7f5e9; border-left: 4px solid #28a745; border-radius: 3px; }\n";
    html << L".reference { margin-top: 8px; color: #555; font-size: 0.9em; }\n";
    html << L".info-box.warning { border-left: 4px solid #fd7e14; }\n";
    html << L"</style>\n";
    html << L"</head>\n<body>\n";
    
    // Header
    html << L"<h1>🔒 SysRecon Security Assessment Report</h1>\n";
    html << L"<div class=\"info-box\">\n";
    // Header values come from the host too (computer and user names are
    // configurable), so they are escaped like everything else.
    html << L"<p><strong>Generated:</strong> " << H(Core::Utils::GetCurrentTimestamp()) << L"</p>\n";
    html << L"<p><strong>System:</strong> " << H(Core::Utils::GetComputerName()) << L"</p>\n";
    html << L"<p><strong>OS Version:</strong> " << H(Core::Utils::GetWindowsVersion()) << L"</p>\n";
    html << L"<p><strong>User:</strong> " << H(Core::Utils::GetCurrentUserName()) << L"</p>\n";
    html << L"<p><strong>Elevated:</strong> " << (system_info_.elevated ? L"Yes" : L"No") << L"</p>\n";
    html << L"<p><strong>Modules:</strong> " << H(Core::Utils::Join(system_info_.modules, L", "))
         << (system_info_.stealth ? L" (stealth mode)" : L"") << L"</p>\n";
    html << L"<p><strong>Configuration:</strong> " << H(system_info_.config_path) << L"</p>\n";
    html << L"<p><strong>Total Findings:</strong> " << scan_results_.size() << L"</p>\n";
    html << L"</div>\n";

    if (!incomplete_checks_.empty()) {
        html << L"<h2>Incomplete Checks</h2>\n";
        html << L"<div class=\"info-box warning\">\n<p>These checks did not complete; "
                L"the absence of findings in these areas is not evidence of safety.</p>\n<ul>\n";
        for (const auto& note : incomplete_checks_) {
            html << L"<li>" << H(note) << L"</li>\n";
        }
        html << L"</ul>\n</div>\n";
    }
    
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
    
    // Summary
    const int score = CalculateRiskScore();
    html << L"<h2>📊 Summary</h2>\n";
    html << L"<div class=\"info-box\">\n";
    html << L"<p><strong>Overall risk rating:</strong> " << H(RiskRating(score))
         << L" (score " << score << L"/100)</p>\n";
    html << L"<p><span class=\"risk-critical\">Critical:</span> " << critical << L"</p>\n";
    html << L"<p><span class=\"risk-high\">High:</span> " << high << L"</p>\n";
    html << L"<p><span class=\"risk-medium\">Medium:</span> " << medium << L"</p>\n";
    html << L"<p><span class=\"risk-low\">Low:</span> " << low << L"</p>\n";
    html << L"</div>\n";
    
    // Findings
    html << L"<h2>🔍 Detailed Findings</h2>\n";
    
    for (const auto& result : scan_results_) {
        String risk_class, risk_str;
        switch (result.risk_level) {
            case SecurityLevel::Critical: risk_class = L"critical"; risk_str = L"Critical"; break;
            case SecurityLevel::High: risk_class = L"high"; risk_str = L"High"; break;
            case SecurityLevel::Medium: risk_class = L"medium"; risk_str = L"Medium"; break;
            case SecurityLevel::Low: risk_class = L"low"; risk_str = L"Low"; break;
        }
        
        // risk_class/risk_str are fixed literals from the switch above and are
        // safe; everything else is untrusted and must be escaped.
        html << L"<div class=\"finding " << risk_class << L"\">\n";
        html << L"<h3>" << H(result.module_name) << L" - " << H(result.item_name) << L"</h3>\n";
        html << L"<p><strong>Risk:</strong> <span class=\"risk-" << risk_class << L"\">" << risk_str << L"</span></p>\n";
        html << L"<p>" << H(result.description) << L"</p>\n";

        if (!result.details.empty()) {
            html << L"<div class=\"details\">\n";
            html << L"<strong>Details:</strong><br>\n";
            for (const auto& detail : result.details) {
                html << L"<strong>" << H(detail.first) << L":</strong> " << H(detail.second) << L"<br>\n";
            }
            html << L"</div>\n";
        }

        if (!result.remediation.empty()) {
            html << L"<div class=\"remediation\"><strong>\u2714 Remediation:</strong> "
                 << H(result.remediation) << L"</div>\n";
        }
        if (!result.reference.empty()) {
            html << L"<p class=\"reference\"><strong>Reference:</strong> "
                 << H(result.reference) << L"</p>\n";
        }
        
        html << L"</div>\n";
    }
    
    html << L"</body>\n</html>\n";
    
    // Wide path: narrowing to the ANSI codepage made any non-ASCII output
    // directory fail to open. std::filesystem::path preserves it.
    std::ofstream file{std::filesystem::path(filename)};
    if (!file.is_open()) {
        SYSRECON_LOG_ERROR(L"Failed to create HTML file");
        return false;
    }
    
    file << Core::Utils::WideToUtf8(html.str());
    file.close();
    
    SYSRECON_LOG_INFO(L"HTML report generated successfully");
    return true;
}

int ReportGenerator::CalculateRiskScore() const {
    int critical = 0, high = 0, medium = 0, low = 0;
    for (const auto& r : scan_results_) {
        switch (r.risk_level) {
            case SecurityLevel::Critical: ++critical; break;
            case SecurityLevel::High:     ++high; break;
            case SecurityLevel::Medium:   ++medium; break;
            case SecurityLevel::Low:      ++low; break;
        }
    }
    int score = critical * 25 + high * 10 + medium * 4 + low;
    return score > 100 ? 100 : score;
}

String ReportGenerator::RiskRating(int score) const {
    int critical = 0, high = 0, medium = 0;
    for (const auto& r : scan_results_) {
        if (r.risk_level == SecurityLevel::Critical) ++critical;
        else if (r.risk_level == SecurityLevel::High) ++high;
        else if (r.risk_level == SecurityLevel::Medium) ++medium;
    }
    if (critical > 0 || score >= 60) return L"Critical";
    if (high > 0 || score >= 30)     return L"High";
    if (medium > 0 || score >= 10)   return L"Moderate";
    if (score > 0)                   return L"Low";
    return L"Minimal";
}

namespace {
// Extracts MITRE ATT&CK technique IDs (Txxxx or Txxxx.yyy) from a reference
// string such as "MITRE ATT&CK T1548.002 (Bypass UAC)".
SysRecon::StringVector ExtractTechniqueIds(const SysRecon::String& reference) {
    SysRecon::StringVector ids;
    size_t i = 0;
    while (i < reference.size()) {
        if (reference[i] == L'T' && i + 1 < reference.size() &&
            reference[i + 1] >= L'0' && reference[i + 1] <= L'9') {
            size_t j = i + 1;
            while (j < reference.size() && reference[j] >= L'0' && reference[j] <= L'9') ++j;
            if (j < reference.size() && reference[j] == L'.') {
                size_t k = j + 1;
                while (k < reference.size() && reference[k] >= L'0' && reference[k] <= L'9') ++k;
                if (k > j + 1) j = k;
            }
            ids.push_back(reference.substr(i, j - i));
            i = j;
        } else {
            ++i;
        }
    }
    return ids;
}
}  // namespace

bool ReportGenerator::GenerateSARIF(const String& filename) {
    SYSRECON_LOG_INFO(L"Generating SARIF report...");
    try {
        json root;
        root["version"] = "2.1.0";
        root["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";

        json run;
        run["tool"]["driver"]["name"] = "SysRecon";
        run["tool"]["driver"]["version"] = Core::Utils::WideToUtf8(SYSRECON_VERSION);
        run["tool"]["driver"]["informationUri"] = "https://github.com/XpertLambda/SysRecon";

        // One SARIF rule per distinct (module + item) finding type.
        json rules = json::array();
        json results = json::array();
        std::map<std::string, size_t> rule_index;

        auto sarif_level = [](SecurityLevel s) -> const char* {
            // SARIF levels: error/warning/note. Critical+High -> error.
            switch (s) {
                case SecurityLevel::Critical:
                case SecurityLevel::High:   return "error";
                case SecurityLevel::Medium: return "warning";
                default:                    return "note";
            }
        };
        auto sec_name = [](SecurityLevel s) -> const char* {
            switch (s) {
                case SecurityLevel::Critical: return "Critical";
                case SecurityLevel::High:     return "High";
                case SecurityLevel::Medium:   return "Medium";
                default:                      return "Low";
            }
        };

        for (const auto& r : scan_results_) {
            const std::string rule_id =
                Core::Utils::WideToUtf8(r.module_name + L"/" + r.item_name);
            auto it = rule_index.find(rule_id);
            if (it == rule_index.end()) {
                json rule;
                rule["id"] = rule_id;
                rule["name"] = Core::Utils::WideToUtf8(r.item_name);
                rule["shortDescription"]["text"] = Core::Utils::WideToUtf8(r.item_name);
                rule["fullDescription"]["text"] = Core::Utils::WideToUtf8(r.description);
                if (!r.remediation.empty())
                    rule["help"]["text"] = Core::Utils::WideToUtf8(r.remediation);
                rule["properties"]["security-severity"] =
                    (r.risk_level == SecurityLevel::Critical) ? "9.5" :
                    (r.risk_level == SecurityLevel::High)     ? "8.0" :
                    (r.risk_level == SecurityLevel::Medium)   ? "5.0" : "3.0";
                json tags = json::array();
                for (const auto& t : ExtractTechniqueIds(r.reference)) tags.push_back(Core::Utils::WideToUtf8(t));
                if (!tags.empty()) rule["properties"]["tags"] = tags;
                rule_index[rule_id] = rules.size();
                rules.push_back(rule);
            }

            json res;
            res["ruleId"] = rule_id;
            res["level"] = sarif_level(r.risk_level);
            std::string msg = Core::Utils::WideToUtf8(r.description);
            if (!r.remediation.empty()) msg += "\nRemediation: " + Core::Utils::WideToUtf8(r.remediation);
            if (!r.reference.empty())   msg += "\nReference: " + Core::Utils::WideToUtf8(r.reference);
            res["message"]["text"] = msg;
            res["properties"]["severity"] = sec_name(r.risk_level);
            res["properties"]["module"] = Core::Utils::WideToUtf8(r.module_name);
            // A synthetic logical location keeps SARIF viewers happy without a file path.
            res["locations"] = json::array();
            json loc;
            loc["logicalLocations"] = json::array();
            json ll; ll["fullyQualifiedName"] = Core::Utils::WideToUtf8(r.module_name + L": " + r.item_name);
            loc["logicalLocations"].push_back(ll);
            res["locations"].push_back(loc);
            results.push_back(res);
        }

        run["tool"]["driver"]["rules"] = rules;
        run["results"] = results;
        root["runs"] = json::array({run});

        std::ofstream file{std::filesystem::path(filename)};
        if (!file.is_open()) { SYSRECON_LOG_ERROR(L"Failed to create SARIF file"); return false; }
        file << root.dump(2);
        SYSRECON_LOG_INFO(L"SARIF report generated successfully");
        return true;
    } catch (const std::exception& e) {
        SYSRECON_LOG_ERROR(L"Failed to generate SARIF: " + Core::Utils::Utf8ToWide(e.what()));
        return false;
    }
}

bool ReportGenerator::GenerateAttackNavigatorLayer(const String& filename) {
    SYSRECON_LOG_INFO(L"Generating ATT&CK Navigator layer...");
    try {
        // Highest severity seen per technique drives the heat colour.
        std::map<std::string, SecurityLevel> tech;
        for (const auto& r : scan_results_) {
            for (const auto& id : ExtractTechniqueIds(r.reference)) {
                const std::string t = Core::Utils::WideToUtf8(id);
                auto it = tech.find(t);
                if (it == tech.end() || r.risk_level > it->second) tech[t] = r.risk_level;
            }
        }

        json layer;
        layer["name"] = "SysRecon findings";
        layer["versions"] = { {"layer", "4.5"}, {"navigator", "4.9.1"}, {"attack", "14"} };
        layer["domain"] = "enterprise-attack";
        layer["description"] =
            "Techniques mapped from SysRecon privilege-escalation / posture findings.";
        auto colour = [](SecurityLevel s) -> const char* {
            switch (s) {
                case SecurityLevel::Critical: return "#b30000";
                case SecurityLevel::High:     return "#fd7e14";
                case SecurityLevel::Medium:   return "#ffc107";
                default:                      return "#28a745";
            }
        };
        json techniques = json::array();
        for (const auto& [id, sev] : tech) {
            json t;
            t["techniqueID"] = id;
            t["score"] = (sev == SecurityLevel::Critical) ? 100 :
                         (sev == SecurityLevel::High) ? 75 :
                         (sev == SecurityLevel::Medium) ? 50 : 25;
            t["color"] = colour(sev);
            t["enabled"] = true;
            techniques.push_back(t);
        }
        layer["techniques"] = techniques;
        layer["gradient"] = {
            {"colors", json::array({"#ffffff", "#ff6666"})}, {"minValue", 0}, {"maxValue", 100} };

        std::ofstream file{std::filesystem::path(filename)};
        if (!file.is_open()) { SYSRECON_LOG_ERROR(L"Failed to create Navigator file"); return false; }
        file << layer.dump(2);
        SYSRECON_LOG_INFO(L"ATT&CK Navigator layer generated successfully");
        return true;
    } catch (const std::exception& e) {
        SYSRECON_LOG_ERROR(L"Failed to generate Navigator layer: " + Core::Utils::Utf8ToWide(e.what()));
        return false;
    }
}

bool ReportGenerator::GenerateAllFormats(const String& base_filename) {
    bool success = true;
    success &= GenerateJSON(base_filename + L".json");
    success &= GenerateCSV(base_filename + L".csv");
    success &= GenerateHTML(base_filename + L".html");
    return success;
}

}
}
