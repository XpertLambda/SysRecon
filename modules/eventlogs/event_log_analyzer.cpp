#include "../../include/modules/eventlogs/event_log_analyzer.h"
#include "../../include/core/utils.h"
#include "../../include/core/text_utils.h"

#ifdef _WIN32
#include <winevt.h>
#endif

#include <set>
#include <unordered_map>

namespace SysRecon {
namespace Modules {

namespace Text = Core::Text;

namespace {
// "DOMAIN\\user" -> "user"; a bare name is returned as is.
SysRecon::String AccountNameWithoutDomain(const SysRecon::String& account) {
    const size_t slash = account.rfind(L'\\');
    return slash == SysRecon::String::npos ? account : account.substr(slash + 1);
}
}  // namespace

namespace {

constexpr const wchar_t* kModule = L"Event Logs";
constexpr const wchar_t* kDefenderChannel = L"Microsoft-Windows-Windows Defender/Operational";
constexpr const wchar_t* kPowerShellChannel = L"Microsoft-Windows-PowerShell/Operational";

// Up to `limit` "key (count)" entries, most frequent first.
String TopCounts(const std::unordered_map<String, size_t>& counts, size_t limit) {
    std::vector<std::pair<String, size_t>> v(counts.begin(), counts.end());
    std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    StringVector parts;
    for (size_t i = 0; i < v.size() && i < limit; ++i) {
        parts.push_back(v[i].first + L" (" + std::to_wstring(v[i].second) + L")");
    }
    return parts.empty() ? String(L"(none)") : Core::Utils::Join(parts, L", ");
}

// "2026-11-01T10:15:30.1234567Z" -> "2026-11-01 10:15:30 UTC"
String FormatEventTime(const String& system_time) {
    if (system_time.size() < 19) return system_time;
    String t = system_time.substr(0, 19);
    t[10] = L' ';
    return t + L" UTC";
}

String EventTime(const String& xml) {
    return FormatEventTime(Text::XmlAttribute(xml, L"TimeCreated", L"SystemTime"));
}

// Text inside <UserData>, where log-cleared events keep their fields; the
// <System> block has elements with the same names (Channel, ...).
String UserDataPart(const String& xml) {
    const size_t pos = xml.find(L"<UserData");
    return pos == String::npos ? String() : xml.substr(pos);
}

String JoinUser(const String& domain, const String& user) {
    if (user.empty() || user == L"-") return L"(unknown)";
    return (domain.empty() || domain == L"-") ? user : domain + L"\\" + user;
}

}  // namespace

EventLogAnalyzer::EventLogAnalyzer() = default;
EventLogAnalyzer::~EventLogAnalyzer() { Cleanup(); }

bool EventLogAnalyzer::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Event Logs module");
    initialized_ = true;
    return true;
}

void EventLogAnalyzer::Cleanup() {
    scan_results_.clear();
    initialized_ = false;
}

void EventLogAnalyzer::Record(const String& item, const String& description, SecurityLevel risk,
                              const StringMap& details, const String& remediation,
                              const String& reference, const String& check_id,
                              const String& instance_key) {
    ScanResult r;
    r.module_name = kModule;
    r.item_name = item;
    r.check_id = check_id;
    r.instance_key = instance_key;
    r.description = description;
    r.risk_level = risk;
    r.details = details;
    r.remediation = remediation;
    r.reference = reference;
    r.timestamp = std::chrono::system_clock::now();
    scan_results_.push_back(r);
}

String EventLogAnalyzer::WindowLabel() const {
    return std::to_wstring(lookback_days_) + (lookback_days_ == 1 ? L" day" : L" days");
}

String EventLogAnalyzer::BuildXPath(std::initializer_list<int> event_ids) const {
    String ids;
    for (int id : event_ids) {
        if (!ids.empty()) ids += L" or ";
        ids += L"EventID=" + std::to_wstring(id);
    }
    const unsigned long long window_ms = static_cast<unsigned long long>(lookback_days_) * 86400000ULL;
    return L"*[System[(" + ids + L") and TimeCreated[timediff(@SystemTime) <= " +
           std::to_wstring(window_ms) + L"]]]";
}

bool EventLogAnalyzer::ReportQueryFailure(const String& check, const String& channel, QueryStatus status) {
    switch (status) {
        case QueryStatus::Ok:
            return true;
        case QueryStatus::ChannelMissing:
            // Not every SKU has every channel (Server Core without Defender).
            SYSRECON_LOG_INFO(check + L": channel not present on this system: " + channel);
            return true;
        case QueryStatus::AccessDenied:
            SYSRECON_LOG_ERROR(check + L": access denied reading the " + channel +
                               L" log (run as Administrator)");
            return false;
        case QueryStatus::Failed:
        default:
            SYSRECON_LOG_ERROR(check + L": could not query the " + channel + L" log");
            return false;
    }
}

#ifdef _WIN32

EventLogAnalyzer::QueryStatus EventLogAnalyzer::Query(const String& channel, const String& xpath,
                                                      size_t max_events, std::vector<String>& events_xml,
                                                      bool& truncated) {
    events_xml.clear();
    truncated = false;

    EVT_HANDLE query = EvtQuery(nullptr, channel.c_str(), xpath.c_str(),
                                EvtQueryChannelPath | EvtQueryReverseDirection);
    if (query == nullptr) {
        const DWORD err = GetLastError();
        SYSRECON_LOG_DEBUG(L"EvtQuery(" + channel + L") failed: " + Core::Utils::GetLastErrorString(err));
        if (err == ERROR_EVT_CHANNEL_NOT_FOUND || err == ERROR_EVT_INVALID_CHANNEL_PATH) {
            return QueryStatus::ChannelMissing;
        }
        if (err == ERROR_ACCESS_DENIED) {
            return QueryStatus::AccessDenied;
        }
        return QueryStatus::Failed;
    }

    QueryStatus status = QueryStatus::Ok;
    std::vector<wchar_t> buffer(4096);
    EVT_HANDLE batch[64];
    DWORD returned = 0;
    while (true) {
        if (!EvtNext(query, 64, batch, 10000, 0, &returned)) {
            const DWORD err = GetLastError();
            if (err != ERROR_NO_MORE_ITEMS) {
                SYSRECON_LOG_DEBUG(L"EvtNext(" + channel + L") failed: " + Core::Utils::GetLastErrorString(err));
                status = (err == ERROR_ACCESS_DENIED) ? QueryStatus::AccessDenied : QueryStatus::Failed;
            }
            break;
        }
        for (DWORD i = 0; i < returned; ++i) {
            if (events_xml.size() >= max_events) {
                truncated = true;
            } else {
                DWORD used = 0, props = 0;
                BOOL ok = EvtRender(nullptr, batch[i], EvtRenderEventXml,
                                    static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                                    buffer.data(), &used, &props);
                if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    buffer.resize(used / sizeof(wchar_t) + 1);
                    ok = EvtRender(nullptr, batch[i], EvtRenderEventXml,
                                   static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                                   buffer.data(), &used, &props);
                }
                if (ok) {
                    events_xml.emplace_back(buffer.data());
                }
            }
            EvtClose(batch[i]);
        }
        if (truncated) {
            break;
        }
    }
    EvtClose(query);
    return status;
}

namespace {

// Reads one channel-configuration property. Returns false if unavailable.
bool ChannelProperty(EVT_HANDLE channel, EVT_CHANNEL_CONFIG_PROPERTY_ID id, std::vector<BYTE>& buf,
                     PEVT_VARIANT& value) {
    DWORD used = 0;
    if (!EvtGetChannelConfigProperty(channel, id, 0, static_cast<DWORD>(buf.size()),
                                     reinterpret_cast<PEVT_VARIANT>(buf.data()), &used)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return false;
        }
        buf.resize(used);
        if (!EvtGetChannelConfigProperty(channel, id, 0, static_cast<DWORD>(buf.size()),
                                         reinterpret_cast<PEVT_VARIANT>(buf.data()), &used)) {
            return false;
        }
    }
    value = reinterpret_cast<PEVT_VARIANT>(buf.data());
    return value->Type != EvtVarTypeNull;
}

}  // namespace

bool EventLogAnalyzer::CheckLogConfiguration() {
    if (!initialized_) return false;
    SYSRECON_LOG_INFO(L"Checking event log configuration...");

    struct Channel { const wchar_t* name; SecurityLevel disabled_risk; SecurityLevel small_risk; };
    const Channel channels[] = {
        { L"Security",          SecurityLevel::High,   SecurityLevel::Medium },
        { L"System",            SecurityLevel::Medium, SecurityLevel::Low },
        { L"Application",       SecurityLevel::Medium, SecurityLevel::Low },
        { kPowerShellChannel,   SecurityLevel::Medium, SecurityLevel::Low },
    };

    bool all_ok = true;
    StringVector sizes;
    std::vector<BYTE> buf(256);
    for (const auto& c : channels) {
        EVT_HANDLE h = EvtOpenChannelConfig(nullptr, c.name, 0);
        if (h == nullptr) {
            const DWORD err = GetLastError();
            if (err == ERROR_EVT_CHANNEL_NOT_FOUND || err == ERROR_EVT_INVALID_CHANNEL_PATH) {
                continue;
            }
            SYSRECON_LOG_ERROR(String(L"Could not read the configuration of the ") + c.name +
                               L" log: " + Core::Utils::GetLastErrorString(err));
            all_ok = false;
            continue;
        }

        PEVT_VARIANT v = nullptr;
        const bool enabled = !ChannelProperty(h, EvtChannelConfigEnabled, buf, v) || v->BooleanVal != FALSE;
        uint64_t size_kb = 0;
        if (ChannelProperty(h, EvtChannelLoggingConfigMaxSize, buf, v) && v->Type == EvtVarTypeUInt64) {
            size_kb = v->UInt64Val / 1024;
        }
        bool retain = false;  // true = stop logging when full instead of overwriting
        if (ChannelProperty(h, EvtChannelLoggingConfigRetention, buf, v)) {
            retain = v->BooleanVal != FALSE;
        }
        EvtClose(h);

        // Group Policy wins over the channel's own setting, and is in KB.
        String source = L"Local setting";
        if (Text::RecommendedLogSizeKb(c.name) > 0) {
            if (auto policy = Core::Utils::TryReadRegistryDword(
                    HKEY_LOCAL_MACHINE, String(L"SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\") + c.name,
                    L"MaxSize")) {
                size_kb = *policy;
                source = L"Group Policy";
            }
        }
        sizes.push_back(String(c.name) + L": " + std::to_wstring(size_kb / 1024) + L" MB" +
                        (enabled ? L"" : L" (disabled)"));

        if (!enabled) {
            StringMap d;
            d[L"Log"] = c.name;
            d[L"Technique"] = L"T1562.002 Impair Defenses: Disable Windows Event Logging";
            Record(String(c.name) + L" log disabled",
                   String(L"The ") + c.name + L" event log is disabled, so nothing is recorded in it",
                   c.disabled_risk, d,
                   String(L"Enable the log: wevtutil sl \"") + c.name + L"\" /e:true",
                   L"T1562.002");
            continue;
        }

        const uint64_t recommended = Text::RecommendedLogSizeKb(c.name);
        if (recommended > 0 && size_kb > 0 && size_kb < recommended) {
            StringMap d;
            d[L"Log"] = c.name;
            d[L"Maximum size"] = std::to_wstring(size_kb) + L" KB";
            d[L"Recommended (CIS L1)"] = std::to_wstring(recommended) + L" KB or more";
            d[L"Source"] = source;
            d[L"When full"] = retain ? L"Stops logging" : L"Overwrites oldest events";
            const bool security = String(c.name) == L"Security";
            Record(String(c.name) + L" log size",
                   String(L"The ") + c.name + L" log holds at most " + std::to_wstring(size_kb / 1024) +
                       L" MB; older events are lost before an investigation can reach them",
                   c.small_risk, d,
                   security ? String(L"Invoke-SysReconHardening.ps1 -Include AuditPolicy (sets 192 MB), "
                                     L"and forward events to a SIEM")
                            : String(L"wevtutil sl ") + c.name + L" /ms:" +
                                  std::to_wstring(recommended * 1024),
                   L"CIS Benchmark 18.9.27");
        }
    }

    if (!sizes.empty()) {
        StringMap d;
        d[L"Logs"] = Core::Utils::Join(sizes, L"; ");
        Record(L"Event log configuration", L"Size and state of the main event logs", SecurityLevel::Low, d);
    }
    return all_ok;
}

bool EventLogAnalyzer::CheckLogClearing() {
    if (!initialized_) return false;
    SYSRECON_LOG_INFO(L"Looking for cleared event logs...");

    bool all_ok = true;
    struct Source { const wchar_t* channel; int event_id; };
    for (const Source& s : { Source{L"Security", 1102}, Source{L"System", 104} }) {
        std::vector<String> events;
        bool truncated = false;
        const QueryStatus st = Query(s.channel, BuildXPath({s.event_id}), 200, events, truncated);
        if (!ReportQueryFailure(L"Log-clearing check", s.channel, st)) {
            all_ok = false;
            continue;
        }

        // One finding per cleared log, with how often and by whom.
        struct Cleared { size_t count = 0; String last_time; std::unordered_map<String, size_t> by; };
        std::map<String, Cleared> cleared;
        for (const auto& xml : events) {
            const String user_data = UserDataPart(xml);
            String log = Text::XmlElementText(user_data, L"Channel");
            if (log.empty()) log = s.channel;
            const String who = JoinUser(Text::XmlElementText(user_data, L"SubjectDomainName"),
                                        Text::XmlElementText(user_data, L"SubjectUserName"));
            Cleared& c = cleared[log];
            if (c.count++ == 0) c.last_time = EventTime(xml);  // Newest first.
            ++c.by[who];
        }
        for (const auto& [log, c] : cleared) {
            StringMap d;
            d[L"Log"] = log;
            d[L"Times cleared"] = std::to_wstring(c.count) + (truncated ? L"+" : L"");
            d[L"Most recent"] = c.last_time;
            d[L"Cleared by"] = TopCounts(c.by, 5);
            d[L"Event ID"] = std::to_wstring(s.event_id) + L" (" + s.channel + L" log)";
            d[L"Technique"] = L"T1070.001 Indicator Removal: Clear Windows Event Logs";
            Record(L"Event log cleared: " + log,
                   L"The " + log + L" log was cleared in the last " + WindowLabel() +
                       L"; clearing logs is a common step to hide an intrusion",
                   SecurityLevel::High, d,
                   L"Confirm who cleared the log and why. Forward events to a SIEM so a local clear "
                   L"does not destroy them.",
                   L"T1070.001");
        }
    }
    return all_ok;
}

bool EventLogAnalyzer::CheckServiceInstalls() {
    if (!initialized_) return false;
    SYSRECON_LOG_INFO(L"Reviewing recently installed services...");

    std::vector<String> events;
    bool truncated = false;
    const QueryStatus st = Query(L"System", BuildXPath({7045}), 500, events, truncated);
    if (st != QueryStatus::Ok) {
        return ReportQueryFailure(L"Service-install check", L"System", st);
    }

    std::map<String, size_t> benign;     // service name -> times installed
    std::set<String> reported;
    for (const auto& xml : events) {
        const String name = Text::EventDataValue(xml, L"ServiceName");
        const String image = Text::EventDataValue(xml, L"ImagePath");
        const int severity = Text::ServiceInstallSeverity(image);
        if (severity < 2) {
            ++benign[name.empty() ? L"(unnamed)" : name];
            continue;
        }
        if (!reported.insert(name + L"|" + image).second) {
            continue;  // Same service re-installed: newest event already reported.
        }
        StringMap d;
        d[L"Service"] = name;
        d[L"Image Path"] = image;
        d[L"Account"] = Text::EventDataValue(xml, L"AccountName");
        d[L"Start Type"] = Text::EventDataValue(xml, L"StartType");
        d[L"Installed"] = EventTime(xml);
        d[L"Event ID"] = L"7045 (System log)";
        const bool shell = severity >= 3;
        d[L"Technique"] = shell ? L"T1569.002 System Services: Service Execution"
                                : L"T1543.003 Create or Modify System Process: Windows Service";
        Record(L"Service installed: " + name,
               shell ? L"A service was installed that runs a command interpreter or script host directly, "
                       L"the pattern used by PsExec-style lateral movement and Metasploit"
                     : L"A service was installed whose binary is in a user-writable location or on a network share",
               shell ? SecurityLevel::High : SecurityLevel::Medium, d,
               L"Confirm the service is expected. If not, stop and delete it (sc.exe delete) and "
               L"investigate the account that installed it.",
               shell ? L"T1569.002" : L"T1543.003");
    }

    StringMap d;
    StringVector names;
    size_t total = 0;
    for (const auto& [name, count] : benign) {
        total += count;
        if (names.size() < 30) names.push_back(count > 1 ? name + L" (x" + std::to_wstring(count) + L")" : name);
    }
    d[L"Services"] = names.empty() ? String(L"(none)") : Core::Utils::Join(names, L", ");
    if (benign.size() > names.size()) {
        d[L"Services"] += L", ... (" + std::to_wstring(benign.size() - names.size()) + L" more)";
    }
    Record(L"Services installed recently",
           std::to_wstring(total) + (truncated ? L"+" : L"") + L" service installation(s) from standard "
               L"locations in the last " + WindowLabel(),
           SecurityLevel::Low, d);
    return true;
}

bool EventLogAnalyzer::CheckAccountChanges() {
    if (!initialized_) return false;
    SYSRECON_LOG_INFO(L"Reviewing account creation and privileged group changes...");

    std::vector<String> events;
    bool truncated = false;
    const QueryStatus st = Query(L"Security", BuildXPath({4720, 4728, 4732, 4756}), 1000, events, truncated);
    if (st != QueryStatus::Ok) {
        return ReportQueryFailure(L"Account-change check", L"Security", st);
    }

    struct Change { size_t count = 0; String last_time; String by; StringMap extra; };
    std::map<String, Change> created;        // account
    std::map<String, Change> added;          // group|member
    for (const auto& xml : events) {
        const String id = Text::XmlElementText(xml, L"EventID");
        const String by = JoinUser(Text::EventDataValue(xml, L"SubjectDomainName"),
                                   Text::EventDataValue(xml, L"SubjectUserName"));
        if (id == L"4720") {
            const String account = JoinUser(Text::EventDataValue(xml, L"TargetDomainName"),
                                            Text::EventDataValue(xml, L"TargetUserName"));
            Change& c = created[account];
            if (c.count++ == 0) {
                c.last_time = EventTime(xml);
                c.by = by;
                c.extra[L"SID"] = Text::EventDataValue(xml, L"TargetSid");
            }
            continue;
        }
        const String group_sid = Text::EventDataValue(xml, L"TargetSid");
        if (!Text::IsPrivilegedGroupSid(group_sid)) {
            continue;
        }
        const String group = JoinUser(Text::EventDataValue(xml, L"TargetDomainName"),
                                      Text::EventDataValue(xml, L"TargetUserName"));
        String member = Text::EventDataValue(xml, L"MemberName");
        const String member_sid = Text::EventDataValue(xml, L"MemberSid");
        if (member.empty() || member == L"-") {
            member = Core::Utils::SidStringToAccountName(member_sid);
        }
        Change& c = added[group + L"|" + member];
        if (c.count++ == 0) {
            c.last_time = EventTime(xml);
            c.by = by;
            c.extra[L"Group"] = group;
            c.extra[L"Group SID"] = group_sid;
            c.extra[L"Member"] = member;
            c.extra[L"Member SID"] = member_sid;
        }
    }

    for (const auto& [account, c] : created) {
        StringMap d = c.extra;
        d[L"Account"] = account;
        d[L"Created"] = c.last_time;
        d[L"Created by"] = c.by;
        d[L"Event ID"] = L"4720 (Security log)";
        d[L"Technique"] = L"T1136.001 Create Account: Local Account";
        Record(L"Account created: " + account,
               L"A user account was created in the last " + WindowLabel(),
               SecurityLevel::Medium, d,
               L"Confirm the account was created by an authorised administrator for a known purpose; "
               L"disable it otherwise.",
               L"T1136.001",
               // Identity: the rule plus the account name without its domain, which for a
               // local account is the name of the machine it was created on (a hostname
               // changes on rename / re-image and would change the ID with it).
               L"Account created", AccountNameWithoutDomain(account));
    }
    for (const auto& [key, c] : added) {
        StringMap d = c.extra;
        d[L"Times added"] = std::to_wstring(c.count);
        d[L"Most recent"] = c.last_time;
        d[L"Added by"] = c.by;
        d[L"Event ID"] = L"4728 / 4732 / 4756 (Security log)";
        d[L"Technique"] = L"T1098 Account Manipulation";
        const String member = c.extra.at(L"Member");
        const String group = c.extra.at(L"Group");
        Record(L"Added to " + group + L": " + member,
               L"An account was added to a privileged group in the last " + WindowLabel(),
               SecurityLevel::High, d,
               L"Confirm the membership change was authorised; remove the member otherwise and review "
               L"what the account did since.",
               L"T1098",
               // The group's SID is the same on every host for built-in groups
               // (S-1-5-32-544 is Administrators); the member is its bare name.
               L"Added to privileged group",
               c.extra.at(L"Group SID") + L"-" + AccountNameWithoutDomain(member));
    }
    if (truncated) {
        SYSRECON_LOG_WARNING(L"Account-change check: more than 1000 events; only the newest were reviewed");
    }
    return true;
}

bool EventLogAnalyzer::CheckFailedLogons() {
    if (!initialized_) return false;
    SYSRECON_LOG_INFO(L"Counting failed logons...");

    std::vector<String> events;
    bool truncated = false;
    const size_t cap = 5000;
    const QueryStatus st = Query(L"Security", BuildXPath({4625}), cap, events, truncated);
    if (st != QueryStatus::Ok) {
        return ReportQueryFailure(L"Failed-logon check", L"Security", st);
    }

    std::unordered_map<String, size_t> accounts, sources;
    for (const auto& xml : events) {
        ++accounts[JoinUser(Text::EventDataValue(xml, L"TargetDomainName"),
                            Text::EventDataValue(xml, L"TargetUserName"))];
        String ip = Text::EventDataValue(xml, L"IpAddress");
        if (ip.empty() || ip == L"-") ip = L"(local)";
        ++sources[ip];
    }

    const size_t n = events.size();
    StringMap d;
    d[L"Failed logons"] = std::to_wstring(n) + (truncated ? L"+" : L"");
    d[L"Threshold"] = std::to_wstring(failed_logon_threshold_);
    d[L"Top accounts"] = TopCounts(accounts, 5);
    d[L"Top sources"] = TopCounts(sources, 5);
    d[L"Event ID"] = L"4625 (Security log)";
    if (n >= failed_logon_threshold_) {
        d[L"Technique"] = L"T1110 Brute Force";
        Record(L"Failed logons",
               std::to_wstring(n) + (truncated ? L"+" : L"") + L" failed logons in the last " + WindowLabel() +
                   L", at or above the threshold of " + std::to_wstring(failed_logon_threshold_),
               (n >= failed_logon_threshold_ * 10) ? SecurityLevel::High : SecurityLevel::Medium, d,
               L"Check the top sources and accounts. Block abusive sources, require strong passwords and "
               L"an account lockout policy (Invoke-SysReconHardening.ps1 -Include AccountPolicy).",
               L"T1110");
    } else {
        Record(L"Failed logons",
               std::to_wstring(n) + L" failed logons in the last " + WindowLabel() + L" (below the threshold)",
               SecurityLevel::Low, d);
    }
    return true;
}

bool EventLogAnalyzer::CheckDefenderEvents() {
    if (!initialized_) return false;
    SYSRECON_LOG_INFO(L"Reviewing Microsoft Defender events...");

    std::vector<String> events;
    bool truncated = false;
    const QueryStatus st = Query(kDefenderChannel, BuildXPath({1116, 5001}), 500, events, truncated);
    if (st != QueryStatus::Ok) {
        return ReportQueryFailure(L"Defender event check", kDefenderChannel, st);
    }

    struct Detection { size_t count = 0; String last_time; StringMap d; };
    std::map<String, Detection> threats;
    size_t rtp_off = 0;
    String rtp_last;
    for (const auto& xml : events) {
        const String id = Text::XmlElementText(xml, L"EventID");
        if (id == L"5001") {
            if (rtp_off++ == 0) rtp_last = EventTime(xml);
            continue;
        }
        const String threat = Text::EventDataValue(xml, L"Threat Name");
        const String path = Text::EventDataValue(xml, L"Path");
        Detection& t = threats[threat.empty() ? String(L"(unnamed threat)") : threat];
        if (t.count++ == 0) {
            t.last_time = EventTime(xml);
            t.d[L"Path"] = path;
            t.d[L"Severity"] = Text::EventDataValue(xml, L"Severity Name");
            t.d[L"Detection user"] = Text::EventDataValue(xml, L"Detection User");
            t.d[L"Process"] = Text::EventDataValue(xml, L"Process Name");
        }
    }

    for (const auto& [name, t] : threats) {
        StringMap d = t.d;
        d[L"Threat"] = name;
        d[L"Detections"] = std::to_wstring(t.count);
        d[L"Most recent"] = t.last_time;
        d[L"Event ID"] = L"1116 (Defender Operational log)";
        Record(L"Defender detection: " + name,
               L"Microsoft Defender detected malware or a potentially unwanted program in the last " +
                   WindowLabel(),
               SecurityLevel::High, d,
               L"Confirm Defender remediated the threat (Get-MpThreatDetection) and investigate how it "
               L"arrived; a detection means something got onto the host.",
               L"Microsoft Defender");
    }
    if (rtp_off > 0) {
        StringMap d;
        d[L"Times disabled"] = std::to_wstring(rtp_off);
        d[L"Most recent"] = rtp_last;
        d[L"Event ID"] = L"5001 (Defender Operational log)";
        d[L"Technique"] = L"T1562.001 Impair Defenses: Disable or Modify Tools";
        Record(L"Defender real-time protection disabled",
               L"Microsoft Defender real-time protection was turned off in the last " + WindowLabel(),
               SecurityLevel::High, d,
               L"Confirm who disabled it and why; turn on Tamper Protection so it cannot be switched off "
               L"locally (Invoke-SysReconHardening.ps1 -Include Defender).",
               L"T1562.001");
    }
    return true;
}

#else  // !_WIN32

EventLogAnalyzer::QueryStatus EventLogAnalyzer::Query(const String&, const String&, size_t,
                                                      std::vector<String>& events_xml, bool& truncated) {
    events_xml.clear();
    truncated = false;
    return QueryStatus::Failed;
}
bool EventLogAnalyzer::CheckLogConfiguration() { return false; }
bool EventLogAnalyzer::CheckLogClearing() { return false; }
bool EventLogAnalyzer::CheckServiceInstalls() { return false; }
bool EventLogAnalyzer::CheckAccountChanges() { return false; }
bool EventLogAnalyzer::CheckFailedLogons() { return false; }
bool EventLogAnalyzer::CheckDefenderEvents() { return false; }

#endif

} // namespace Modules
} // namespace SysRecon
