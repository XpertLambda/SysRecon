#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

// Read-only review of the Windows event logs:
//   * log configuration -- disabled channels, logs smaller than the CIS sizes
//   * evidence of tampering and persistence within the look-back window:
//     cleared logs (1102 / 104), newly installed services (7045), accounts
//     created (4720) or added to privileged groups (4728 / 4732 / 4756),
//     failed-logon volume (4625), Defender detections and real-time
//     protection being turned off (1116 / 5001)
//
// Nothing is written, cleared or subscribed to. Reading the Security log
// needs Administrator rights; without them that check is reported as
// incomplete rather than silently skipped.
class EventLogAnalyzer {
public:
    EventLogAnalyzer();
    ~EventLogAnalyzer();

    bool Initialize();
    void Cleanup();

    void SetLookbackDays(size_t days) { lookback_days_ = days == 0 ? 1 : days; }
    void SetFailedLogonThreshold(size_t n) { failed_logon_threshold_ = n == 0 ? 1 : n; }

    bool CheckLogConfiguration();
    bool CheckLogClearing();
    bool CheckServiceInstalls();
    bool CheckAccountChanges();
    bool CheckFailedLogons();
    bool CheckDefenderEvents();

    const ScanResults& GetScanResults() const { return scan_results_; }

private:
    enum class QueryStatus { Ok, ChannelMissing, AccessDenied, Failed };

    // Runs an XPath query against `channel`, newest first, rendering up to
    // `max_events` events as XML. `truncated` is set when more matched.
    QueryStatus Query(const String& channel, const String& xpath, size_t max_events,
                      std::vector<String>& events_xml, bool& truncated);
    // "*[System[(EventID=a or EventID=b) and TimeCreated[...]]]"
    String BuildXPath(std::initializer_list<int> event_ids) const;
    String WindowLabel() const;
    bool ReportQueryFailure(const String& check, const String& channel, QueryStatus status);

    void Record(const String& item, const String& description, SecurityLevel risk,
                const StringMap& details, const String& remediation = L"",
                const String& reference = L"");

    ScanResults scan_results_;
    size_t lookback_days_ = 7;
    size_t failed_logon_threshold_ = 20;
    bool initialized_ = false;
};

} // namespace Modules
} // namespace SysRecon
