#pragma once

#include "../sysrecon.h"

// Platform-independent operations on collected findings: stable IDs,
// --only / --skip filtering, and baseline comparison (--baseline). Kept out of
// the engine so every rule is unit-tested natively.

namespace SysRecon {
namespace Core {
namespace Findings {

// Lower-case ASCII slug: letters and digits are kept, every other run of
// characters becomes a single '-', with no leading or trailing '-'.
// "Privilege Escalation" -> "privilege-escalation".
String Slug(const String& text);

// Stable identifier of a finding: "<module-slug>/<item-slug>", e.g.
// "privilege-escalation/writable-directory-on-path-c-tools". It depends only
// on the module and item names, never on the description or details, so
// counts and timestamps in a description do not change it between runs.
String FindingId(const String& module_name, const String& item_name);
String FindingId(const ScanResult& result);

// Case-insensitive glob match where '*' matches any run of characters
// (including '/') and '?' matches exactly one.
bool GlobMatch(const String& pattern, const String& text);

// True if `pattern` selects the finding with this ID. A pattern containing
// '/' is matched against the whole ID; a pattern without '/' is matched
// against the module part only, so "--skip network" drops every Network
// finding. Patterns are slugged the same way IDs are (spaces and case do not
// matter), apart from the wildcards.
bool PatternSelects(const String& pattern, const String& finding_id);

// Applies --only (keep a finding only if some pattern selects it; empty means
// keep everything) and then --skip (drop a finding if any pattern selects it).
// Returns the number of findings removed.
size_t ApplyFilters(ScanResults& results, const StringVector& only, const StringVector& skip);

// --- Baseline comparison ---------------------------------------------------

struct BaselineEntry {
    String id;
    String module;
    String item;
    String risk_level;   // As written in the report ("Critical", "High", ...)
};

struct Baseline {
    String source;                      // Path the baseline was read from.
    String scan_timestamp;              // scan_info.timestamp of that report.
    std::vector<BaselineEntry> entries;
};

// Parses a SysRecon JSON report (any version that has a "results" array of
// objects with "module" and "item") into a baseline. Reports written by 1.8+
// carry an "id" per result; older ones get it computed from module and item.
// Returns false and sets `error` if the text is not such a report.
bool ParseBaseline(const std::string& json_text, Baseline& out, String& error);

struct BaselineDiff {
    // One flag per current result, in order: true if the finding is not in
    // the baseline.
    std::vector<bool> is_new;
    size_t new_count = 0;
    size_t unchanged_count = 0;
    // Baseline findings that the current scan no longer reports.
    std::vector<BaselineEntry> resolved;
};

// Compares by finding ID as a multiset: if the baseline had two findings with
// one ID and the current scan has three, one of the three is new; if it has
// one, one baseline entry is resolved.
BaselineDiff Compare(const ScanResults& current, const Baseline& baseline);

// The detail key under which the engine records "new" / "unchanged".
inline const wchar_t* kBaselineDetailKey = L"Baseline";

}
}
}
