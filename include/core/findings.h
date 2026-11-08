#pragma once

#include "../sysrecon.h"

// Platform-independent operations on collected findings: stable IDs,
// --only / --skip filtering, and baseline comparison (--baseline). Kept out of
// the engine so every rule is unit-tested natively.

namespace SysRecon {
namespace Core {
namespace Findings {

// Lower-case ASCII slug: ASCII letters and digits are kept, every other run of
// punctuation/whitespace becomes a single '-', with no leading or trailing
// '-'. "Privilege Escalation" -> "privilege-escalation".
// A non-ASCII character is never discarded (that made distinct names collide,
// and an all-non-ASCII name vanish): it becomes its own token "uXXXX" (code
// point in lower-case hex, at least four digits), so "Benutzer \u00fcber" ->
// "benutzer-u00fc-ber". Identical on every platform (UTF-16 surrogate pairs are
// combined into one code point first).
String Slug(const String& text);

// Stable identifier of a finding. Findings are identified by the rule that
// produced them plus, where one rule can fire several times, the object it
// fired on:
//     "<module-slug>/<check-slug>"                 one instance per scan
//     "<module-slug>/<check-slug>#<instance-slug>" several instances
// The check part is ScanResult::check_id when set, else the item name; the
// instance part is ScanResult::instance_key. It depends on nothing else, so
// counts, timestamps and descriptions never change it between runs, and rules
// that supply an instance_key never put the machine's own name in the ID.
// Findings without check_id/instance_key keep the 1.8.0 ID
// ("<module-slug>/<item-slug>"), so 1.8 baselines still compare.
String FindingId(const String& module_name, const String& item_name);
String FindingId(const ScanResult& result);

// The rule part of the ID: "<module-slug>/<check-slug>" (no instance). Scoring
// uses it to down-weight repeats of one rule.
String CheckId(const ScanResult& result);

// Makes every ID in `results` unique, deterministically (by order). The second
// and later finding with an ID already seen gets "dupN" appended to its
// instance_key. A rule that fires several times should set instance_key
// itself; this is the safety net, and the number returned (how many findings
// had to be renamed) lets the engine log a warning and tests assert zero.
size_t EnsureUniqueIds(ScanResults& results);

// Collapses findings that report the same underlying fact (equal, non-empty
// fact_key) to one, so a value read by two modules is not counted twice. Keeps
// the most useful of each group (one that carries remediation, then the
// earliest), preserves the order of the survivors, and returns how many were
// dropped.
size_t DropDuplicateFacts(ScanResults& results);

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
// one, one baseline entry is resolved. A current finding whose ID has an
// instance part ("rule#instance") that the baseline does not know also matches
// a baseline entry carrying just the rule ID, because reports before 1.9
// identified every instance of a rule by the rule alone.
BaselineDiff Compare(const ScanResults& current, const Baseline& baseline);

// The detail key under which the engine records "new" / "unchanged".
inline const wchar_t* kBaselineDetailKey = L"Baseline";

}
}
}
