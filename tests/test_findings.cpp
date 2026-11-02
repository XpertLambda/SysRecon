#include <gtest/gtest.h>

#include "core/findings.h"

using namespace SysRecon;
using namespace SysRecon::Core::Findings;

namespace {

ScanResult Make(const String& module, const String& item, SecurityLevel level = SecurityLevel::High,
                const String& description = L"d") {
    ScanResult r;
    r.module_name = module;
    r.item_name = item;
    r.description = description;
    r.risk_level = level;
    return r;
}

}  // namespace

TEST(Findings, SlugCollapsesSeparatorsAndLowercases) {
    EXPECT_EQ(Slug(L"Privilege Escalation"), L"privilege-escalation");
    EXPECT_EQ(Slug(L"  Writable directory on PATH: C:\\Tools\\ "), L"writable-directory-on-path-c-tools");
    EXPECT_EQ(Slug(L"TCP 445 (System)"), L"tcp-445-system");
    EXPECT_EQ(Slug(L"---"), L"");
    // Non-ASCII letters are separators: IDs stay ASCII.
    EXPECT_EQ(Slug(L"Benutzer \u00fcber"), L"benutzer-ber");
}

TEST(Findings, FindingIdDependsOnlyOnModuleAndItem) {
    const ScanResult a = Make(L"Network", L"Listening TCP ports", SecurityLevel::Low, L"12 TCP ports");
    const ScanResult b = Make(L"Network", L"Listening TCP ports", SecurityLevel::Low, L"13 TCP ports");
    EXPECT_EQ(FindingId(a), L"network/listening-tcp-ports");
    EXPECT_EQ(FindingId(a), FindingId(b));
    EXPECT_EQ(FindingId(L"", L""), L"unknown/unnamed");
}

TEST(Findings, GlobMatch) {
    EXPECT_TRUE(GlobMatch(L"network/*", L"network/listening-tcp-ports"));
    EXPECT_TRUE(GlobMatch(L"*", L""));
    EXPECT_TRUE(GlobMatch(L"*tcp*", L"network/tcp-445-system"));
    EXPECT_TRUE(GlobMatch(L"tcp-44?-system", L"tcp-445-system"));
    EXPECT_TRUE(GlobMatch(L"NETWORK/*", L"network/x"));
    EXPECT_FALSE(GlobMatch(L"network/*", L"firewall/x"));
    EXPECT_FALSE(GlobMatch(L"tcp-44?", L"tcp-4455"));
    EXPECT_TRUE(GlobMatch(L"a*b*c", L"axxbyyc"));
    EXPECT_FALSE(GlobMatch(L"a*b*c", L"axxbyy"));
}

TEST(Findings, PatternWithoutSlashSelectsModule) {
    const String id = L"user-accounts/runneradmin";
    EXPECT_TRUE(PatternSelects(L"user-accounts", id));
    EXPECT_TRUE(PatternSelects(L"User Accounts", id));
    EXPECT_TRUE(PatternSelects(L"user*", id));
    // Matches the module only, never the item.
    EXPECT_FALSE(PatternSelects(L"runneradmin", id));
    EXPECT_FALSE(PatternSelects(L"user", id));
}

TEST(Findings, PatternWithSlashSelectsWholeId) {
    const String id = L"privilege-escalation/writable-directory-on-path-c-tools";
    EXPECT_TRUE(PatternSelects(L"privilege-escalation/writable-directory-on-path*", id));
    EXPECT_TRUE(PatternSelects(L"Privilege Escalation/Writable directory on PATH*", id));
    EXPECT_TRUE(PatternSelects(L"*/writable-directory*", id));
    EXPECT_FALSE(PatternSelects(L"privilege-escalation/unquoted*", id));
    EXPECT_FALSE(PatternSelects(L"", id));
    EXPECT_FALSE(PatternSelects(L"   ", id));
}

TEST(Findings, ApplyFiltersOnlyThenSkip) {
    ScanResults results = {
        Make(L"User Accounts", L"runneradmin"),
        Make(L"Account Policy", L"Minimum password length"),
        Make(L"Network", L"TCP 445 (System)"),
        Make(L"Firewall", L"Public firewall profile"),
    };
    ScanResults only = results;
    EXPECT_EQ(ApplyFilters(only, {L"user-accounts", L"account-policy"}, {}), 2u);
    ASSERT_EQ(only.size(), 2u);
    EXPECT_EQ(only[0].module_name, L"User Accounts");

    ScanResults skip = results;
    EXPECT_EQ(ApplyFilters(skip, {}, {L"network", L"firewall/*"}), 2u);
    ASSERT_EQ(skip.size(), 2u);
    EXPECT_EQ(skip[1].module_name, L"Account Policy");

    ScanResults both = results;
    EXPECT_EQ(ApplyFilters(both, {L"*account*"}, {L"user-accounts/runneradmin"}), 3u);
    ASSERT_EQ(both.size(), 1u);
    EXPECT_EQ(both[0].item_name, L"Minimum password length");

    ScanResults none = results;
    EXPECT_EQ(ApplyFilters(none, {}, {}), 0u);
    EXPECT_EQ(none.size(), results.size());
}

TEST(Findings, ParseBaselineReadsReportsWithAndWithoutIds) {
    const std::string report = R"json({
        "scan_info": {"timestamp": "20261102_101500", "version": "1.7.1"},
        "results": [
            {"module": "Network", "item": "TCP 445 (System)", "risk_level": "Medium"},
            {"id": "custom/id", "module": "X", "item": "Y", "risk_level": "Low"}
        ]
    })json";
    Baseline b;
    String error;
    ASSERT_TRUE(ParseBaseline(report, b, error));
    EXPECT_EQ(b.scan_timestamp, L"20261102_101500");
    ASSERT_EQ(b.entries.size(), 2u);
    EXPECT_EQ(b.entries[0].id, L"network/tcp-445-system");
    EXPECT_EQ(b.entries[0].risk_level, L"Medium");
    EXPECT_EQ(b.entries[1].id, L"custom/id");
}

TEST(Findings, ParseBaselineRejectsNonReports) {
    Baseline b;
    String error;
    EXPECT_FALSE(ParseBaseline("not json", b, error));
    EXPECT_FALSE(error.empty());
    EXPECT_FALSE(ParseBaseline(R"({"general": {}})", b, error));
    EXPECT_FALSE(ParseBaseline(R"({"results": [42]})", b, error));
    EXPECT_FALSE(ParseBaseline(R"({"results": [{"risk_level": "Low"}]})", b, error));
    EXPECT_TRUE(ParseBaseline(R"({"results": []})", b, error));
    EXPECT_TRUE(b.entries.empty());
}

TEST(Findings, CompareIsAMultisetDiff) {
    Baseline b;
    for (const auto& [m, i] : std::vector<std::pair<String, String>>{
             {L"Network", L"TCP 445 (System)"},
             {L"Privilege Escalation", L"Writable directory on PATH"},
             {L"Privilege Escalation", L"Writable directory on PATH"},
             {L"Firewall", L"Public firewall profile"}}) {
        b.entries.push_back({FindingId(m, i), m, i, L"High"});
    }
    const ScanResults current = {
        Make(L"Network", L"TCP 445 (System)", SecurityLevel::Medium, L"changed text"),
        Make(L"Privilege Escalation", L"Writable directory on PATH"),
        Make(L"Event Logs", L"Security log cleared"),
    };
    const BaselineDiff d = Compare(current, b);
    ASSERT_EQ(d.is_new.size(), 3u);
    EXPECT_FALSE(d.is_new[0]);
    EXPECT_FALSE(d.is_new[1]);
    EXPECT_TRUE(d.is_new[2]);
    EXPECT_EQ(d.new_count, 1u);
    EXPECT_EQ(d.unchanged_count, 2u);
    ASSERT_EQ(d.resolved.size(), 2u);
    EXPECT_EQ(d.resolved[0].item, L"Writable directory on PATH");
    EXPECT_EQ(d.resolved[1].module, L"Firewall");
}

TEST(Findings, CompareAgainstEmptyBaselineMarksEverythingNew) {
    const ScanResults current = {Make(L"A", L"1"), Make(L"A", L"1")};
    const BaselineDiff d = Compare(current, Baseline{});
    EXPECT_EQ(d.new_count, 2u);
    EXPECT_EQ(d.unchanged_count, 0u);
    EXPECT_TRUE(d.resolved.empty());
}
