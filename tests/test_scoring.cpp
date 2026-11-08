#include <gtest/gtest.h>
#include <random>

#include "core/scoring.h"

using namespace SysRecon;
using namespace SysRecon::Core::Scoring;

namespace {

Entry E(SecurityLevel s, Confidence c = Confidence::High, const String& check = L"") {
    static int counter = 0;
    // Distinct check by default, so the repeat down-weighting only applies when asked for.
    return {s, c, check.empty() ? L"check-" + std::to_wstring(counter++) : check};
}

std::vector<Entry> Many(SecurityLevel s, int n) {
    std::vector<Entry> v;
    for (int i = 0; i < n; ++i) v.push_back(E(s));
    return v;
}

}  // namespace

TEST(Scoring, NothingIsMinimal) {
    const Result r = Compute(std::vector<Entry>{});
    EXPECT_EQ(r.score, 0);
    EXPECT_EQ(r.rating, L"Minimal");
}

TEST(Scoring, ReferenceValuesFromTheDesign) {
    EXPECT_EQ(Compute({E(SecurityLevel::High)}).score, 65);
    EXPECT_EQ(Compute({E(SecurityLevel::Critical)}).score, 93);
    EXPECT_EQ(Compute({E(SecurityLevel::Medium)}).score, 32);
    EXPECT_EQ(Compute({E(SecurityLevel::Low)}).score, 5);
    EXPECT_EQ(Compute({E(SecurityLevel::Critical)}).rating, L"Critical");
    EXPECT_EQ(Compute({E(SecurityLevel::High)}).rating, L"High");
    EXPECT_EQ(Compute({E(SecurityLevel::Medium)}).rating, L"Moderate");
    EXPECT_EQ(Compute({E(SecurityLevel::Low)}).rating, L"Low");
}

// BUG-001: a Windows 11 scan with 0 Critical, 7 High, 33 Medium, 31 Low was
// reported as "score 100, Critical".
TEST(Scoring, Bug001_ManyLowerTiersNeverBecomeCritical) {
    std::vector<Entry> v;
    for (auto s : {std::make_pair(SecurityLevel::High, 7), std::make_pair(SecurityLevel::Medium, 33),
                   std::make_pair(SecurityLevel::Low, 31)}) {
        auto part = Many(s.first, s.second);
        v.insert(v.end(), part.begin(), part.end());
    }
    const Result r = Compute(v);
    EXPECT_EQ(r.rating, L"High");
    EXPECT_EQ(r.score, 84);
    EXPECT_LT(r.score, 100);
}

TEST(Scoring, ThousandsOfMediumsStayModerate) {
    const Result r = Compute(Many(SecurityLevel::Medium, 1000));
    EXPECT_EQ(r.rating, L"Moderate");
    EXPECT_EQ(r.score, 59);
}

TEST(Scoring, ThousandsOfLowsStayLow) {
    const Result r = Compute(Many(SecurityLevel::Low, 5000));
    EXPECT_EQ(r.rating, L"Low");
    EXPECT_LE(r.score, 29);
}

TEST(Scoring, LowConfidenceDemotesOneTier) {
    EXPECT_EQ(EffectiveTier(SecurityLevel::Critical, Confidence::Low), SecurityLevel::High);
    EXPECT_EQ(EffectiveTier(SecurityLevel::High, Confidence::Low), SecurityLevel::Medium);
    EXPECT_EQ(EffectiveTier(SecurityLevel::Medium, Confidence::Low), SecurityLevel::Low);
    EXPECT_EQ(EffectiveTier(SecurityLevel::Low, Confidence::Low), SecurityLevel::Low);
    EXPECT_EQ(EffectiveTier(SecurityLevel::High, Confidence::Medium), SecurityLevel::High);
    // A heuristic Critical cannot make the headline Critical.
    EXPECT_EQ(Compute({E(SecurityLevel::Critical, Confidence::Low)}).rating, L"High");
}

TEST(Scoring, RepeatsOfOneRuleCountLess) {
    const int six_distinct = Compute(Many(SecurityLevel::Medium, 6)).score;
    std::vector<Entry> same;
    for (int i = 0; i < 6; ++i) same.push_back(E(SecurityLevel::Medium, Confidence::High, L"one-rule"));
    EXPECT_LT(Compute(same).score, six_distinct);
}

TEST(Scoring, RatingAndScoreAlwaysAgreeAndAreMonotone) {
    std::mt19937 rng(12345);
    for (int round = 0; round < 3000; ++round) {
        std::vector<Entry> v;
        const int n = rng() % 60;
        int previous = 0;
        for (int i = 0; i < n; ++i) {
            const auto sev = static_cast<SecurityLevel>(rng() % 4);
            const auto conf = static_cast<Confidence>(rng() % 3);
            v.push_back(E(sev, conf, (rng() % 4 == 0) ? L"shared" : L""));
            const Result r = Compute(v);

            // Never decreases when a finding is added.
            ASSERT_GE(r.score, previous);
            previous = r.score;

            // The rating is the band of the score.
            int lo = 0, hi = 100;
            if (r.rating == L"Critical")      { lo = 85; hi = 100; }
            else if (r.rating == L"High")     { lo = 60; hi = 84; }
            else if (r.rating == L"Moderate") { lo = 30; hi = 59; }
            else if (r.rating == L"Low")      { lo = 5;  hi = 29; }
            ASSERT_GE(r.score, lo);
            ASSERT_LE(r.score, hi);
            ASSERT_LE(r.score, 100);
        }
        // No counted Critical (after demotion) means no Critical rating, no
        // counted High means no score >= 60.
        bool crit = false, high = false;
        for (const auto& e : v) {
            const auto t = EffectiveTier(e.severity, e.confidence);
            crit |= t == SecurityLevel::Critical;
            high |= t == SecurityLevel::High;
        }
        const Result r = Compute(v);
        if (!crit) { EXPECT_NE(r.rating, L"Critical"); }
        if (!crit && !high) { EXPECT_LE(r.score, 59); }
    }
}
