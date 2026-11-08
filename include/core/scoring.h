#pragma once

#include "../sysrecon.h"

// Host risk score and rating (scoring model v2).
//
// v1 (<= 1.8.0) added critical*25 + high*10 + medium*4 + low and capped the sum
// at 100, so thirty Medium findings alone produced "score 100, rating Critical"
// with no Critical or High finding. v2 makes the rating the *worst effective
// tier* and keeps the score inside that tier's band, so the two can never
// disagree and a pile of lower-tier findings can never reach a higher tier.
//
//   effective tier  = severity, demoted one tier when confidence is Low
//                     (Critical->High->Medium->Low; Low stays Low), so a
//                     heuristic cannot drive a red headline.
//   T               = worst effective tier present.
//   q_i             = k[tier_i] * confidence_factor_i * w_i
//                     w_i = 1 for the first finding of a rule (CheckId),
//                     kRepeatWeight for repeats of the same rule.
//   sat             = 1 - prod(1 - q_i)                    (over all findings)
//   score           = round_half_up(floor[T] + (cap[T] - floor[T]) * sat)
//
//   tier       floor  cap   k       rating
//   Critical     85   100   0.500   Critical
//   High         60    84   0.200   High
//   Medium       30    59   0.060   Moderate
//   Low           5    29   0.015   Low
//   (nothing counts)  0                Minimal
//
// Pure arithmetic with no Win32 dependency; covered by tests/test_scoring.cpp.

namespace SysRecon {
namespace Core {
namespace Scoring {

// Bumped whenever the formula or its constants change; written to the report
// so a consumer can tell which model produced a score.
constexpr int kModelVersion = 2;
constexpr double kRepeatWeight = 0.3;

struct Entry {
    SecurityLevel severity = SecurityLevel::Low;
    Confidence confidence = Confidence::High;
    String check_id;   // Repeats of one rule are down-weighted.
};

struct Result {
    int score = 0;          // 0-100
    String rating;          // Critical | High | Moderate | Low | Minimal
    size_t counted = 0;     // Findings that contributed.
};

// The severity a finding counts as after the confidence demotion.
SecurityLevel EffectiveTier(SecurityLevel severity, Confidence confidence);

Result Compute(const std::vector<Entry>& entries);
Result Compute(const ScanResults& results);

// Rating label for a score band (kept for callers that only have the score).
String RatingForTier(SecurityLevel tier);

}
}
}
