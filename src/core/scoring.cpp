#include "../../include/core/scoring.h"
#include "../../include/core/findings.h"

#include <cmath>
#include <unordered_map>

namespace SysRecon {
namespace Core {
namespace Scoring {

namespace {

struct Band { double floor; double cap; double k; };

Band BandFor(SecurityLevel tier) {
    switch (tier) {
        case SecurityLevel::Critical: return {85, 100, 0.500};
        case SecurityLevel::High:     return {60,  84, 0.200};
        case SecurityLevel::Medium:   return {30,  59, 0.060};
        case SecurityLevel::Low:      return { 5,  29, 0.015};
    }
    return {5, 29, 0.015};
}

double ConfidenceFactor(Confidence c) {
    switch (c) {
        case Confidence::High:   return 1.0;
        case Confidence::Medium: return 0.75;
        case Confidence::Low:    return 0.5;
    }
    return 1.0;
}

}  // namespace

SecurityLevel EffectiveTier(SecurityLevel severity, Confidence confidence) {
    if (confidence != Confidence::Low) return severity;
    switch (severity) {
        case SecurityLevel::Critical: return SecurityLevel::High;
        case SecurityLevel::High:     return SecurityLevel::Medium;
        case SecurityLevel::Medium:   return SecurityLevel::Low;
        case SecurityLevel::Low:      return SecurityLevel::Low;
    }
    return severity;
}

String RatingForTier(SecurityLevel tier) {
    switch (tier) {
        case SecurityLevel::Critical: return L"Critical";
        case SecurityLevel::High:     return L"High";
        case SecurityLevel::Medium:   return L"Moderate";
        case SecurityLevel::Low:      return L"Low";
    }
    return L"Low";
}

Result Compute(const std::vector<Entry>& entries) {
    Result result;
    if (entries.empty()) {
        result.rating = L"Minimal";
        return result;
    }

    int worst = -1;                       // Highest SecurityLevel value present.
    double survive = 1.0;                 // prod(1 - q_i)
    std::unordered_map<String, size_t> seen;
    for (const auto& e : entries) {
        const SecurityLevel tier = EffectiveTier(e.severity, e.confidence);
        worst = std::max(worst, static_cast<int>(tier));
        const bool repeat = seen[e.check_id]++ > 0;
        const double q = BandFor(tier).k * ConfidenceFactor(e.confidence) *
                         (repeat ? kRepeatWeight : 1.0);
        survive *= (1.0 - q);
        ++result.counted;
    }

    const SecurityLevel top = static_cast<SecurityLevel>(worst);
    const Band band = BandFor(top);
    const double sat = 1.0 - survive;
    double score = band.floor + (band.cap - band.floor) * sat;
    // Round half up, then clamp into the band (guards float noise at the cap).
    int rounded = static_cast<int>(std::floor(score + 0.5));
    rounded = std::max(static_cast<int>(band.floor), std::min(static_cast<int>(band.cap), rounded));
    result.score = rounded;
    result.rating = RatingForTier(top);
    return result;
}

Result Compute(const ScanResults& results) {
    std::vector<Entry> entries;
    entries.reserve(results.size());
    for (const auto& r : results) {
        entries.push_back({r.risk_level, r.confidence, Findings::CheckId(r)});
    }
    return Compute(entries);
}

}
}
}
