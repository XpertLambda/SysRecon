#include "../../include/core/findings.h"
#include "../../include/core/utils.h"

#include <json/json.hpp>
#include <unordered_map>

namespace SysRecon {
namespace Core {
namespace Findings {

namespace {

bool IsAsciiAlnum(wchar_t c) {
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9');
}

wchar_t LowerAscii(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
}

// Reads the next code point from `text` at `i` (advancing i), combining UTF-16
// surrogate pairs so the result is the same wherever wchar_t is 16 or 32 bits.
// A lone surrogate is returned as is.
unsigned long NextCodePoint(const String& text, size_t& i) {
    unsigned long cp = static_cast<unsigned long>(text[i]);
    ++i;
    if (cp >= 0xD800 && cp <= 0xDBFF && i < text.size()) {
        const unsigned long lo = static_cast<unsigned long>(text[i]);
        if (lo >= 0xDC00 && lo <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            ++i;
        }
    }
    return cp;
}

// "u" + lower-case hex, at least four digits.
String CodePointToken(unsigned long cp) {
    static const wchar_t* digits = L"0123456789abcdef";
    String hex;
    do {
        hex.insert(hex.begin(), digits[cp & 0xF]);
        cp >>= 4;
    } while (cp);
    while (hex.size() < 4) hex.insert(hex.begin(), L'0');
    return L"u" + hex;
}

void AppendToken(String& out, bool& pending_dash, const String& token) {
    if (!out.empty() && out.back() != L'/' && out.back() != L'*') {
        out.push_back(L'-');
    }
    out += token;
    pending_dash = true;   // Whatever follows starts a new token.
}

// Slug that keeps glob wildcards and '/', for patterns.
String SlugPattern(const String& pattern) {
    String out;
    bool pending_dash = false;
    for (size_t i = 0; i < pattern.size();) {
        if (static_cast<unsigned long>(pattern[i]) > 0x7F) {
            AppendToken(out, pending_dash, CodePointToken(NextCodePoint(pattern, i)));
            continue;
        }
        const wchar_t c = pattern[i++];
        if (IsAsciiAlnum(c)) {
            if (pending_dash && !out.empty() && out.back() != L'/' && out.back() != L'*') {
                out.push_back(L'-');
            }
            pending_dash = false;
            out.push_back(LowerAscii(c));
        } else if (c == L'*' || c == L'?' || c == L'/') {
            // A separator next to a wildcard is absorbed by it; next to '/' it
            // would never occur in an ID.
            if (pending_dash && c == L'?' && !out.empty() && out.back() != L'/' && out.back() != L'*') {
                out.push_back(L'-');
            }
            pending_dash = false;
            out.push_back(c);
        } else {
            pending_dash = true;
        }
    }
    return out;
}

}  // namespace

String Slug(const String& text) {
    String out;
    bool pending_dash = false;
    for (size_t i = 0; i < text.size();) {
        if (static_cast<unsigned long>(text[i]) > 0x7F) {
            AppendToken(out, pending_dash, CodePointToken(NextCodePoint(text, i)));
            continue;
        }
        const wchar_t c = text[i++];
        if (IsAsciiAlnum(c)) {
            if (pending_dash && !out.empty()) {
                out.push_back(L'-');
            }
            pending_dash = false;
            out.push_back(LowerAscii(c));
        } else {
            pending_dash = true;
        }
    }
    return out;
}

String FindingId(const String& module_name, const String& item_name) {
    String module = Slug(module_name);
    String item = Slug(item_name);
    if (module.empty()) module = L"unknown";
    if (item.empty()) item = L"unnamed";
    return module + L"/" + item;
}

String CheckId(const ScanResult& result) {
    return FindingId(result.module_name,
                     result.check_id.empty() ? result.item_name : result.check_id);
}

String FindingId(const ScanResult& result) {
    String id = CheckId(result);
    const String instance = Slug(result.instance_key);
    if (!instance.empty()) {
        id += L"#" + instance;
    }
    return id;
}

size_t EnsureUniqueIds(ScanResults& results) {
    std::unordered_map<String, size_t> seen;
    size_t renamed = 0;
    for (auto& r : results) {
        const String id = FindingId(r);
        const size_t n = ++seen[id];
        if (n == 1) continue;
        // Suffix until free: "dup2" could itself already exist as a real key.
        for (size_t k = n;; ++k) {
            ScanResult probe = r;
            probe.instance_key = (r.instance_key.empty() ? String() : r.instance_key + L"-") +
                                 L"dup" + std::to_wstring(k);
            const String candidate = FindingId(probe);
            if (seen.find(candidate) == seen.end()) {
                r.instance_key = probe.instance_key;
                ++seen[candidate];
                ++renamed;
                break;
            }
        }
    }
    return renamed;
}

size_t DropDuplicateFacts(ScanResults& results) {
    // Index of the survivor of each fact.
    std::unordered_map<String, size_t> keep;
    for (size_t i = 0; i < results.size(); ++i) {
        const String& key = results[i].fact_key;
        if (key.empty()) continue;
        auto it = keep.find(key);
        if (it == keep.end()) {
            keep.emplace(key, i);
        } else if (results[it->second].remediation.empty() && !results[i].remediation.empty()) {
            it->second = i;   // The richer finding replaces the earlier bare one.
        }
    }
    ScanResults out;
    out.reserve(results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        const String& key = results[i].fact_key;
        if (!key.empty() && keep[key] != i) continue;
        out.push_back(std::move(results[i]));
    }
    const size_t dropped = results.size() - out.size();
    results = std::move(out);
    return dropped;
}

bool GlobMatch(const String& pattern, const String& text) {
    // Iterative wildcard match with single-star backtracking: linear in
    // practice, no recursion on attacker-influenced item names.
    size_t p = 0, t = 0;
    size_t star = String::npos, star_t = 0;
    while (t < text.size()) {
        if (p < pattern.size() &&
            (pattern[p] == L'?' || LowerAscii(pattern[p]) == LowerAscii(text[t]))) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == L'*') {
            star = p++;
            star_t = t;
        } else if (star != String::npos) {
            p = star + 1;
            t = ++star_t;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == L'*') {
        ++p;
    }
    return p == pattern.size();
}

bool PatternSelects(const String& pattern, const String& finding_id) {
    const String slug = SlugPattern(pattern);
    if (slug.empty()) {
        return false;
    }
    if (slug.find(L'/') != String::npos) {
        return GlobMatch(slug, finding_id);
    }
    const size_t slash = finding_id.find(L'/');
    const String module = slash == String::npos ? finding_id : finding_id.substr(0, slash);
    return GlobMatch(slug, module);
}

size_t ApplyFilters(ScanResults& results, const StringVector& only, const StringVector& skip) {
    if (only.empty() && skip.empty()) {
        return 0;
    }
    const size_t before = results.size();
    results.erase(std::remove_if(results.begin(), results.end(), [&](const ScanResult& r) {
        const String id = FindingId(r);
        auto any = [&](const StringVector& patterns) {
            return std::any_of(patterns.begin(), patterns.end(),
                               [&](const String& p) { return PatternSelects(p, id); });
        };
        if (!only.empty() && !any(only)) return true;
        return any(skip);
    }), results.end());
    return before - results.size();
}

bool ParseBaseline(const std::string& json_text, Baseline& out, String& error) {
    using json = nlohmann::json;
    out.entries.clear();
    out.scan_timestamp.clear();

    json j;
    try {
        j = json::parse(json_text);
    } catch (const json::exception& e) {
        error = L"not valid JSON: " + Utils::Utf8ToWide(e.what());
        return false;
    }
    if (!j.is_object() || !j.contains("results") || !j.at("results").is_array()) {
        error = L"not a SysRecon JSON report (no \"results\" array)";
        return false;
    }
    auto str = [](const json& obj, const char* key) -> String {
        if (obj.contains(key) && obj.at(key).is_string()) {
            return Utils::Utf8ToWide(obj.at(key).get<std::string>());
        }
        return String();
    };
    if (j.contains("scan_info") && j.at("scan_info").is_object()) {
        out.scan_timestamp = str(j.at("scan_info"), "timestamp");
    }
    for (const auto& r : j.at("results")) {
        if (!r.is_object()) {
            error = L"a \"results\" entry is not an object";
            return false;
        }
        BaselineEntry e;
        e.module = str(r, "module");
        e.item = str(r, "item");
        e.risk_level = str(r, "risk_level");
        if (e.module.empty() && e.item.empty()) {
            error = L"a \"results\" entry has neither \"module\" nor \"item\"";
            return false;
        }
        e.id = str(r, "id");
        if (e.id.empty()) {
            e.id = FindingId(e.module, e.item);
        }
        out.entries.push_back(std::move(e));
    }
    return true;
}

BaselineDiff Compare(const ScanResults& current, const Baseline& baseline) {
    BaselineDiff diff;
    std::unordered_map<String, size_t> remaining;
    for (const auto& e : baseline.entries) {
        ++remaining[e.id];
    }
    diff.is_new.reserve(current.size());
    for (const auto& r : current) {
        const String id = FindingId(r);
        auto it = remaining.find(id);
        if ((it == remaining.end() || it->second == 0) && id.find(L'#') != String::npos) {
            // Reports before 1.9 knew only the rule, not its instance.
            it = remaining.find(CheckId(r));
        }
        if (it != remaining.end() && it->second > 0) {
            --it->second;
            diff.is_new.push_back(false);
            ++diff.unchanged_count;
        } else {
            diff.is_new.push_back(true);
            ++diff.new_count;
        }
    }
    // Whatever is left over in the baseline was not matched: resolved. Walk
    // the baseline in order so the report lists them as the old one did.
    for (const auto& e : baseline.entries) {
        auto it = remaining.find(e.id);
        if (it != remaining.end() && it->second > 0) {
            --it->second;
            diff.resolved.push_back(e);
        }
    }
    return diff;
}

}
}
}
