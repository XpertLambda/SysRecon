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

// Slug that keeps glob wildcards and '/', for patterns.
String SlugPattern(const String& pattern) {
    String out;
    bool pending_dash = false;
    for (wchar_t c : pattern) {
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
    for (wchar_t c : text) {
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

String FindingId(const ScanResult& result) {
    return FindingId(result.module_name, result.item_name);
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
        auto it = remaining.find(FindingId(r));
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
