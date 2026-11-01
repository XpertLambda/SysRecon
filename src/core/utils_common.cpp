// Portable half of Core::Utils. Part of sysrecon_core: must not depend on
// Win32, so it is compiled and unit-tested natively.

#include "../../include/core/utils.h"
#include "../../include/core/text_utils.h"

#include <cwctype>

namespace SysRecon {
namespace Core {
namespace Utils {

namespace {

constexpr uint32_t kReplacement = 0xFFFD;

void AppendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

void AppendWide(String& out, uint32_t cp) {
    if constexpr (sizeof(wchar_t) == 2) {
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out += static_cast<wchar_t>(0xD800 + (cp >> 10));
            out += static_cast<wchar_t>(0xDC00 + (cp & 0x3FF));
            return;
        }
    }
    out += static_cast<wchar_t>(cp);
}

}  // namespace

std::string WideToUtf8(const String& wide_str) {
    std::string out;
    out.reserve(wide_str.size());
    for (size_t i = 0; i < wide_str.size(); ++i) {
        uint32_t cp = static_cast<uint32_t>(wide_str[i]);
        if constexpr (sizeof(wchar_t) == 2) {
            cp &= 0xFFFF;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                const uint32_t lo = (i + 1 < wide_str.size())
                                        ? (static_cast<uint32_t>(wide_str[i + 1]) & 0xFFFF)
                                        : 0;
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    ++i;
                } else {
                    cp = kReplacement;  // Unpaired high surrogate.
                }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                cp = kReplacement;      // Unpaired low surrogate.
            }
        } else if ((cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) {
            cp = kReplacement;
        }
        AppendUtf8(out, cp);
    }
    return out;
}

String Utf8ToWide(const std::string& utf8_str) {
    String out;
    out.reserve(utf8_str.size());
    const auto* s = reinterpret_cast<const unsigned char*>(utf8_str.data());
    const size_t n = utf8_str.size();

    size_t i = 0;
    while (i < n) {
        const unsigned char c = s[i];
        if (c < 0x80) {
            out += static_cast<wchar_t>(c);
            ++i;
            continue;
        }

        size_t len = 0;
        uint32_t cp = 0;
        uint32_t min_cp = 0;
        if ((c & 0xE0) == 0xC0)      { len = 2; cp = c & 0x1F; min_cp = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min_cp = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min_cp = 0x10000; }
        else {
            out += static_cast<wchar_t>(kReplacement);  // Stray continuation / invalid lead.
            ++i;
            continue;
        }

        if (i + len > n) {
            out += static_cast<wchar_t>(kReplacement);  // Truncated sequence.
            ++i;
            continue;
        }

        bool valid = true;
        for (size_t k = 1; k < len; ++k) {
            if ((s[i + k] & 0xC0) != 0x80) {
                valid = false;
                break;
            }
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        // Reject overlong forms, surrogates and out-of-range code points.
        if (!valid || cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            out += static_cast<wchar_t>(kReplacement);
            ++i;
            continue;
        }

        AppendWide(out, cp);
        i += len;
    }
    return out;
}

String ToLower(const String& str) {
    String result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return result;
}

String ToUpper(const String& str) {
    String result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towupper(c)); });
    return result;
}

String Trim(const String& str) {
    size_t start = str.find_first_not_of(L" \t\r\n");
    if (start == String::npos) return L"";

    size_t end = str.find_last_not_of(L" \t\r\n");
    return str.substr(start, end - start + 1);
}

StringVector Split(const String& str, const String& delimiter) {
    StringVector result;
    if (delimiter.empty()) {
        result.push_back(str);  // find("") would loop forever.
        return result;
    }
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != String::npos) {
        result.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }

    result.push_back(str.substr(start));
    return result;
}

String Join(const StringVector& parts, const String& separator) {
    String result;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) result += separator;
        result += parts[i];
    }
    return result;
}

bool StartsWith(const String& str, const String& prefix) {
    return str.size() >= prefix.size() &&
           str.compare(0, prefix.size(), prefix) == 0;
}

bool EndsWith(const String& str, const String& suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

String ReplaceAll(const String& str, const String& from, const String& to) {
    if (from.empty()) {
        return str;  // Replacing "" would never advance.
    }
    String result = str;
    size_t pos = 0;
    while ((pos = result.find(from, pos)) != String::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    return result;
}

String ExtractExecutablePath(const String& image_path) {
    String p = Trim(image_path);
    if (p.empty()) return L"";

    // Strip a leading \??\ native path prefix if present.
    if (p.rfind(L"\\??\\", 0) == 0) {
        p = p.substr(4);
    }

    // Quoted executable: everything inside the first pair of quotes.
    if (p.front() == L'"') {
        size_t end = p.find(L'"', 1);
        if (end != String::npos) {
            return p.substr(1, end - 1);
        }
        return p.substr(1);
    }

    // Unquoted: the real binary ends at the first ".exe" token boundary.
    String lower = ToLower(p);
    size_t exe = lower.find(L".exe");
    while (exe != String::npos) {
        size_t after = exe + 4;
        if (after >= p.size() || p[after] == L' ' || p[after] == L'\t') {
            return p.substr(0, after);
        }
        exe = lower.find(L".exe", after);
    }

    // No .exe token: cut at the first whitespace (best effort).
    size_t sp = p.find_first_of(L" \t");
    return (sp == String::npos) ? p : p.substr(0, sp);
}

bool FileExists(const String& path) {
    std::error_code ec;
    const std::filesystem::path p(path);
    return std::filesystem::is_regular_file(p, ec);
}

bool DirectoryExists(const String& path) {
    std::error_code ec;
    const std::filesystem::path p(path);
    return std::filesystem::is_directory(p, ec);
}

bool CreateDirectory(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        // create_directories() returns false when the directory already exists,
        // which callers were treating as a hard failure -- the engine logged
        // "Failed to create output directory" on every run after the first.
        // The post-condition we actually care about is that it exists now.
        std::error_code ec;
        std::filesystem::create_directories(fs_path, ec);
        return std::filesystem::is_directory(fs_path, ec);
    } catch (...) {
        return false;
    }
}

String GetFileName(const String& path) {
    try {
        return std::filesystem::path(path).filename().wstring();
    } catch (...) {
        return L"";
    }
}

String GetFileExtension(const String& path) {
    try {
        return std::filesystem::path(path).extension().wstring();
    } catch (...) {
        return L"";
    }
}

String GetDirectoryName(const String& path) {
    try {
        return std::filesystem::path(path).parent_path().wstring();
    } catch (...) {
        return L"";
    }
}

size_t GetFileSize(const String& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(std::filesystem::path(path), ec);
    return ec ? 0 : static_cast<size_t>(size);
}

std::chrono::system_clock::time_point GetFileModificationTime(const String& path) {
    try {
        auto ftime = std::filesystem::last_write_time(std::filesystem::path(path));
        return std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    } catch (...) {
        return std::chrono::system_clock::now();
    }
}

bool CopyFile(const String& source, const String& destination) {
    std::error_code ec;
    std::filesystem::copy_file(std::filesystem::path(source), std::filesystem::path(destination),
                               std::filesystem::copy_options::overwrite_existing, ec);
    return !ec;
}

bool DeleteFile(const String& path) {
    std::error_code ec;
    return std::filesystem::remove(std::filesystem::path(path), ec);
}

StringVector ListFiles(const String& directory, const String& pattern) {
    StringVector result;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::path(directory), ec)) {
        if (entry.is_regular_file(ec)) {
            String filename = entry.path().filename().wstring();
            if (pattern == L"*" || filename.find(pattern) != String::npos) {
                result.push_back(entry.path().wstring());
            }
        }
    }
    return result;
}

String IpAddressToString(uint32_t ip) {
    std::wstringstream ss;
    ss << ((ip >> 24) & 0xFF) << L"."
       << ((ip >> 16) & 0xFF) << L"."
       << ((ip >> 8) & 0xFF) << L"."
       << (ip & 0xFF);
    return ss.str();
}

// These used to carry their own weaker parsing (a regex that accepted
// 999.999.999.999, and a stream parse that left octets uninitialised on bad
// input). They now share the validated parser in Core::Text.
uint32_t StringToIpAddress(const String& ip_str) {
    uint32_t ip = 0;
    return Text::TryParseIpv4(ip_str, ip) ? ip : 0;
}

bool IsValidIpAddress(const String& ip_str) {
    return Text::IsValidIpv4(ip_str);
}

bool IsPrivateIpAddress(const String& ip_str) {
    return Text::IsPrivateIpv4(ip_str);
}

String MacAddressToString(const uint8_t* mac) {
    if (mac == nullptr) {
        return L"";
    }
    wchar_t buffer[18];
    swprintf(buffer, 18, L"%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buffer);
}

bool ToLocalTime(std::time_t t, std::tm& out) {
#ifdef _WIN32
    return localtime_s(&out, &t) == 0;
#else
    return localtime_r(&t, &out) != nullptr;
#endif
}

String FormatTimestamp(const std::chrono::system_clock::time_point& time, const String& format) {
    const std::time_t t = std::chrono::system_clock::to_time_t(time);
    std::tm tm_buf{};
    ToLocalTime(t, tm_buf);
    std::wstringstream ss;
    ss << std::put_time(&tm_buf, format.c_str());
    return ss.str();
}

String GetCurrentTimestamp() {
    return FormatTimestamp(std::chrono::system_clock::now(), L"%Y%m%d_%H%M%S");
}

Timer::Timer() : is_running_(false) {
    Reset();
}

void Timer::Start() {
    start_time_ = std::chrono::steady_clock::now();
    is_running_ = true;
}

void Timer::Stop() {
    if (is_running_) {
        end_time_ = std::chrono::steady_clock::now();
        is_running_ = false;
    }
}

void Timer::Reset() {
    start_time_ = std::chrono::steady_clock::now();
    end_time_ = start_time_;
    is_running_ = false;
}

double Timer::GetElapsedSeconds() const {
    auto end = is_running_ ? std::chrono::steady_clock::now() : end_time_;
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_time_);
    return duration.count() / 1000000.0;
}

double Timer::GetElapsedMilliseconds() const {
    return GetElapsedSeconds() * 1000.0;
}

String Timer::GetElapsedString() const {
    double seconds = GetElapsedSeconds();

    if (seconds < 1.0) {
        return std::to_wstring(static_cast<int>(seconds * 1000)) + L"ms";
    } else if (seconds < 60.0) {
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(1) << seconds << L"s";
        return ss.str();
    } else {
        int minutes = static_cast<int>(seconds / 60);
        int secs = static_cast<int>(seconds) % 60;
        return std::to_wstring(minutes) + L"m " + std::to_wstring(secs) + L"s";
    }
}

String FormatBytes(size_t bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }

    std::wstringstream ss;
    ss << std::fixed << std::setprecision(2) << size << L" " << units[unit];
    return ss.str();
}

}
}
}
