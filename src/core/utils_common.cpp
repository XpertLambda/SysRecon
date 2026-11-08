// Portable half of Core::Utils. Part of sysrecon_core: must not depend on
// Win32, so it is compiled and unit-tested natively.

#include "../../include/core/utils.h"
#include "../../include/core/text_utils.h"

#include <cwctype>
#include <cstdint>
#include <array>
#include <fstream>

namespace SysRecon {
namespace Core {
namespace Utils {

namespace {

// Self-contained SHA-256 (FIPS 180-4). Portable and dependency-free so a
// flagged binary hashes identically on the Linux build host and on Windows,
// and so it is unit-testable in sysrecon_core.
class Sha256 {
public:
    Sha256() { Reset(); }

    void Update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            if (buffer_len_ == 64) { Transform(buffer_.data()); bit_len_ += 512; buffer_len_ = 0; }
        }
    }

    std::array<uint8_t, 32> Final() {
        uint64_t total_bits = bit_len_ + static_cast<uint64_t>(buffer_len_) * 8;
        size_t i = buffer_len_;
        buffer_[i++] = 0x80;
        if (i > 56) { while (i < 64) buffer_[i++] = 0; Transform(buffer_.data()); i = 0; }
        while (i < 56) buffer_[i++] = 0;
        for (int b = 7; b >= 0; --b) buffer_[i++] = static_cast<uint8_t>(total_bits >> (b * 8));
        Transform(buffer_.data());

        std::array<uint8_t, 32> out{};
        for (int j = 0; j < 8; ++j) {
            out[j * 4 + 0] = static_cast<uint8_t>(state_[j] >> 24);
            out[j * 4 + 1] = static_cast<uint8_t>(state_[j] >> 16);
            out[j * 4 + 2] = static_cast<uint8_t>(state_[j] >> 8);
            out[j * 4 + 3] = static_cast<uint8_t>(state_[j]);
        }
        return out;
    }

private:
    static uint32_t Rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void Reset() {
        state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        bit_len_ = 0; buffer_len_ = 0;
    }

    void Transform(const uint8_t* chunk) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(chunk[i*4]) << 24) | (static_cast<uint32_t>(chunk[i*4+1]) << 16) |
                   (static_cast<uint32_t>(chunk[i*4+2]) << 8) | static_cast<uint32_t>(chunk[i*4+3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = Rotr(w[i-15],7) ^ Rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = Rotr(w[i-2],17) ^ Rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=state_[0],b=state_[1],c=state_[2],d=state_[3],e=state_[4],f=state_[5],g=state_[6],h=state_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = Rotr(e,6) ^ Rotr(e,11) ^ Rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = Rotr(a,2) ^ Rotr(a,13) ^ Rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

    std::array<uint32_t, 8> state_{};
    std::array<uint8_t, 64> buffer_{};
    size_t buffer_len_ = 0;
    uint64_t bit_len_ = 0;
};

}  // namespace

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

namespace {
bool ToUtcTime(std::time_t t, std::tm& out) {
#ifdef _WIN32
    return gmtime_s(&out, &t) == 0;
#else
    return gmtime_r(&t, &out) != nullptr;
#endif
}
}  // namespace

String FormatIso8601Utc(const std::chrono::system_clock::time_point& time) {
    const std::time_t t = std::chrono::system_clock::to_time_t(time);
    std::tm tm_buf{};
    if (!ToUtcTime(t, tm_buf)) return L"";
    std::wstringstream ss;
    ss << std::put_time(&tm_buf, L"%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

int LocalUtcOffsetMinutes(const std::chrono::system_clock::time_point& time) {
    const std::time_t t = std::chrono::system_clock::to_time_t(time);
    std::tm local{}, utc{};
    if (!ToLocalTime(t, local) || !ToUtcTime(t, utc)) return 0;
    int minutes = (local.tm_hour * 60 + local.tm_min) - (utc.tm_hour * 60 + utc.tm_min);
    // The two broken-down times can straddle midnight: fold into (-12h, +14h].
    if (minutes > 14 * 60) minutes -= 24 * 60;
    if (minutes <= -12 * 60) minutes += 24 * 60;
    return minutes;
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

String Sha256Hex(const ByteVector& data) {
    Sha256 h;
    if (!data.empty()) h.Update(data.data(), data.size());
    const std::array<uint8_t, 32> digest = h.Final();
    static const wchar_t* hex = L"0123456789abcdef";
    String out;
    out.reserve(64);
    for (uint8_t byte : digest) {
        out.push_back(hex[byte >> 4]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

String CalculateSHA256(const String& file_path) {
    std::ifstream file{std::filesystem::path(file_path), std::ios::binary};
    if (!file.is_open()) return L"";

    Sha256 h;
    char buf[64 * 1024];
    bool any = false;
    while (file) {
        file.read(buf, sizeof(buf));
        std::streamsize got = file.gcount();
        if (got > 0) {
            h.Update(reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(got));
            any = true;
        }
    }
    if (!any && file.bad()) return L"";

    const std::array<uint8_t, 32> digest = h.Final();
    static const wchar_t* hex = L"0123456789abcdef";
    String out;
    out.reserve(64);
    for (uint8_t byte : digest) {
        out.push_back(hex[byte >> 4]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

OsClassification ClassifyWindows(uint32_t major, uint32_t minor, uint32_t build, uint32_t product_type) {
    OsClassification c;
    const bool is_dc = product_type == 2;
    const bool is_server = product_type == 3 || is_dc;
    c.family = is_dc ? OsFamily::DomainController : (is_server ? OsFamily::Server : OsFamily::Client);

    if (major == 10) {
        if (is_server) {
            if (build >= 26100)      c.name = L"Windows Server 2025";
            else if (build >= 25398) c.name = L"Windows Server, version 23H2";
            else if (build >= 20348) c.name = L"Windows Server 2022";
            else if (build >= 17763) c.name = L"Windows Server 2019";
            else if (build >= 14393) c.name = L"Windows Server 2016";
            else                     c.name = L"Windows Server (build " + std::to_wstring(build) + L")";
        } else {
            c.name = build >= 22000 ? L"Windows 11" : L"Windows 10";
        }
    } else if (major == 6) {
        if (is_server) {
            if (minor == 3)      c.name = L"Windows Server 2012 R2";
            else if (minor == 2) c.name = L"Windows Server 2012";
            else if (minor == 1) c.name = L"Windows Server 2008 R2";
            else                 c.name = L"Windows Server 2008";
        } else {
            if (minor == 3)      c.name = L"Windows 8.1";
            else if (minor == 2) c.name = L"Windows 8";
            else if (minor == 1) c.name = L"Windows 7";
            else                 c.name = L"Windows Vista";
        }
    } else if (major == 0) {
        c.family = OsFamily::Unknown;
        c.name = L"Windows";
    } else {
        c.name = L"Windows " + std::to_wstring(major) + L"." + std::to_wstring(minor);
    }
    return c;
}

std::vector<LpePatchHint> MissingLpePatchHints(uint32_t os_build, const std::set<String>& installed_kbs,
                                               bool is_domain_controller) {
    // Curated, deliberately small table of high-signal local-privilege-escalation
    // issues. Each entry lists the builds that existed *before* the fix
    // (affected) and KBs that (among others) addressed it. A CVE is a candidate
    // only on an affected build, only for the right role, and only when none of
    // the fix KBs is installed. This is a hint, not proof: cumulative updates
    // supersede these KBs, so findings are marked low confidence ("verify").
    struct Range { uint32_t from, to; };
    struct Entry {
        const wchar_t* cve;
        const wchar_t* name;
        std::vector<Range> affected;   // inclusive build ranges; empty = any build
        bool dc_only;                  // domain controllers only
        std::vector<String> fix_kbs;
    };
    // Build numbers: 7601 Win7/2008R2, 9600 8.1/2012R2, 14393 Server 2016,
    // 17134 Win10 1803, 17763 Win10 1809/Server 2019, 19041-19043 Win10
    // 2004..21H1, 19044 21H2, 19045 22H2, 20348 Server 2022, 22000 Win11 21H2,
    // 22621+ Win11 22H2 and later. Windows 11 and Windows 10 21H2+ were released
    // after the July 2021 fixes; Windows 10 22H2 and Windows 11 22H2+ after the
    // January 2022 fix.
    static const std::vector<Entry> table = {
        // July 2021 fixes. Builds up to Windows 10 21H1 (19043) pre-date them.
        { L"CVE-2021-34527", L"PrintNightmare (Print Spooler RCE/LPE)", {{0, 19043}}, false,
          { L"KB5004945", L"KB5004946", L"KB5004947", L"KB5004948", L"KB5004950" } },
        { L"CVE-2021-1675",  L"Print Spooler LPE", {{0, 19043}}, false,
          { L"KB5003635", L"KB5004945" } },
        // HiveNightmare: Windows 10 1809 through 21H1 (and Server 2019).
        { L"CVE-2021-36934", L"HiveNightmare / SeriousSAM (SAM hive readable)", {{17763, 19043}}, false,
          { L"KB5004605", L"KB5004237" } },
        // February 2021 fix: Windows 10 1803 through 20H2 (19042).
        { L"CVE-2021-1732",  L"Win32k window-object LPE", {{17134, 19042}}, false,
          { L"KB4601319", L"KB4601315" } },
        // January 2022 fix: Windows 10 1809-21H2, Server 2019/2022, original Windows 11.
        { L"CVE-2022-21882", L"Win32k LPE (CVE-2021-1732 bypass)",
          {{17763, 19044}, {20348, 20348}, {22000, 22000}}, false,
          { L"KB5009543", L"KB5009566" } },
        // Zerologon is a Netlogon flaw on domain controllers (Server 2019 and
        // older); it is not a local privilege escalation on workstations.
        { L"CVE-2020-1472",  L"Zerologon (Netlogon, domain controllers)", {{0, 17763}}, true,
          { L"KB4565349", L"KB4571756", L"KB4571694" } },
    };

    std::vector<LpePatchHint> hints;
    for (const auto& e : table) {
        if (e.dc_only && !is_domain_controller) continue;
        if (!e.affected.empty()) {
            bool in_range = false;
            for (const auto& r : e.affected) {
                if (os_build >= r.from && os_build <= r.to) { in_range = true; break; }
            }
            if (!in_range) continue;
        }
        bool patched = false;
        for (const auto& kb : e.fix_kbs) {
            if (installed_kbs.count(kb)) { patched = true; break; }
        }
        if (patched) continue;
        String fixes;
        for (size_t i = 0; i < e.fix_kbs.size(); ++i) {
            if (i) fixes += L", ";
            fixes += e.fix_kbs[i];
        }
        LpePatchHint h;
        h.cve = e.cve;
        h.name = e.name;
        h.fix_kbs = fixes;
        h.message = String(e.cve) + L" (" + e.name + L") - no fixing hotfix found (" + fixes + L")";
        hints.push_back(std::move(h));
    }
    return hints;
}

}
}
}
