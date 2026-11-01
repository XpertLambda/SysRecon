#include <core/text_utils.h>

#include <algorithm>
#include <array>
#include <cwctype>

namespace SysRecon {
namespace Core {
namespace Text {

WString ToLowerAscii(const WString& value) {
    WString out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) {
        return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
    });
    return out;
}

WString HtmlEscape(const WString& value) {
    WString out;
    out.reserve(value.size());
    for (wchar_t c : value) {
        switch (c) {
            case L'&':  out += L"&amp;";  break;
            case L'<':  out += L"&lt;";   break;
            case L'>':  out += L"&gt;";   break;
            case L'"':  out += L"&quot;"; break;
            case L'\'': out += L"&#39;";  break;
            default:    out += c;         break;
        }
    }
    return out;
}

bool IsFormulaInjection(const WString& value) {
    size_t i = 0;
    // Excel strips leading whitespace before deciding a cell is a formula.
    while (i < value.size() && (value[i] == L' ' || value[i] == L'\t' || value[i] == L'\r')) {
        ++i;
    }
    if (i >= value.size()) {
        return false;
    }
    switch (value[i]) {
        case L'=':
        case L'+':
        case L'-':
        case L'@':
            return true;
        default:
            return false;
    }
}

WString CsvEscape(const WString& value) {
    WString body = value;
    if (IsFormulaInjection(body)) {
        body.insert(body.begin(), L'\'');
    }

    WString out;
    out.reserve(body.size() + 2);
    out += L'"';
    for (wchar_t c : body) {
        if (c == L'"') {
            out += L"\"\"";  // RFC 4180: embedded quotes are doubled.
        } else {
            out += c;
        }
    }
    out += L'"';
    return out;
}

WString GetFileNameComponent(const WString& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == WString::npos ? path : path.substr(slash + 1);
}

bool IsUserWritableExecutionPath(const WString& path) {
    if (path.empty()) {
        return false;
    }
    WString p = ToLowerAscii(path);
    std::replace(p.begin(), p.end(), L'/', L'\\');

    static const wchar_t* markers[] = {
        L"\\appdata\\local\\temp\\",
        L"\\windows\\temp\\",
        L"\\temp\\",
        L"\\tmp\\",
        L"\\downloads\\",
        L"\\users\\public\\",
        L"\\programdata\\",
        L"$recycle.bin",
    };
    for (const auto* marker : markers) {
        if (p.find(marker) != WString::npos) {
            return true;
        }
    }
    return false;
}

WString ExtractExecutablePath(const WString& command_line) {
    size_t first = command_line.find_first_not_of(L" \t");
    if (first == WString::npos) {
        return WString();
    }
    const WString cmd = command_line.substr(first);

    if (cmd.front() == L'"') {
        const size_t close = cmd.find(L'"', 1);
        if (close == WString::npos) {
            return WString();  // Unterminated quote: nothing trustworthy to read.
        }
        return cmd.substr(1, close - 1);
    }

    // Unquoted. Prefer the first token that ends in .exe; this keeps
    // "C:\Windows\system32\rundll32.exe foo.dll,Entry" from returning the DLL.
    const WString lower = ToLowerAscii(cmd);
    const size_t exe = lower.find(L".exe");
    if (exe != WString::npos) {
        return cmd.substr(0, exe + 4);
    }

    const size_t space = cmd.find(L' ');
    return space == WString::npos ? cmd : cmd.substr(0, space);
}

bool IsPathUnder(const WString& path, const WString& prefix) {
    if (prefix.empty()) {
        return false;
    }
    const WString p = ToLowerAscii(path);
    WString base = ToLowerAscii(prefix);

    // Normalise both to backslashes so C:/Windows and C:\Windows compare equal.
    std::replace(base.begin(), base.end(), L'/', L'\\');
    WString norm = p;
    std::replace(norm.begin(), norm.end(), L'/', L'\\');

    while (!base.empty() && base.back() == L'\\') {
        base.pop_back();
    }
    if (norm.compare(0, base.size(), base) != 0) {
        return false;
    }
    // An exact match, or a match that ends on a path separator. This is what
    // stops "c:\windows" from matching "C:\WindowsUpdate\evil.exe".
    return norm.size() == base.size() || norm[base.size()] == L'\\';
}

bool TryParseIpv4(const WString& text, uint32_t& out) {
    uint32_t octets[4] = {0, 0, 0, 0};
    size_t pos = 0;

    for (int i = 0; i < 4; ++i) {
        if (i > 0) {
            if (pos >= text.size() || text[pos] != L'.') {
                return false;
            }
            ++pos;
        }
        size_t digits = 0;
        uint32_t value = 0;
        while (pos < text.size() && text[pos] >= L'0' && text[pos] <= L'9') {
            value = value * 10 + static_cast<uint32_t>(text[pos] - L'0');
            if (value > 255) {
                return false;  // Rejects 999 and friends.
            }
            ++pos;
            ++digits;
            if (digits > 3) {
                return false;
            }
        }
        if (digits == 0) {
            return false;
        }
        octets[i] = value;
    }
    if (pos != text.size()) {
        return false;  // Trailing garbage.
    }

    out = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return true;
}

bool IsValidIpv4(const WString& text) {
    uint32_t ignored = 0;
    return TryParseIpv4(text, ignored);
}

bool IsPrivateIpv4(const WString& text) {
    uint32_t ip = 0;
    if (!TryParseIpv4(text, ip)) {
        return false;
    }
    const uint32_t a = (ip >> 24) & 0xFF;
    const uint32_t b = (ip >> 16) & 0xFF;

    if (a == 10) return true;                          // 10.0.0.0/8
    if (a == 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
    if (a == 192 && b == 168) return true;             // 192.168.0.0/16
    if (a == 127) return true;                         // 127.0.0.0/8
    if (a == 169 && b == 254) return true;             // 169.254.0.0/16
    return false;
}

bool IsLoopbackIpv4(const WString& text) {
    uint32_t ip = 0;
    return TryParseIpv4(text, ip) && ((ip >> 24) & 0xFF) == 127;
}

WString RegistryBufferToString(const wchar_t* data, size_t byte_count) {
    if (data == nullptr) {
        return WString();
    }
    // An odd trailing byte cannot form a character; ignore it.
    const size_t chars = byte_count / sizeof(wchar_t);
    size_t len = 0;
    while (len < chars && data[len] != L'\0') {
        ++len;
    }
    return WString(data, len);
}

WString SanitizeFileName(const WString& name) {
    WString out;
    out.reserve(name.size());
    for (wchar_t c : name) {
        const bool safe = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                          (c >= L'0' && c <= L'9') || c == L'.' || c == L'_' || c == L'-';
        out += safe ? c : L'_';
        if (out.size() >= 64) {
            break;
        }
    }
    // "." / ".." and hidden-file names must not survive as a path component.
    for (auto& c : out) {
        if (c != L'.') {
            break;
        }
        c = L'_';
    }
    return out.empty() ? WString(L"unnamed") : out;
}

}
}
}
