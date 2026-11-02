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

namespace {
constexpr uint8_t kInheritOnlyAce = 0x08;

constexpr uint32_t kServiceChangeConfig = 0x00000002;
constexpr uint32_t kFileWriteData       = 0x00000002;  // FILE_ADD_FILE on directories
constexpr uint32_t kFileAppendData      = 0x00000004;  // FILE_ADD_SUBDIRECTORY on directories
constexpr uint32_t kWriteDac            = 0x00040000;
constexpr uint32_t kWriteOwner          = 0x00080000;
constexpr uint32_t kGenericAll          = 0x10000000;
constexpr uint32_t kGenericWrite        = 0x40000000;
}  // namespace

bool AceAppliesToObject(uint8_t ace_flags) {
    return (ace_flags & kInheritOnlyAce) == 0;
}

bool GrantsServiceReconfiguration(uint32_t mask) {
    return (mask & (kServiceChangeConfig | kWriteDac | kWriteOwner | kGenericWrite | kGenericAll)) != 0;
}

bool GrantsFileModification(uint32_t mask) {
    return (mask & (kFileWriteData | kFileAppendData | kWriteDac | kWriteOwner |
                    kGenericWrite | kGenericAll)) != 0;
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

// --- Event log decisions ---------------------------------------------------

namespace {

bool IsXmlNameChar(wchar_t c) {
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ||
           c == L'_' || c == L'-' || c == L'.' || c == L':';
}

// Finds the next start tag "<name" whose local name is exactly `name`.
// Returns the position just after the name, or npos.
size_t FindStartTag(const WString& xml, const WString& name, size_t from) {
    const WString open = L"<" + name;
    for (size_t pos = xml.find(open, from); pos != WString::npos; pos = xml.find(open, pos + 1)) {
        const size_t after = pos + open.size();
        if (after >= xml.size() || !IsXmlNameChar(xml[after])) {
            return after;
        }
    }
    return WString::npos;
}

}  // namespace

WString XmlDecode(const WString& text) {
    WString out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] != L'&') {
            out.push_back(text[i]);
            continue;
        }
        const size_t semi = text.find(L';', i);
        if (semi == WString::npos || semi - i > 10) {
            out.push_back(text[i]);
            continue;
        }
        const WString entity = text.substr(i + 1, semi - i - 1);
        wchar_t decoded = 0;
        if (entity == L"lt") decoded = L'<';
        else if (entity == L"gt") decoded = L'>';
        else if (entity == L"amp") decoded = L'&';
        else if (entity == L"quot") decoded = L'"';
        else if (entity == L"apos") decoded = L'\'';
        else if (entity.size() > 1 && entity[0] == L'#') {
            const bool hex = entity[1] == L'x' || entity[1] == L'X';
            const WString digits = entity.substr(hex ? 2 : 1);
            uint32_t value = 0;
            bool ok = !digits.empty();
            for (wchar_t c : digits) {
                uint32_t d;
                if (c >= L'0' && c <= L'9') d = c - L'0';
                else if (hex && c >= L'a' && c <= L'f') d = c - L'a' + 10;
                else if (hex && c >= L'A' && c <= L'F') d = c - L'A' + 10;
                else { ok = false; break; }
                value = value * (hex ? 16 : 10) + d;
                if (value > 0xFFFF) { ok = false; break; }
            }
            if (ok && value != 0) decoded = static_cast<wchar_t>(value);
        }
        if (decoded == 0) {
            out.push_back(text[i]);
            continue;
        }
        out.push_back(decoded);
        i = semi;
    }
    return out;
}

WString XmlElementText(const WString& xml, const WString& name) {
    const size_t after = FindStartTag(xml, name, 0);
    if (after == WString::npos) {
        return WString();
    }
    const size_t gt = xml.find(L'>', after);
    if (gt == WString::npos || (gt > 0 && xml[gt - 1] == L'/')) {
        return WString();  // Unterminated, or self-closing <name/>.
    }
    const size_t close = xml.find(L"</" + name + L">", gt + 1);
    if (close == WString::npos) {
        return WString();
    }
    return XmlDecode(xml.substr(gt + 1, close - gt - 1));
}

WString EventDataValue(const WString& xml, const WString& name) {
    for (const wchar_t quote : {L'\'', L'"'}) {
        const WString marker = WString(L"Name=") + quote + name + quote;
        size_t pos = 0;
        while ((pos = xml.find(marker, pos)) != WString::npos) {
            // The marker must sit inside a <Data ...> start tag.
            const size_t lt = xml.rfind(L'<', pos);
            const size_t gt = xml.find(L'>', pos);
            if (lt != WString::npos && gt != WString::npos &&
                xml.compare(lt, 5, L"<Data") == 0 && xml.find(L'>', lt) == gt) {
                if (xml[gt - 1] == L'/') {
                    return WString();
                }
                const size_t close = xml.find(L"</Data>", gt + 1);
                if (close == WString::npos) {
                    return WString();
                }
                return XmlDecode(xml.substr(gt + 1, close - gt - 1));
            }
            pos += marker.size();
        }
    }
    return WString();
}

WString XmlAttribute(const WString& xml, const WString& element, const WString& attr) {
    const size_t after = FindStartTag(xml, element, 0);
    if (after == WString::npos) {
        return WString();
    }
    const size_t gt = xml.find(L'>', after);
    const WString tag = xml.substr(after, gt == WString::npos ? WString::npos : gt - after);
    for (size_t pos = tag.find(attr); pos != WString::npos; pos = tag.find(attr, pos + 1)) {
        // Whole attribute name: preceded by whitespace, followed by '='.
        if (pos == 0 || !iswspace(tag[pos - 1])) continue;
        size_t eq = pos + attr.size();
        while (eq < tag.size() && iswspace(tag[eq])) ++eq;
        if (eq >= tag.size() || tag[eq] != L'=') continue;
        size_t q = eq + 1;
        while (q < tag.size() && iswspace(tag[q])) ++q;
        if (q >= tag.size() || (tag[q] != L'\'' && tag[q] != L'"')) continue;
        const size_t end = tag.find(tag[q], q + 1);
        if (end == WString::npos) return WString();
        return XmlDecode(tag.substr(q + 1, end - q - 1));
    }
    return WString();
}

int ServiceInstallSeverity(const WString& image_path) {
    WString p = ToLowerAscii(image_path);
    std::replace(p.begin(), p.end(), L'/', L'\\');

    static const wchar_t* hosts[] = {
        L"%comspec%", L"cmd.exe", L"cmd ", L"powershell", L"pwsh", L"mshta", L"rundll32",
        L"regsvr32", L"wscript", L"cscript",
    };
    const WString exe = ToLowerAscii(GetFileNameComponent(ExtractExecutablePath(image_path)));
    for (const auto* h : hosts) {
        const WString host(h);
        if (exe == host || exe + L" " == host || exe == host + L".exe" ||
            p.rfind(host, 0) == 0 || p.find(L"\\" + host) != WString::npos) {
            return 3;
        }
    }
    if (p.find(L" -enc") != WString::npos || p.find(L" -encodedcommand") != WString::npos ||
        p.find(L"frombase64string") != WString::npos) {
        return 3;
    }

    if (p.rfind(L"\\\\", 0) == 0 || p.rfind(L"\"\\\\", 0) == 0) {
        return 2;  // Binary on a network share.
    }
    // Defender's platform binaries live under ProgramData by design.
    if (p.find(L"\\programdata\\microsoft\\windows defender\\") != WString::npos) {
        return 0;
    }
    if (IsUserWritableExecutionPath(p) ||
        (p.find(L"\\users\\") != WString::npos && p.find(L"\\appdata\\") != WString::npos)) {
        return 2;
    }
    return 0;
}

bool IsPrivilegedGroupSid(const WString& sid) {
    const WString s = ToLowerAscii(sid);
    if (s == L"s-1-5-32-544" || s == L"s-1-5-32-551" || s == L"s-1-5-32-555") {
        return true;
    }
    if (s.rfind(L"s-1-5-21-", 0) != 0) {
        return false;
    }
    const size_t dash = s.find_last_of(L'-');
    const WString rid = s.substr(dash + 1);
    return rid == L"512" || rid == L"518" || rid == L"519";
}

uint64_t RecommendedLogSizeKb(const WString& channel) {
    const WString c = ToLowerAscii(channel);
    if (c == L"security") return 196608;
    if (c == L"application" || c == L"system") return 32768;
    return 0;
}

// --- Firewall rule decisions -----------------------------------------------

bool PortListIncludes(const WString& ports, int port) {
    const WString list = ToLowerAscii(ports);
    size_t start = 0;
    while (start <= list.size()) {
        size_t comma = list.find(L',', start);
        if (comma == WString::npos) comma = list.size();
        WString token = list.substr(start, comma - start);
        token.erase(std::remove_if(token.begin(), token.end(), [](wchar_t c) { return iswspace(c); }),
                    token.end());
        start = comma + 1;
        if (token == L"*") {
            return true;
        }
        auto parse = [](const WString& t, int& out) {
            if (t.empty() || t.size() > 5) return false;
            int v = 0;
            for (wchar_t c : t) {
                if (c < L'0' || c > L'9') return false;
                v = v * 10 + (c - L'0');
            }
            out = v;
            return v <= 65535;
        };
        const size_t dash = token.find(L'-');
        int lo = 0, hi = 0;
        if (dash == WString::npos) {
            if (parse(token, lo) && lo == port) return true;
        } else if (parse(token.substr(0, dash), lo) && parse(token.substr(dash + 1), hi)) {
            if (lo <= port && port <= hi) return true;
        }
        if (comma == list.size()) break;
    }
    return false;
}

int FirewallRuleSeverity(const FirewallRuleView& rule) {
    if (!rule.enabled || !rule.inbound || !rule.allow) {
        return 0;
    }
    auto is_any = [](const WString& v) {
        WString t = ToLowerAscii(v);
        t.erase(std::remove_if(t.begin(), t.end(), [](wchar_t c) { return iswspace(c); }), t.end());
        return t.empty() || t == L"*" || t == L"any";
    };
    if (!is_any(rule.remote_addresses)) {
        return 0;
    }
    // ICMP and other port-less protocols: LocalPorts is meaningless there.
    const bool has_ports = rule.protocol == 6 || rule.protocol == 17 || rule.protocol == 256;
    if (!has_ports) {
        return 0;
    }
    if (is_any(rule.local_ports) && rule.application.empty() && is_any(rule.service)) {
        return 3;
    }
    // An any-port rule scoped to one program only admits that program's
    // listeners, so only explicit port lists count here.
    if (rule.public_profile && rule.protocol != 17 && !is_any(rule.local_ports)) {
        static const int admin_ports[] = {22, 23, 135, 139, 445, 3389, 5985, 5986};
        for (int p : admin_ports) {
            if (PortListIncludes(rule.local_ports, p)) {
                return 2;
            }
        }
    }
    return 0;
}

}
}
}
