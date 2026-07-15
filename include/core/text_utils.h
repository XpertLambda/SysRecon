#pragma once

#include <string>
#include <cstdint>

// Platform-independent text handling. Deliberately free of Win32 dependencies
// so it can be unit-tested natively -- these functions guard the report output,
// which is the tool's primary attack surface.

namespace SysRecon {
namespace Core {
namespace Text {

using WString = std::wstring;

// Escapes & < > " ' for safe interpolation into HTML text and attributes.
// Every attacker-influenced value written into a report must pass through this.
WString HtmlEscape(const WString& value);

// Quotes a field per RFC 4180: wraps in quotes and doubles any embedded quote.
// Also neutralises spreadsheet formula injection: a field starting with
// = + - @ (or a leading tab/CR, which Excel strips before parsing) is prefixed
// with an apostrophe so it is treated as text rather than executed.
WString CsvEscape(const WString& value);

// True if the field would be interpreted as a formula by Excel/LibreOffice.
bool IsFormulaInjection(const WString& value);

// Case-insensitive path prefix test that respects path boundaries:
// IsPathUnder(L"C:\\WindowsUpdate\\x.exe", L"c:\\windows") == false
// IsPathUnder(L"C:\\Windows\\System32\\x.exe", L"c:\\windows") == true
bool IsPathUnder(const WString& path, const WString& prefix);

WString ToLowerAscii(const WString& value);

// Extracts the executable path from a command line, so callers can check where
// a binary actually lives rather than trusting its name. Handles both quoted
// ("C:\Program Files\X\y.exe" -k) and unquoted (C:\Windows\x.exe /a) forms.
// Returns an empty string when no executable can be identified.
WString ExtractExecutablePath(const WString& command_line);

// Parses a dotted-quad IPv4 address. Returns false (leaving `out` untouched)
// on anything malformed, including out-of-range octets like 999.999.999.999.
bool TryParseIpv4(const WString& text, uint32_t& out);

bool IsValidIpv4(const WString& text);
bool IsPrivateIpv4(const WString& text);

}
}
}
