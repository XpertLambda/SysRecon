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

// True if a path sits in a location any unprivileged user can write to, and
// from which binaries do not normally execute (temp dirs, Downloads, the
// recycle bin, ProgramData, Public). Not proof of anything on its own -- it
// raises a finding's risk, it never clears one.
bool IsUserWritableExecutionPath(const WString& path);

// Extracts the filename component of a path ("C:\a\b\x.exe" -> "x.exe").
WString GetFileNameComponent(const WString& path);

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

// True for 127.0.0.0/8. Services bound only to loopback are not reachable
// from the network, so they are not reported as exposed.
bool IsLoopbackIpv4(const WString& text);

// Decodes a REG_SZ / REG_EXPAND_SZ buffer as returned by RegQueryValueEx /
// RegEnumValue. Registry data is attacker-controlled: it is not guaranteed to
// be NUL-terminated, may have an odd byte count, and may contain embedded
// NULs. The result stops at the first NUL or at the end of the buffer,
// whichever comes first, and never reads past `byte_count`.
WString RegistryBufferToString(const wchar_t* data, size_t byte_count);

// --- DACL decisions --------------------------------------------------------
// Portable so they are unit-tested natively; the values are the documented
// Win32 access-right constants.

// True unless the ACE is inherit-only (INHERIT_ONLY_ACE, 0x08): such an ACE
// only describes what child objects receive and grants nothing on the object
// itself.
bool AceAppliesToObject(uint8_t ace_flags);

// True if a service ACE mask lets its holder reconfigure the service
// (SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE/ALL).
// Read, query, start and stop rights do not count. Previously the check
// tested `mask & SERVICE_ALL_ACCESS`, which is non-zero for *any* service
// right, so the read access every standard service grants to Authenticated
// Users / INTERACTIVE was reported as a Critical privilege escalation.
bool GrantsServiceReconfiguration(uint32_t mask);

// True if a file/directory ACE mask lets its holder replace or plant content:
// FILE_WRITE_DATA (add file), FILE_APPEND_DATA (add subdirectory), WRITE_DAC,
// WRITE_OWNER, GENERIC_WRITE/ALL. Attribute/EA writes and DELETE alone do not
// allow replacing a binary and are not counted.
bool GrantsFileModification(uint32_t mask);

// Makes an attacker-influenced name (e.g. a process name) safe to use as a
// single file-name component: anything other than [A-Za-z0-9._-] becomes
// '_', leading dots are replaced, and the result is capped at 64 characters.
// Never returns an empty string.
WString SanitizeFileName(const WString& name);

// --- Event log decisions ---------------------------------------------------
// The Event Logs module renders each event as XML (EvtRenderEventXml) and
// reads fields with these. Event data is attacker-influenced (account and
// service names, image paths), so parsing is bounded, never throws, and
// decodes only the five predefined XML entities.

// Text of the first <name ...>text</name> element, entity-decoded. Matches the
// local name exactly (<SubjectUserName> does not match "UserName"). Returns
// an empty string if absent or self-closing.
WString XmlElementText(const WString& xml, const WString& name);

// Value of <Data Name='name'>value</Data> (either quote style), as used in
// EventData. Empty if absent.
WString EventDataValue(const WString& xml, const WString& name);

// Value of attribute `attr` on the first <element ...> tag, e.g.
// XmlAttribute(xml, L"TimeCreated", L"SystemTime"). Empty if absent.
WString XmlAttribute(const WString& xml, const WString& element, const WString& attr);

// Decodes &lt; &gt; &amp; &quot; &apos; and numeric &#N; / &#xN; references.
// Anything else is left as-is.
WString XmlDecode(const WString& text);

// Severity of a service installed according to event 7045, from its image
// path: 3 (High) when it launches a script host or LOLBin directly (cmd,
// powershell, pwsh, mshta, rundll32, regsvr32, wscript, cscript) or carries an
// encoded command; 2 (Medium) when the binary is in a user-writable location
// (see IsUserWritableExecutionPath) or is a UNC path; 0 (informational)
// otherwise. Values match SecurityLevel.
int ServiceInstallSeverity(const WString& image_path);

// True for well-known privileged group SIDs: BUILTIN\Administrators
// (S-1-5-32-544), Backup Operators (-551), Remote Desktop Users (-555),
// and domain RIDs 512 (Domain Admins), 518 (Schema Admins), 519 (Enterprise
// Admins).
bool IsPrivilegedGroupSid(const WString& sid);

// CIS minimum size, in KB, for the classic logs: 196608 for Security, 32768
// for Application and System. 0 for any other channel (no requirement).
uint64_t RecommendedLogSizeKb(const WString& channel);

// --- Firewall rule decisions -----------------------------------------------

struct FirewallRuleView {
    bool enabled = false;
    bool inbound = false;
    bool allow = false;
    bool public_profile = false;     // Rule applies to the Public profile.
    WString remote_addresses;        // "*" = any
    WString local_ports;             // "*" = any
    WString application;             // Empty = any program
    // Package SID of a Store/UWP app the rule is scoped to (INetFwRule3
    // LocalAppPackageId). Such rules leave `application` empty but only
    // admit that app's listeners.
    WString app_package;
    WString service;                 // Empty or "*" = any service
    int protocol = 256;              // IANA number; 256 = any
};

// 3 (High): enabled inbound allow rule open to any remote address, on any
// local port, for any program and service -- the firewall does nothing for
// that traffic (a rule scoped to an app package does not count: it only
// admits that app). 2 (Medium): enabled inbound allow from any address, on the
// Public profile, to a remote-administration or file-sharing port (22, 23,
// 135, 139, 445, 3389, 5985, 5986). 0 otherwise.
int FirewallRuleSeverity(const FirewallRuleView& rule);

// True if a firewall port list ("80,443,5000-5010", "RPC", "*") includes
// `port`. Keywords such as "RPC" or "Ply2Disc" never match a number.
bool PortListIncludes(const WString& ports, int port);

}
}
}
