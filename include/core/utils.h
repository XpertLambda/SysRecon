#pragma once

#include "../sysrecon.h"
#include <ctime>
#include <set>

namespace SysRecon {
namespace Core {
namespace Utils {

// ---------------------------------------------------------------------------
// Portable helpers (src/core/utils_common.cpp, part of sysrecon_core and
// unit-tested natively).
// ---------------------------------------------------------------------------

// UTF-8 <-> wide conversion. Implemented without Win32 so the same code is
// tested on Linux and shipped on Windows. Invalid input (bad UTF-8, unpaired
// surrogates) becomes U+FFFD rather than being silently dropped or truncated.
String Utf8ToWide(const std::string& utf8_str);
std::string WideToUtf8(const String& wide_str);

String ToLower(const String& str);
String ToUpper(const String& str);
String Trim(const String& str);
StringVector Split(const String& str, const String& delimiter);
String Join(const StringVector& parts, const String& separator);
bool StartsWith(const String& str, const String& prefix);
bool EndsWith(const String& str, const String& suffix);
String ReplaceAll(const String& str, const String& from, const String& to);

// Extracts the executable path from a service ImagePath / command string,
// honouring quoting ("C:\Program Files\x\s.exe" -k), unquoted paths that
// contain spaces (first ".exe" token wins), and a leading \??\ native prefix.
// Pure string logic so it is unit-testable on any host.
String ExtractExecutablePath(const String& image_path);

// SHA-256 of a buffer / of a file, returned as lowercase hex (64 chars) or an
// empty string if the file could not be read. A portable implementation so the
// hash of a flagged binary is identical on the build host and the target, and
// is unit-tested against the NIST vectors with no OS crypto dependency.
String Sha256Hex(const ByteVector& data);
String CalculateSHA256(const String& file_path);

// What kind of Windows this is. Build numbers alone cannot tell client from
// server (Windows Server 2025 and Windows 11 24H2 are both build 26100).
enum class OsFamily { Unknown, Client, Server, DomainController };

struct OsClassification {
    OsFamily family = OsFamily::Unknown;
    String name;   // "Windows 11", "Windows Server 2025", "Windows Server 2012 R2", ...
};

// Pure mapping from RtlGetVersion's fields to a family and a product name.
// `product_type` is OSVERSIONINFOEX::wProductType: 1 workstation, 2 domain
// controller, 3 server (0 = unknown, treated as a client). Unit-tested.
OsClassification ClassifyWindows(uint32_t major, uint32_t minor, uint32_t build, uint32_t product_type);

// One curated local-privilege-escalation issue whose fix looks to be missing.
struct LpePatchHint {
    String cve;        // "CVE-2021-34527"
    String name;       // "PrintNightmare (Print Spooler RCE/LPE)"
    String fix_kbs;    // "KB5004945, KB5004946, ..." for the evidence line
    String message;    // "<cve> (<name>) - no fixing hotfix found (<kbs>)"
};

// Offline "is a known local-privilege-escalation patch missing?" lookup.
// Given the OS build number, the set of installed hotfix IDs (e.g.
// "KB5004945") and whether the host is a domain controller, returns one hint
// per curated CVE that (a) can affect this build, (b) applies to this role and
// (c) whose fixing KB is not present. A CVE is only a candidate on the builds
// that existed before its fix; later builds (Windows 11, Server 2022+, Windows
// 10 21H2+ for the 2021 issues) shipped with it and are never reported, which
// is what stops a current Windows 11 from getting 2020-2022 "missing patch"
// findings. A hint is still a heuristic: cumulative updates supersede the
// listed KBs. Pure data + logic, unit-tested; the Win32 side only gathers the
// inputs (WMI Win32_QuickFixEngineering, RtlGetVersion, ProductType).
std::vector<LpePatchHint> MissingLpePatchHints(uint32_t os_build,
                                               const std::set<String>& installed_kbs,
                                               bool is_domain_controller = false);

bool FileExists(const String& path);
bool DirectoryExists(const String& path);
bool CreateDirectory(const String& path);
String GetFileName(const String& path);
String GetFileExtension(const String& path);
String GetDirectoryName(const String& path);
size_t GetFileSize(const String& path);
std::chrono::system_clock::time_point GetFileModificationTime(const String& path);
bool CopyFile(const String& source, const String& destination);
bool DeleteFile(const String& path);
StringVector ListFiles(const String& directory, const String& pattern = L"*");

String IpAddressToString(uint32_t ip);
// Returns 0 for anything that is not a valid dotted quad.
uint32_t StringToIpAddress(const String& ip_str);
bool IsValidIpAddress(const String& ip_str);
bool IsPrivateIpAddress(const String& ip_str);
String MacAddressToString(const uint8_t* mac);

// Thread-safe localtime (localtime_s on Windows, localtime_r elsewhere).
bool ToLocalTime(std::time_t t, std::tm& out);
String FormatTimestamp(const std::chrono::system_clock::time_point& time, const String& format = L"%Y-%m-%d %H:%M:%S");
String GetCurrentTimestamp();
// "2026-11-08T16:54:37Z": unambiguous, sortable, for machine-readable output.
// (GetCurrentTimestamp() is local time with no zone and is meant for file names.)
String FormatIso8601Utc(const std::chrono::system_clock::time_point& time);
// Offset of the local time zone from UTC at `time`, in minutes (e.g. -480).
int LocalUtcOffsetMinutes(const std::chrono::system_clock::time_point& time);

class Timer {
public:
    Timer();
    void Start();
    void Stop();
    void Reset();
    double GetElapsedSeconds() const;
    double GetElapsedMilliseconds() const;
    String GetElapsedString() const;

private:
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    bool is_running_;
};

String FormatBytes(size_t bytes);

// ---------------------------------------------------------------------------
// Win32 helpers (src/core/utils.cpp, Windows executable only).
// ---------------------------------------------------------------------------
#ifdef _WIN32
bool IsRunningAsAdmin();
bool EnableDebugPrivilege();
bool EnableBackupPrivilege();
String GetLastErrorString();
String GetLastErrorString(DWORD error_code);
DWORD GetProcessIdByName(const String& process_name);
String GetProcessName(DWORD process_id);
// PID -> executable name for every process, from a single snapshot. Use this
// instead of calling GetProcessName in a loop (one snapshot per call).
std::map<DWORD, String> GetProcessNameMap();
String GetSystemDirectory();
String GetWindowsDirectory();
String GetTempDirectory();
// Directory containing sysrecon.exe, without a trailing separator.
String GetExecutableDirectory();
// Expands %SystemRoot%-style variables and the \SystemRoot\ and \??\ prefixes
// that appear in service ImagePath values, so the result can be opened.
String ExpandImagePath(const String& path);
String GetCurrentUserName();
String GetComputerName();
// Replaces a file's DACL with a protected one granting full control only to
// SYSTEM, BUILTIN\Administrators and the file's owner. Reports contain
// usernames, SIDs, admin membership and service paths; inheriting the parent
// folder's ACL (e.g. Users:Read under Program Files) exposed them to every
// local user. Returns false if the ACL could not be applied.
bool RestrictToAdministrators(const String& path);
String GetWindowsVersion();
bool IsWow64Process();

String RegistryKeyToString(HKEY key);
bool RegistryKeyExists(HKEY root, const String& subkey);
String ReadRegistryString(HKEY root, const String& subkey, const String& value_name);
DWORD ReadRegistryDword(HKEY root, const String& subkey, const String& value_name);
// Distinguishes "value is 0" from "value is absent", which matters for policy
// checks where an unset value has its own (documented) default.
std::optional<DWORD> TryReadRegistryDword(HKEY root, const String& subkey, const String& value_name);
std::optional<String> TryReadRegistryString(HKEY root, const String& subkey, const String& value_name);
// "S-1-5-21-...-1001" -> "DOMAIN\name". Returns the SID string itself when it
// cannot be parsed or resolved (deleted accounts, offline domain).
String SidStringToAccountName(const String& sid);
ByteVector ReadRegistryBinary(HKEY root, const String& subkey, const String& value_name);
StringVector EnumerateRegistrySubkeys(HKEY root, const String& subkey);
StringVector EnumerateRegistryValues(HKEY root, const String& subkey);

// True when a non-administrative principal (Everyone, Authenticated Users,
// BUILTIN\Users or INTERACTIVE) holds write/modify rights on the file or
// directory at `path`, honouring explicit DENY ACEs. The matching principals
// are appended to `principals` when non-null. This is the core signal for
// binary-planting and service-binary-tampering privilege escalation.
bool IsWritableByNonAdmin(const String& path, StringVector* principals = nullptr);

// Authenticode verification via WinVerifyTrust.
enum class SignatureStatus {
    Trusted,     // valid, chains to a trusted root
    Unsigned,    // no embedded signature (and no catalog hit)
    Untrusted,   // signed but invalid/expired/untrusted chain
    Error        // could not be determined (file missing, API failure)
};
struct SignatureInfo {
    SignatureStatus status = SignatureStatus::Error;
    String signer;           // subject CN of the signing certificate, if any
    String status_text;      // short human-readable status
};
SignatureInfo VerifySignature(const String& file_path);

// Current-process token facts, for the privilege-escalation context check.
String GetIntegrityLevel();                 // "System" / "High" / "Medium" / "Low" / "Untrusted"
bool IsTokenElevated();                      // token elevation (split-token aware)
// Privileges currently present in the token, each as {name, enabled}. Name is
// the system name, e.g. "SeImpersonatePrivilege".
std::vector<std::pair<String, bool>> GetTokenPrivileges();
StringVector GetTokenGroupNames();           // resolved group account names

// Installed hotfix IDs (e.g. "KB5004945") from WMI Win32_QuickFixEngineering,
// and the OS build number. Used together with MissingLpePatchHints().
std::set<String> GetInstalledHotfixes();
uint32_t GetOsBuildNumber();
// Family and name from the live OS (RtlGetVersion incl. product type).
OsClassification GetOsClassification();
// Update Build Revision (the ".7019" in 26200.7019): which cumulative update
// is installed. 0 when it cannot be read.
uint32_t GetOsUbr();
#endif

}
}
}
