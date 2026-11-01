#pragma once

#include "../sysrecon.h"
#include <ctime>

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
ByteVector ReadRegistryBinary(HKEY root, const String& subkey, const String& value_name);
StringVector EnumerateRegistrySubkeys(HKEY root, const String& subkey);
StringVector EnumerateRegistryValues(HKEY root, const String& subkey);

// True when a non-administrative principal (Everyone, Authenticated Users,
// BUILTIN\Users or INTERACTIVE) holds write/modify rights on the file or
// directory at `path`, honouring explicit DENY ACEs. The matching principals
// are appended to `principals` when non-null. This is the core signal for
// binary-planting and service-binary-tampering privilege escalation.
bool IsWritableByNonAdmin(const String& path, StringVector* principals = nullptr);
#endif

}
}
}
