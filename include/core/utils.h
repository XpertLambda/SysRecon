#pragma once

#include "../sysrecon.h"

namespace SysRecon {
namespace Core {
namespace Utils {

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

#ifdef _WIN32
bool IsRunningAsAdmin();
bool EnableDebugPrivilege();
bool EnableBackupPrivilege();
String GetLastErrorString();
String GetLastErrorString(DWORD error_code);
DWORD GetProcessIdByName(const String& process_name);
String GetProcessName(DWORD process_id);
String GetSystemDirectory();
String GetWindowsDirectory();
String GetTempDirectory();
String GetCurrentUserName();
String GetComputerName();
String GetWindowsVersion();
bool IsWow64Process();
#endif

String IpAddressToString(uint32_t ip);
uint32_t StringToIpAddress(const String& ip_str);
bool IsValidIpAddress(const String& ip_str);
bool IsPrivateIpAddress(const String& ip_str);
String MacAddressToString(const uint8_t* mac);

String Base64Encode(const ByteVector& data);
ByteVector Base64Decode(const String& encoded);
String HexEncode(const ByteVector& data);
ByteVector HexDecode(const String& hex_str);
String UrlEncode(const String& str);
String UrlDecode(const String& str);

String CalculateMD5(const String& file_path);
String CalculateSHA1(const String& file_path);
String CalculateSHA256(const String& file_path);
String CalculateHashFromBuffer(const ByteVector& buffer, const String& algorithm);

#ifdef _WIN32
String RegistryKeyToString(HKEY key);
bool RegistryKeyExists(HKEY root, const String& subkey);
String ReadRegistryString(HKEY root, const String& subkey, const String& value_name);
DWORD ReadRegistryDword(HKEY root, const String& subkey, const String& value_name);
ByteVector ReadRegistryBinary(HKEY root, const String& subkey, const String& value_name);
StringVector EnumerateRegistrySubkeys(HKEY root, const String& subkey);
StringVector EnumerateRegistryValues(HKEY root, const String& subkey);
#endif

String GenerateRandomString(size_t length);
ByteVector GenerateRandomBytes(size_t length);
String HashPassword(const String& password, const String& salt);
bool VerifyPassword(const String& password, const String& hash, const String& salt);

String FormatTimestamp(const std::chrono::system_clock::time_point& time, const String& format = L"%Y-%m-%d %H:%M:%S");
std::chrono::system_clock::time_point ParseTimestamp(const String& timestamp, const String& format = L"%Y-%m-%d %H:%M:%S");
String GetCurrentTimestamp();
String GetUptime();

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
    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
    bool is_running_;
};

String FormatBytes(size_t bytes);
size_t GetAvailableMemory();
size_t GetTotalMemory();
double GetMemoryUsagePercentage();

struct ProcessInfo {
    DWORD pid;
    String name;
    String path;
    String command_line;
    DWORD parent_pid;
    std::chrono::system_clock::time_point creation_time;
    size_t memory_usage;
    double cpu_usage;
};

StringVector GetRunningProcesses();
ProcessInfo GetProcessInfo(DWORD pid);
bool TerminateProcess(DWORD pid);
bool IsProcessRunning(const String& process_name);

}
}
}
