#include "../include/core/utils.h"

namespace SysRecon {
namespace Core {
namespace Utils {

#ifdef _WIN32
String Utf8ToWide(const std::string& utf8_str) {
    if (utf8_str.empty()) return L"";
    
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, nullptr, 0);
    if (size_needed <= 0) return L"";
    
    std::wstring result(size_needed - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, &result[0], size_needed);
    
    return result;
}

std::string WideToUtf8(const String& wide_str) {
    if (wide_str.empty()) return "";
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return "";
    
    std::string result(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, &result[0], size_needed, nullptr, nullptr);
    
    return result;
}
#else
String Utf8ToWide(const std::string& utf8_str) {
    return String(utf8_str.begin(), utf8_str.end());
}

std::string WideToUtf8(const String& wide_str) {
    return std::string(wide_str.begin(), wide_str.end());
}
#endif

String ToLower(const String& str) {
    String result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

String ToUpper(const String& str) {
    String result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towupper);
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
    if (parts.empty()) return L"";
    if (parts.size() == 1) return parts[0];
    
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
    String result = str;
    size_t pos = 0;
    
    while ((pos = result.find(from, pos)) != String::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    
    return result;
}

bool FileExists(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        return std::filesystem::exists(fs_path) && std::filesystem::is_regular_file(fs_path);
    } catch (...) {
        return false;
    }
}

bool DirectoryExists(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        return std::filesystem::exists(fs_path) && std::filesystem::is_directory(fs_path);
    } catch (...) {
        return false;
    }
}

bool CreateDirectory(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        return std::filesystem::create_directories(fs_path);
    } catch (...) {
        return false;
    }
}

String GetFileName(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        return fs_path.filename().wstring();
    } catch (...) {
        return L"";
    }
}

String GetFileExtension(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        return fs_path.extension().wstring();
    } catch (...) {
        return L"";
    }
}

String GetDirectoryName(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        return fs_path.parent_path().wstring();
    } catch (...) {
        return L"";
    }
}

size_t GetFileSize(const String& path) {
    try {
        std::filesystem::path fs_path(path);
        return std::filesystem::file_size(fs_path);
    } catch (...) {
        return 0;
    }
}

#ifdef _WIN32
bool IsRunningAsAdmin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, 
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    
    return is_admin == TRUE;
}

bool EnableDebugPrivilege() {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) != FALSE;
    CloseHandle(token);
    
    return result;
}

String GetLastErrorString() {
    return GetLastErrorString(GetLastError());
}

String GetLastErrorString(DWORD error_code) {
    wchar_t* message_buffer = nullptr;
    size_t size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&message_buffer, 0, nullptr);
    
    String message(message_buffer, size);
    LocalFree(message_buffer);
    
    return Trim(message);
}

String GetComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer) / sizeof(buffer[0]);
    
    if (::GetComputerNameW(buffer, &size)) {
        return String(buffer, size);
    }
    
    return L"Unknown";
}

String GetCurrentUserName() {
    wchar_t buffer[256];
    DWORD size = sizeof(buffer) / sizeof(buffer[0]);
    
    if (::GetUserNameW(buffer, &size)) {
        return String(buffer, size - 1);
    }
    
    return L"Unknown";
}

#else
bool IsRunningAsAdmin() { return false; }
bool EnableDebugPrivilege() { return false; }
String GetLastErrorString() { return L"Not implemented"; }
String GetLastErrorString(DWORD) { return L"Not implemented"; }
String GetComputerName() { return L"Cross-compiled"; }
String GetCurrentUserName() { return L"Cross-compiled"; }
#endif

String GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::wstringstream ss;
    ss << std::put_time(std::localtime(&time_t), L"%Y%m%d_%H%M%S");
    
    return ss.str();
}

String FormatTimestamp(const std::chrono::system_clock::time_point& time, const String& format) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    
    std::wstringstream ss;
    ss << std::put_time(std::localtime(&time_t), format.c_str());
    
    return ss.str();
}

Timer::Timer() : is_running_(false) {
    Reset();
}

void Timer::Start() {
    start_time_ = std::chrono::high_resolution_clock::now();
    is_running_ = true;
}

void Timer::Stop() {
    if (is_running_) {
        end_time_ = std::chrono::high_resolution_clock::now();
        is_running_ = false;
    }
}

void Timer::Reset() {
    start_time_ = std::chrono::high_resolution_clock::now();
    end_time_ = start_time_;
    is_running_ = false;
}

double Timer::GetElapsedSeconds() const {
    auto end = is_running_ ? std::chrono::high_resolution_clock::now() : end_time_;
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
        return std::to_wstring(seconds) + L"s";
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

String GetWindowsVersion() {
#ifdef _WIN32
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        typedef LONG (WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
        
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW rovi = {};
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if (RtlGetVersion(&rovi) == 0) {
                osvi.dwMajorVersion = rovi.dwMajorVersion;
                osvi.dwMinorVersion = rovi.dwMinorVersion;
                osvi.dwBuildNumber = rovi.dwBuildNumber;
            }
        }
    }
    
    std::wstringstream ss;
    ss << L"Windows ";
    
    if (osvi.dwMajorVersion == 10) {
        if (osvi.dwBuildNumber >= 22000) {
            ss << L"11";
        } else {
            ss << L"10";
        }
    } else if (osvi.dwMajorVersion == 6) {
        if (osvi.dwMinorVersion == 3) {
            ss << L"8.1";
        } else if (osvi.dwMinorVersion == 2) {
            ss << L"8";
        } else if (osvi.dwMinorVersion == 1) {
            ss << L"7";
        } else {
            ss << L"Vista";
        }
    } else {
        ss << osvi.dwMajorVersion << L"." << osvi.dwMinorVersion;
    }
    
    ss << L" (Build " << osvi.dwBuildNumber << L")";
    return ss.str();
#else
    return L"Windows (Cross-compiled)";
#endif
}

}
}
}
