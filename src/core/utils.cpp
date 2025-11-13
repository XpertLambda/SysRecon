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

#ifdef _WIN32
bool EnableBackupPrivilege() {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    
    if (!LookupPrivilegeValue(nullptr, SE_BACKUP_NAME, &luid)) {
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

String GetSystemDirectory() {
    wchar_t buffer[MAX_PATH];
    UINT len = ::GetSystemDirectoryW(buffer, MAX_PATH);
    return (len > 0) ? String(buffer, len) : L"";
}

String GetWindowsDirectory() {
    wchar_t buffer[MAX_PATH];
    UINT len = ::GetWindowsDirectoryW(buffer, MAX_PATH);
    return (len > 0) ? String(buffer, len) : L"";
}

String GetTempDirectory() {
    wchar_t buffer[MAX_PATH];
    DWORD len = ::GetTempPathW(MAX_PATH, buffer);
    return (len > 0) ? String(buffer, len - 1) : L"";
}

DWORD GetProcessIdByName(const String& process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (ToLower(String(entry.szExeFile)) == ToLower(process_name)) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    
    CloseHandle(snapshot);
    return 0;
}

String GetProcessName(DWORD process_id) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return L"";
    }
    
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == process_id) {
                CloseHandle(snapshot);
                return String(entry.szExeFile);
            }
        } while (Process32NextW(snapshot, &entry));
    }
    
    CloseHandle(snapshot);
    return L"";
}

bool IsWow64Process() {
    BOOL isWow64 = FALSE;
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandleW(L"kernel32"), "IsWow64Process");
    
    if (fnIsWow64Process != nullptr) {
        if (!fnIsWow64Process(GetCurrentProcess(), &isWow64)) {
            return false;
        }
    }
    return isWow64 == TRUE;
}

bool RegistryKeyExists(HKEY root, const String& subkey) {
    HKEY key;
    LONG result = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(key);
        return true;
    }
    return false;
}

String ReadRegistryString(HKEY root, const String& subkey, const String& value_name) {
    HKEY key;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return L"";
    }
    
    wchar_t buffer[1024];
    DWORD buffer_size = sizeof(buffer);
    DWORD type;
    
    LONG result = RegQueryValueExW(key, value_name.c_str(), nullptr, &type, 
                                   (LPBYTE)buffer, &buffer_size);
    RegCloseKey(key);
    
    if (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        return String(buffer);
    }
    
    return L"";
}

DWORD ReadRegistryDword(HKEY root, const String& subkey, const String& value_name) {
    HKEY key;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return 0;
    }
    
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    DWORD type;
    
    RegQueryValueExW(key, value_name.c_str(), nullptr, &type, (LPBYTE)&value, &size);
    RegCloseKey(key);
    
    return value;
}

ByteVector ReadRegistryBinary(HKEY root, const String& subkey, const String& value_name) {
    HKEY key;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return ByteVector();
    }
    
    DWORD size = 0;
    DWORD type;
    RegQueryValueExW(key, value_name.c_str(), nullptr, &type, nullptr, &size);
    
    if (size == 0) {
        RegCloseKey(key);
        return ByteVector();
    }
    
    ByteVector data(size);
    RegQueryValueExW(key, value_name.c_str(), nullptr, &type, data.data(), &size);
    RegCloseKey(key);
    
    return data;
}

StringVector EnumerateRegistrySubkeys(HKEY root, const String& subkey) {
    StringVector result;
    HKEY key;
    
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return result;
    }
    
    wchar_t name[256];
    DWORD index = 0;
    DWORD name_len;
    
    while (true) {
        name_len = sizeof(name) / sizeof(name[0]);
        LONG ret = RegEnumKeyExW(key, index, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        
        if (ret == ERROR_SUCCESS) {
            result.push_back(String(name, name_len));
            index++;
        } else {
            break;
        }
    }
    
    RegCloseKey(key);
    return result;
}

StringVector EnumerateRegistryValues(HKEY root, const String& subkey) {
    StringVector result;
    HKEY key;
    
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return result;
    }
    
    wchar_t name[16384];
    DWORD index = 0;
    DWORD name_len;
    
    while (true) {
        name_len = sizeof(name) / sizeof(name[0]);
        LONG ret = RegEnumValueW(key, index, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        
        if (ret == ERROR_SUCCESS) {
            result.push_back(String(name, name_len));
            index++;
        } else {
            break;
        }
    }
    
    RegCloseKey(key);
    return result;
}

String RegistryKeyToString(HKEY key) {
    if (key == HKEY_LOCAL_MACHINE) return L"HKEY_LOCAL_MACHINE";
    if (key == HKEY_CURRENT_USER) return L"HKEY_CURRENT_USER";
    if (key == HKEY_CLASSES_ROOT) return L"HKEY_CLASSES_ROOT";
    if (key == HKEY_USERS) return L"HKEY_USERS";
    if (key == HKEY_CURRENT_CONFIG) return L"HKEY_CURRENT_CONFIG";
    return L"UNKNOWN_KEY";
}

#else
bool EnableBackupPrivilege() { return false; }
String GetSystemDirectory() { return L""; }
String GetWindowsDirectory() { return L""; }
String GetTempDirectory() { return L"/tmp"; }
DWORD GetProcessIdByName(const String&) { return 0; }
String GetProcessName(DWORD) { return L""; }
bool IsWow64Process() { return false; }
bool RegistryKeyExists(HKEY, const String&) { return false; }
String ReadRegistryString(HKEY, const String&, const String&) { return L""; }
DWORD ReadRegistryDword(HKEY, const String&, const String&) { return 0; }
ByteVector ReadRegistryBinary(HKEY, const String&, const String&) { return ByteVector(); }
StringVector EnumerateRegistrySubkeys(HKEY, const String&) { return StringVector(); }
StringVector EnumerateRegistryValues(HKEY, const String&) { return StringVector(); }
String RegistryKeyToString(HKEY) { return L""; }
#endif

String IpAddressToString(uint32_t ip) {
    std::wstringstream ss;
    ss << ((ip >> 24) & 0xFF) << L"."
       << ((ip >> 16) & 0xFF) << L"."
       << ((ip >> 8) & 0xFF) << L"."
       << (ip & 0xFF);
    return ss.str();
}

uint32_t StringToIpAddress(const String& ip_str) {
    std::wstringstream ss(ip_str);
    uint32_t a, b, c, d;
    wchar_t dot;
    ss >> a >> dot >> b >> dot >> c >> dot >> d;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

bool IsValidIpAddress(const String& ip_str) {
    std::wregex ip_regex(L"^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    return std::regex_match(ip_str, ip_regex);
}

bool IsPrivateIpAddress(const String& ip_str) {
    uint32_t ip = StringToIpAddress(ip_str);
    uint32_t octet1 = (ip >> 24) & 0xFF;
    uint32_t octet2 = (ip >> 16) & 0xFF;
    
    // 10.0.0.0/8
    if (octet1 == 10) return true;
    
    // 172.16.0.0/12
    if (octet1 == 172 && (octet2 >= 16 && octet2 <= 31)) return true;
    
    // 192.168.0.0/16
    if (octet1 == 192 && octet2 == 168) return true;
    
    return false;
}

String MacAddressToString(const uint8_t* mac) {
    wchar_t buffer[18];
    swprintf(buffer, 18, L"%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buffer);
}

StringVector ListFiles(const String& directory, const String& pattern) {
    StringVector result;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                String filename = entry.path().filename().wstring();
                if (pattern == L"*" || filename.find(pattern) != String::npos) {
                    result.push_back(entry.path().wstring());
                }
            }
        }
    } catch (...) {
    }
    return result;
}

std::chrono::system_clock::time_point GetFileModificationTime(const String& path) {
    try {
        auto ftime = std::filesystem::last_write_time(path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        return sctp;
    } catch (...) {
        return std::chrono::system_clock::now();
    }
}

bool CopyFile(const String& source, const String& destination) {
    try {
        std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing);
        return true;
    } catch (...) {
        return false;
    }
}

bool DeleteFile(const String& path) {
    try {
        return std::filesystem::remove(path);
    } catch (...) {
        return false;
    }
}

}
}
}
