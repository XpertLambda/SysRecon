// Win32 half of Core::Utils. Built into the Windows executable only; the
// portable helpers live in utils_common.cpp (sysrecon_core).

#include "../../include/core/utils.h"
#include "../../include/core/text_utils.h"

namespace SysRecon {
namespace Core {
namespace Utils {

namespace {

bool EnablePrivilege(const wchar_t* privilege_name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilege_name, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // AdjustTokenPrivileges returns TRUE even when it assigned nothing: it
    // reports ERROR_NOT_ALL_ASSIGNED via GetLastError. Without this check a
    // non-admin run reported the privilege as successfully enabled, and the
    // OpenProcess calls that depend on it then failed with no explanation.
    BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
    bool result = (adjusted != FALSE) && (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    CloseHandle(token);
    return result;
}

}  // namespace

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
    return EnablePrivilege(SE_DEBUG_NAME);
}

bool EnableBackupPrivilege() {
    return EnablePrivilege(SE_BACKUP_NAME);
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

    // FormatMessageW returns 0 and leaves message_buffer null for error codes
    // it cannot map. Constructing a std::wstring from (nullptr, 0) is UB, so
    // the result must be checked rather than assumed.
    if (size == 0 || message_buffer == nullptr) {
        return L"Unknown error " + std::to_wstring(error_code);
    }

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

bool RestrictToAdministrators(const String& path) {
    // P = protected (no inheritance from the parent); FA = file all access;
    // SY = LocalSystem, BA = BUILTIN\Administrators, OW = owner rights.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    bool ok = false;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present && dacl) {
        std::vector<wchar_t> buffer(path.begin(), path.end());
        buffer.push_back(L'\0');
        ok = SetNamedSecurityInfoW(buffer.data(), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
    }
    LocalFree(sd);
    return ok;
}

String GetCurrentUserName() {
    wchar_t buffer[257];
    DWORD size = sizeof(buffer) / sizeof(buffer[0]);

    if (::GetUserNameW(buffer, &size) && size > 0) {
        return String(buffer, size - 1);  // size includes the terminator.
    }
    return L"Unknown";
}

String GetWindowsVersion() {
    DWORD major = 0, minor = 0, build = 0;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        typedef LONG (WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        // Cast via void*: casting FARPROC straight to a typed function
        // pointer is a -Wcast-function-type violation.
        RtlGetVersionPtr RtlGetVersion =
            reinterpret_cast<RtlGetVersionPtr>(
                reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));

        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW rovi = {};
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if (RtlGetVersion(&rovi) == 0) {
                major = rovi.dwMajorVersion;
                minor = rovi.dwMinorVersion;
                build = rovi.dwBuildNumber;
            }
        }
    }

    std::wstringstream ss;
    ss << L"Windows ";
    if (major == 10) {
        ss << (build >= 22000 ? L"11" : L"10");
    } else if (major == 6) {
        if (minor == 3) ss << L"8.1";
        else if (minor == 2) ss << L"8";
        else if (minor == 1) ss << L"7";
        else ss << L"Vista";
    } else {
        ss << major << L"." << minor;
    }
    ss << L" (Build " << build << L")";
    return ss.str();
}

String GetSystemDirectory() {
    wchar_t buffer[MAX_PATH];
    UINT len = ::GetSystemDirectoryW(buffer, MAX_PATH);
    return (len > 0 && len < MAX_PATH) ? String(buffer, len) : L"";
}

String GetWindowsDirectory() {
    wchar_t buffer[MAX_PATH];
    UINT len = ::GetWindowsDirectoryW(buffer, MAX_PATH);
    return (len > 0 && len < MAX_PATH) ? String(buffer, len) : L"";
}

String GetTempDirectory() {
    wchar_t buffer[MAX_PATH + 1];
    DWORD len = ::GetTempPathW(MAX_PATH + 1, buffer);
    return (len > 0 && len <= MAX_PATH) ? String(buffer, len - 1) : L"";
}

String GetExecutableDirectory() {
    // Long paths: grow the buffer until GetModuleFileNameW stops truncating.
    std::vector<wchar_t> buffer(MAX_PATH);
    while (true) {
        DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) {
            return L"";
        }
        if (len < buffer.size()) {
            String path(buffer.data(), len);
            const size_t slash = path.find_last_of(L"\\/");
            return slash == String::npos ? String() : path.substr(0, slash);
        }
        if (buffer.size() >= 32768) {
            return L"";
        }
        buffer.resize(buffer.size() * 2);
    }
}

String ExpandImagePath(const String& path) {
    String p = path;
    const String lower = Text::ToLowerAscii(p);

    if (lower.rfind(L"\\systemroot\\", 0) == 0) {
        p = GetWindowsDirectory() + p.substr(11);
    } else if (lower.rfind(L"\\??\\", 0) == 0) {
        p = p.substr(4);
    } else if (lower.rfind(L"system32\\", 0) == 0) {
        p = GetWindowsDirectory() + L"\\" + p;
    }

    if (p.find(L'%') == String::npos) {
        return p;
    }
    DWORD needed = ExpandEnvironmentStringsW(p.c_str(), nullptr, 0);
    if (needed == 0) {
        return p;
    }
    std::vector<wchar_t> buffer(needed);
    DWORD written = ExpandEnvironmentStringsW(p.c_str(), buffer.data(), needed);
    if (written == 0 || written > needed) {
        return p;
    }
    return String(buffer.data());
}

std::map<DWORD, String> GetProcessNameMap() {
    std::map<DWORD, String> names;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return names;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            names[entry.th32ProcessID] = String(entry.szExeFile);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return names;
}

DWORD GetProcessIdByName(const String& process_name) {
    const String wanted = ToLower(process_name);
    for (const auto& [pid, name] : GetProcessNameMap()) {
        if (ToLower(name) == wanted) {
            return pid;
        }
    }
    return 0;
}

String GetProcessName(DWORD process_id) {
    const auto names = GetProcessNameMap();
    auto it = names.find(process_id);
    return it == names.end() ? String() : it->second;
}

bool IsWow64Process() {
    BOOL isWow64 = FALSE;
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process =
        reinterpret_cast<LPFN_ISWOW64PROCESS>(
            reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32"),
                                                   "IsWow64Process")));

    if (fnIsWow64Process != nullptr) {
        if (!fnIsWow64Process(GetCurrentProcess(), &isWow64)) {
            return false;
        }
    }
    return isWow64 == TRUE;
}

bool RegistryKeyExists(HKEY root, const String& subkey) {
    HKEY key;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegCloseKey(key);
        return true;
    }
    return false;
}

std::optional<String> TryReadRegistryString(HKEY root, const String& subkey, const String& value_name) {
    HKEY key;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD type = 0;
    DWORD size = 0;
    LONG result = RegQueryValueExW(key, value_name.c_str(), nullptr, &type, nullptr, &size);
    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || size > 1024 * 1024) {
        RegCloseKey(key);
        return std::nullopt;
    }

    // +2 wchar_t of slack: the value may change size between the two calls,
    // and RegistryBufferToString never reads past the reported size anyway.
    std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, L'\0');
    DWORD buffer_size = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
    result = RegQueryValueExW(key, value_name.c_str(), nullptr, &type,
                              reinterpret_cast<LPBYTE>(buffer.data()), &buffer_size);
    RegCloseKey(key);

    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return std::nullopt;
    }
    return Text::RegistryBufferToString(buffer.data(), buffer_size);
}

String ReadRegistryString(HKEY root, const String& subkey, const String& value_name) {
    return TryReadRegistryString(root, subkey, value_name).value_or(L"");
}

std::optional<DWORD> TryReadRegistryDword(HKEY root, const String& subkey, const String& value_name) {
    HKEY key;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = 0;
    LONG result = RegQueryValueExW(key, value_name.c_str(), nullptr, &type, (LPBYTE)&value, &size);
    RegCloseKey(key);

    if (result != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(DWORD)) {
        return std::nullopt;
    }
    return value;
}

DWORD ReadRegistryDword(HKEY root, const String& subkey, const String& value_name) {
    return TryReadRegistryDword(root, subkey, value_name).value_or(0);
}

ByteVector ReadRegistryBinary(HKEY root, const String& subkey, const String& value_name) {
    HKEY key;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return ByteVector();
    }

    DWORD size = 0;
    DWORD type;
    if (RegQueryValueExW(key, value_name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
        size == 0) {
        RegCloseKey(key);
        return ByteVector();
    }

    ByteVector data(size);
    if (RegQueryValueExW(key, value_name.c_str(), nullptr, &type, data.data(), &size) != ERROR_SUCCESS) {
        data.clear();
    } else {
        data.resize(size);
    }
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
    for (DWORD index = 0;; ++index) {
        DWORD name_len = sizeof(name) / sizeof(name[0]);
        LONG ret = RegEnumKeyExW(key, index, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (ret == ERROR_MORE_DATA) {
            continue;  // Name longer than the max key name; skip, do not stop.
        }
        if (ret != ERROR_SUCCESS) {
            break;
        }
        result.push_back(String(name, name_len));
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

    std::vector<wchar_t> name(16384);
    for (DWORD index = 0;; ++index) {
        DWORD name_len = static_cast<DWORD>(name.size());
        LONG ret = RegEnumValueW(key, index, name.data(), &name_len, nullptr, nullptr, nullptr, nullptr);
        if (ret != ERROR_SUCCESS) {
            break;
        }
        result.push_back(String(name.data(), name_len));
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

bool IsWritableByNonAdmin(const String& path, StringVector* principals) {
    if (path.empty()) return false;

    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    DWORD res = GetNamedSecurityInfoW(
        path.c_str(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
        nullptr, nullptr, &dacl, nullptr, &sd);
    if (res != ERROR_SUCCESS || dacl == nullptr) {
        if (sd) LocalFree(sd);
        return false;
    }

    // The low-privilege principals we treat as "non-admin".
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone = nullptr, users = nullptr, authUsers = nullptr, interactive = nullptr;
    AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &everyone);
    AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0,0,0,0,0,0, &users);
    AllocateAndInitializeSid(&nt, 1, SECURITY_AUTHENTICATED_USER_RID, 0,0,0,0,0,0,0, &authUsers);
    AllocateAndInitializeSid(&nt, 1, SECURITY_INTERACTIVE_RID, 0,0,0,0,0,0,0, &interactive);

    struct NamedSid { PSID sid; const wchar_t* label; };
    NamedSid watch[] = {
        { everyone,    L"Everyone" },
        { users,       L"BUILTIN\\Users" },
        { authUsers,   L"Authenticated Users" },
        { interactive, L"INTERACTIVE" },
    };
    constexpr size_t kWatch = sizeof(watch) / sizeof(watch[0]);

    // Rights that allow replacing or altering the target.
    const DWORD dangerous = FILE_WRITE_DATA | FILE_APPEND_DATA |
                            FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                            WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_WRITE | GENERIC_ALL;

    // First pass: principals explicitly DENIED a dangerous right.
    bool denied[kWatch] = { false };
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;
        ACE_HEADER* hdr = reinterpret_cast<ACE_HEADER*>(ace);
        if (hdr->AceType != ACCESS_DENIED_ACE_TYPE) continue;
        ACCESS_DENIED_ACE* deny = reinterpret_cast<ACCESS_DENIED_ACE*>(ace);
        if ((deny->Mask & dangerous) == 0) continue;
        PSID aceSid = reinterpret_cast<PSID>(&deny->SidStart);
        for (size_t w = 0; w < kWatch; ++w) {
            if (watch[w].sid && EqualSid(aceSid, watch[w].sid)) denied[w] = true;
        }
    }

    // Second pass: an ALLOW of a dangerous right to a non-denied watched SID.
    bool writable = false;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;
        ACE_HEADER* hdr = reinterpret_cast<ACE_HEADER*>(ace);
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        ACCESS_ALLOWED_ACE* allow = reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace);
        if ((allow->Mask & dangerous) == 0) continue;
        PSID aceSid = reinterpret_cast<PSID>(&allow->SidStart);
        for (size_t w = 0; w < kWatch; ++w) {
            if (denied[w]) continue;
            if (watch[w].sid && EqualSid(aceSid, watch[w].sid)) {
                writable = true;
                if (principals) principals->push_back(watch[w].label);
            }
        }
    }

    if (everyone) FreeSid(everyone);
    if (users) FreeSid(users);
    if (authUsers) FreeSid(authUsers);
    if (interactive) FreeSid(interactive);
    if (sd) LocalFree(sd);
    return writable;
}

}
}
}
