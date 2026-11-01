#include "../../include/modules/privesc/privesc_analyzer.h"
#include "../../include/core/utils.h"
#include "../../include/core/whitelist.h"

namespace SysRecon {
namespace Modules {

PrivEscAnalyzer::PrivEscAnalyzer() = default;
PrivEscAnalyzer::~PrivEscAnalyzer() { Cleanup(); }

bool PrivEscAnalyzer::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Privilege Escalation analyzer module");
    initialized_ = true;
    return true;
}

void PrivEscAnalyzer::Cleanup() {
    findings_.clear();
    scan_results_.clear();
    initialized_ = false;
}

void PrivEscAnalyzer::Record(const PrivEscFinding& finding) {
    findings_.push_back(finding);

    ScanResult result;
    result.module_name = L"Privilege Escalation";
    result.item_name = finding.title;
    result.description = finding.description;
    result.risk_level = finding.risk_level;
    result.remediation = finding.remediation;
    result.reference = finding.reference;
    result.timestamp = std::chrono::system_clock::now();

    if (!finding.category.empty())    result.details[L"Category"] = finding.category;
    if (!finding.evidence.empty())    result.details[L"Evidence"] = finding.evidence;
    if (!finding.remediation.empty()) result.details[L"Remediation"] = finding.remediation;
    if (!finding.reference.empty())   result.details[L"Reference"] = finding.reference;

    scan_results_.push_back(result);
}

bool PrivEscAnalyzer::RunAllChecks() {
    if (!initialized_) return false;

    SYSRECON_LOG_INFO(L"Running privilege-escalation assessment checks...");

    CheckUnquotedServicePaths();
    CheckWeakServicePermissions();
    CheckWritableServiceBinaries();
    CheckAlwaysInstallElevated();
    CheckWritablePathDirectories();
    CheckAutorunWritableTargets();
    CheckStoredCredentials();
    CheckUacPosture();
    CheckUnattendedInstallFiles();

    SYSRECON_LOG_INFO(L"Privilege-escalation assessment complete: " +
                      std::to_wstring(findings_.size()) + L" finding(s)");
    return true;
}

#ifdef _WIN32

namespace {

// Lightweight view of a service used by several checks.
struct SvcEntry {
    String name;
    String display_name;
    String image_path;
    String account;
    String start_type;
};

// Enumerate all Win32 services with their config. Best-effort; services whose
// config cannot be read are skipped.
std::vector<SvcEntry> EnumerateServiceConfigs() {
    std::vector<SvcEntry> out;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return out;

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &bytesNeeded, &count, &resume, nullptr);
    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(scm);
        return out;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    auto services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buffer.data(), bytesNeeded, &bytesNeeded, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return out;
    }

    for (DWORD i = 0; i < count; ++i) {
        SvcEntry e;
        e.name = services[i].lpServiceName ? services[i].lpServiceName : L"";
        e.display_name = services[i].lpDisplayName ? services[i].lpDisplayName : L"";

        SC_HANDLE svc = OpenServiceW(scm, e.name.c_str(), SERVICE_QUERY_CONFIG);
        if (svc) {
            DWORD need = 0;
            QueryServiceConfigW(svc, nullptr, 0, &need);
            if (need > 0) {
                std::vector<BYTE> cfgbuf(need);
                auto cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(cfgbuf.data());
                if (QueryServiceConfigW(svc, cfg, need, &need)) {
                    e.image_path = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
                    e.account    = cfg->lpServiceStartName ? cfg->lpServiceStartName : L"";
                    switch (cfg->dwStartType) {
                        case SERVICE_AUTO_START:   e.start_type = L"Automatic"; break;
                        case SERVICE_DEMAND_START: e.start_type = L"Manual"; break;
                        case SERVICE_DISABLED:     e.start_type = L"Disabled"; break;
                        case SERVICE_BOOT_START:   e.start_type = L"Boot"; break;
                        case SERVICE_SYSTEM_START: e.start_type = L"System"; break;
                        default:                   e.start_type = L"Unknown"; break;
                    }
                }
            }
            CloseServiceHandle(svc);
        }
        out.push_back(std::move(e));
    }

    CloseServiceHandle(scm);
    return out;
}

// True when the service account is a high-privilege local account.
bool AccountIsPrivileged(const String& account) {
    String a = Core::Utils::ToLower(account);
    return a.empty() ||
           a == L"localsystem" ||
           a.find(L"\\system") != String::npos ||
           a.find(L"localservice") != String::npos ||
           a.find(L"networkservice") != String::npos ||
           a.find(L"nt authority") != String::npos;
}

} // namespace

bool PrivEscAnalyzer::ServiceDaclIsWeak(const String& service_name, StringVector& principals) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, service_name.c_str(), READ_CONTROL);
    if (!svc) { CloseServiceHandle(scm); return false; }

    DWORD needed = 0;
    QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, nullptr, 0, &needed);
    if (needed == 0) { CloseServiceHandle(svc); CloseServiceHandle(scm); return false; }

    std::vector<BYTE> sdbuf(needed);
    PSECURITY_DESCRIPTOR sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(sdbuf.data());
    if (!QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd, needed, &needed)) {
        CloseServiceHandle(svc); CloseServiceHandle(scm); return false;
    }

    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl) {
        CloseServiceHandle(svc); CloseServiceHandle(scm); return false;
    }

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

    // Rights that let a principal hijack the service (reconfigure binary/account
    // or take ownership of the object).
    const DWORD dangerous = SERVICE_CHANGE_CONFIG | WRITE_DAC | WRITE_OWNER |
                            SERVICE_ALL_ACCESS | GENERIC_WRITE | GENERIC_ALL;

    bool weak = false;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;
        ACE_HEADER* hdr = reinterpret_cast<ACE_HEADER*>(ace);
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        ACCESS_ALLOWED_ACE* allow = reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace);
        if ((allow->Mask & dangerous) == 0) continue;
        PSID aceSid = reinterpret_cast<PSID>(&allow->SidStart);
        for (const auto& w : watch) {
            if (w.sid && EqualSid(aceSid, w.sid)) {
                weak = true;
                principals.push_back(w.label);
            }
        }
    }

    if (everyone) FreeSid(everyone);
    if (users) FreeSid(users);
    if (authUsers) FreeSid(authUsers);
    if (interactive) FreeSid(interactive);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return weak;
}

bool PrivEscAnalyzer::CheckUnquotedServicePaths() {
    auto services = EnumerateServiceConfigs();
    auto& wl = Core::SystemWhitelist::Instance();

    for (const auto& s : services) {
        const String& img = s.image_path;
        if (img.empty() || img.front() == L'"') continue;          // already quoted
        if (img.find(L' ') == String::npos) continue;              // no space, no risk
        if (img.find(L'\\') == String::npos) continue;             // not a path

        // Only flag real filesystem paths that could be hijacked.
        String exe = Core::Utils::ExtractExecutablePath(img);
        String lower = Core::Utils::ToLower(img);
        // Skip paths rooted in protected system locations handled by Windows.
        if (wl.IsSafeUnquotedPath(img)) continue;

        PrivEscFinding f;
        f.category = L"Service";
        f.title = L"Unquoted service path: " + s.name;
        f.risk_level = SecurityLevel::High;
        f.description = L"Service '" + s.display_name + L"' (" + s.name +
            L") has an unquoted ImagePath containing spaces. Windows searches each "
            L"space-delimited prefix, so a binary planted at an earlier path (e.g. "
            L"C:\\Program.exe) would run with the service's privileges.";
        f.evidence = L"ImagePath=" + img + L" | Account=" + s.account;

        // Higher confidence when the service runs privileged.
        if (AccountIsPrivileged(s.account)) {
            f.evidence += L" (runs as a privileged account)";
        }

        f.remediation =
            L"Wrap the service ImagePath in double quotes: sc config \"" + s.name +
            L"\" binPath= \"\\\"" + exe + L"\\\" <args>\". Ensure no user-writable "
            L"directory exists along the path prefix.";
        f.reference = L"MITRE ATT&CK T1574.009 (Path Interception: Unquoted Path)";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckWeakServicePermissions() {
    auto services = EnumerateServiceConfigs();

    for (const auto& s : services) {
        StringVector principals;
        if (!ServiceDaclIsWeak(s.name, principals)) continue;

        PrivEscFinding f;
        f.category = L"Service";
        f.title = L"Weak service permissions: " + s.name;
        f.risk_level = AccountIsPrivileged(s.account) ? SecurityLevel::Critical
                                                      : SecurityLevel::High;
        f.description = L"The service security descriptor grants reconfiguration "
            L"rights (SERVICE_CHANGE_CONFIG / WRITE_DAC / full control) to a "
            L"low-privilege principal. That principal can repoint the service "
            L"binary or change its logon account and start it to execute code "
            L"as " + (s.account.empty() ? String(L"LocalSystem") : s.account) + L".";
        f.evidence = L"Service=" + s.name + L" | Writable by: " +
                     Core::Utils::Join(principals, L", ");
        f.remediation =
            L"Restrict the service DACL: remove change-config/write rights from "
            L"Users/Authenticated Users/Everyone (review with 'sc sdshow " + s.name +
            L"' and reset with 'sc sdset'). Only administrators should reconfigure "
            L"services.";
        f.reference = L"MITRE ATT&CK T1543.003 (Create or Modify System Process: Windows Service)";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckWritableServiceBinaries() {
    auto services = EnumerateServiceConfigs();

    for (const auto& s : services) {
        String exe = Core::Utils::ExtractExecutablePath(s.image_path);
        if (exe.empty()) continue;

        StringVector who;
        bool exe_writable = Core::Utils::IsWritableByNonAdmin(exe, &who);

        // Also check the containing directory (attacker could drop a DLL the
        // service loads, or replace via rename when the file is unlocked).
        String dir = Core::Utils::GetDirectoryName(exe);
        StringVector whoDir;
        bool dir_writable = !dir.empty() && Core::Utils::IsWritableByNonAdmin(dir, &whoDir);

        if (!exe_writable && !dir_writable) continue;

        PrivEscFinding f;
        f.category = L"Filesystem";
        f.title = L"Modifiable service binary: " + s.name;
        f.risk_level = AccountIsPrivileged(s.account) ? SecurityLevel::Critical
                                                      : SecurityLevel::High;
        String target = exe_writable ? exe : dir;
        StringVector& principals = exe_writable ? who : whoDir;
        f.description = L"The service executable" +
            String(exe_writable ? L"" : L"'s directory") +
            L" is writable by a non-administrative principal. The binary can be "
            L"replaced/planted and will run as " +
            (s.account.empty() ? String(L"LocalSystem") : s.account) +
            L" on next start.";
        f.evidence = L"Target=" + target + L" | Writable by: " +
                     Core::Utils::Join(principals, L", ");
        f.remediation =
            L"Tighten NTFS permissions on the binary and its directory so only "
            L"SYSTEM/Administrators have write/modify; grant Users read+execute "
            L"only (icacls \"" + target + L"\" /inheritance:r /grant ...).";
        f.reference = L"MITRE ATT&CK T1574.010 (Services File Permissions Weakness)";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckAlwaysInstallElevated() {
    DWORD hklm = Core::Utils::ReadRegistryDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated");
    DWORD hkcu = Core::Utils::ReadRegistryDword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated");

    if (hklm == 1 && hkcu == 1) {
        PrivEscFinding f;
        f.category = L"Registry";
        f.title = L"AlwaysInstallElevated enabled";
        f.risk_level = SecurityLevel::Critical;
        f.description = L"AlwaysInstallElevated is set in both HKLM and HKCU. Any "
            L"user can install a crafted MSI package that executes as SYSTEM, a "
            L"direct local privilege escalation.";
        f.evidence = L"HKLM\\...\\Installer\\AlwaysInstallElevated=1 and "
                     L"HKCU\\...\\Installer\\AlwaysInstallElevated=1";
        f.remediation = L"Set both AlwaysInstallElevated values to 0 (or remove "
            L"them) via Group Policy: Computer/User Config > Administrative "
            L"Templates > Windows Installer > 'Always install with elevated "
            L"privileges' = Disabled.";
        f.reference = L"MITRE ATT&CK T1548.002 / Microsoft Installer policy";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckWritablePathDirectories() {
    DWORD needed = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    if (needed == 0) return true;
    std::vector<wchar_t> pathBuf(needed);
    DWORD written = GetEnvironmentVariableW(L"PATH", pathBuf.data(), needed);
    if (written == 0 || written >= needed) return true;
    String path(pathBuf.data(), written);

    for (const auto& dirRaw : Core::Utils::Split(path, L";")) {
        String dir = Core::Utils::Trim(dirRaw);
        if (dir.empty()) continue;
        if (!Core::Utils::DirectoryExists(dir)) continue;

        StringVector who;
        if (!Core::Utils::IsWritableByNonAdmin(dir, &who)) continue;

        PrivEscFinding f;
        f.category = L"Filesystem";
        f.title = L"Writable directory on PATH";
        f.risk_level = SecurityLevel::High;
        f.description = L"A directory on the system PATH is writable by a "
            L"non-administrative principal. Attackers can plant a malicious "
            L"executable or DLL that privileged processes resolve and load "
            L"(binary/DLL search-order hijacking).";
        f.evidence = L"Directory=" + dir + L" | Writable by: " +
                     Core::Utils::Join(who, L", ");
        f.remediation = L"Remove write/modify access for non-admins on this "
            L"directory, or remove it from the system PATH if not required.";
        f.reference = L"MITRE ATT&CK T1574.007 (Path Interception: PATH Env Var)";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckAutorunWritableTargets() {
    struct RunKey { HKEY root; const wchar_t* path; const wchar_t* label; };
    const RunKey keys[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\...\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\WOW6432Node\\...\\Run" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU\\...\\Run" },
    };

    for (const auto& k : keys) {
        for (const auto& value : Core::Utils::EnumerateRegistryValues(k.root, k.path)) {
            String cmd = Core::Utils::ReadRegistryString(k.root, k.path, value);
            String exe = Core::Utils::ExtractExecutablePath(cmd);
            if (exe.empty()) continue;

            StringVector who;
            if (!Core::Utils::IsWritableByNonAdmin(exe, &who)) continue;

            PrivEscFinding f;
            f.category = L"Registry";
            f.title = L"Writable autorun target: " + value;
            f.risk_level = (k.root == HKEY_LOCAL_MACHINE) ? SecurityLevel::High
                                                          : SecurityLevel::Medium;
            f.description = L"An autostart program referenced from the Run key points "
                L"to a binary writable by a non-administrative principal. Replacing "
                L"it executes attacker code in the context of whoever logs on"
                + String(k.root == HKEY_LOCAL_MACHINE ? L" (including administrators)." : L".");
            f.evidence = String(k.label) + L"\\" + value + L" -> " + exe +
                         L" | Writable by: " + Core::Utils::Join(who, L", ");
            f.remediation = L"Restrict NTFS write/modify on the target binary to "
                L"SYSTEM/Administrators, or remove the autorun entry if unneeded.";
            f.reference = L"MITRE ATT&CK T1547.001 (Registry Run Keys)";
            Record(f);
        }
    }
    return true;
}

bool PrivEscAnalyzer::CheckStoredCredentials() {
    const wchar_t* winlogon = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    DWORD autoLogon = 0;
    String autoStr = Core::Utils::ReadRegistryString(HKEY_LOCAL_MACHINE, winlogon, L"AutoAdminLogon");
    if (!autoStr.empty()) autoLogon = (autoStr == L"1") ? 1 : 0;

    String defPwd = Core::Utils::ReadRegistryString(HKEY_LOCAL_MACHINE, winlogon, L"DefaultPassword");
    String defUser = Core::Utils::ReadRegistryString(HKEY_LOCAL_MACHINE, winlogon, L"DefaultUserName");

    if (autoLogon == 1 || !defPwd.empty()) {
        PrivEscFinding f;
        f.category = L"Credentials";
        f.title = L"Cleartext autologon credentials in registry";
        f.risk_level = SecurityLevel::High;
        f.description = L"Winlogon is configured for automatic logon and/or stores "
            L"a DefaultPassword in cleartext. Any user who can read the key recovers "
            L"the account password.";
        f.evidence = String(L"AutoAdminLogon=") + (autoLogon ? L"1" : L"0") +
                     L" | DefaultUserName=" + defUser +
                     L" | DefaultPassword=" + (defPwd.empty() ? L"(absent)" : L"(present)");
        f.remediation = L"Disable autologon (set AutoAdminLogon=0) and delete the "
            L"DefaultPassword value. If autologon is required, use the LSA secret "
            L"via sysinternals Autologon instead of a cleartext registry value.";
        f.reference = L"MITRE ATT&CK T1552.002 (Credentials in Registry)";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckUacPosture() {
    const wchar_t* polSystem = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

    DWORD enableLua = Core::Utils::ReadRegistryDword(HKEY_LOCAL_MACHINE, polSystem, L"EnableLUA");
    if (enableLua == 0) {
        PrivEscFinding f;
        f.category = L"Registry";
        f.title = L"UAC disabled (EnableLUA=0)";
        f.risk_level = SecurityLevel::High;
        f.description = L"User Account Control is turned off. Administrative tokens "
            L"are not split, so any code run by an admin user executes fully elevated "
            L"without a consent prompt, removing a key containment boundary.";
        f.evidence = String(polSystem) + L"\\EnableLUA=0";
        f.remediation = L"Re-enable UAC: set EnableLUA=1 and reboot. Configure "
            L"ConsentPromptBehaviorAdmin to prompt (value 2) for strong posture.";
        f.reference = L"MITRE ATT&CK T1548.002 (Bypass User Account Control)";
        Record(f);
    }

    DWORD tokenFilter = Core::Utils::ReadRegistryDword(HKEY_LOCAL_MACHINE, polSystem,
                                                       L"LocalAccountTokenFilterPolicy");
    if (tokenFilter == 1) {
        PrivEscFinding f;
        f.category = L"Registry";
        f.title = L"Remote UAC restrictions disabled (LocalAccountTokenFilterPolicy=1)";
        f.risk_level = SecurityLevel::Medium;
        f.description = L"LocalAccountTokenFilterPolicy=1 grants local accounts full "
            L"elevated tokens over the network, enabling pass-the-hash / lateral "
            L"movement with any local admin-equivalent account.";
        f.evidence = String(polSystem) + L"\\LocalAccountTokenFilterPolicy=1";
        f.remediation = L"Set LocalAccountTokenFilterPolicy=0 (default) unless a "
            L"documented management need exists; prefer domain accounts for remote "
            L"administration.";
        f.reference = L"MITRE ATT&CK T1550.002 (Pass the Hash)";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckUnattendedInstallFiles() {
    String windir = Core::Utils::GetWindowsDirectory();
    if (windir.empty()) windir = L"C:\\Windows";

    const String candidates[] = {
        windir + L"\\Panther\\Unattend.xml",
        windir + L"\\Panther\\Autounattend.xml",
        windir + L"\\Panther\\Unattended.xml",
        windir + L"\\System32\\Sysprep\\Unattend.xml",
        windir + L"\\System32\\Sysprep\\Panther\\Unattend.xml",
        L"C:\\unattend.xml",
        L"C:\\Autounattend.xml",
        windir + L"\\System32\\Sysprep\\sysprep.inf",
    };

    for (const auto& path : candidates) {
        if (!Core::Utils::FileExists(path)) continue;

        PrivEscFinding f;
        f.category = L"Credentials";
        f.title = L"Unattended-install answer file present";
        f.risk_level = SecurityLevel::Medium;
        f.description = L"A Windows unattended-setup answer file remains on disk. "
            L"These frequently contain a local administrator password (plaintext or "
            L"reversibly base64-encoded) left over from imaging.";
        f.evidence = L"File=" + path;
        f.remediation = L"Delete leftover answer files after provisioning, or strip "
            L"the <AdministratorPassword>/<AutoLogon> credential sections. Rotate any "
            L"password that was exposed.";
        f.reference = L"MITRE ATT&CK T1552.001 (Unsecured Credentials: Files)";
        Record(f);
    }
    return true;
}

#else  // non-Windows stubs (cross-compilation / native build sanity only)

bool PrivEscAnalyzer::CheckUnquotedServicePaths()     { return true; }
bool PrivEscAnalyzer::CheckWeakServicePermissions()   { return true; }
bool PrivEscAnalyzer::CheckWritableServiceBinaries()  { return true; }
bool PrivEscAnalyzer::CheckAlwaysInstallElevated()    { return true; }
bool PrivEscAnalyzer::CheckWritablePathDirectories()  { return true; }
bool PrivEscAnalyzer::CheckAutorunWritableTargets()   { return true; }
bool PrivEscAnalyzer::CheckStoredCredentials()        { return true; }
bool PrivEscAnalyzer::CheckUacPosture()               { return true; }
bool PrivEscAnalyzer::CheckUnattendedInstallFiles()   { return true; }

#endif

} // namespace Modules
} // namespace SysRecon
