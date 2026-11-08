#include "../../include/modules/privesc/privesc_analyzer.h"
#include "../../include/core/utils.h"
#include "../../include/core/whitelist.h"
#include "../../include/core/text_utils.h"

#ifdef _WIN32
#include <objbase.h>
#include <taskschd.h>
#endif

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
    result.instance_key = finding.instance_key;
    result.confidence = finding.confidence;
    result.fact_key = finding.fact_key;
    if (!finding.instance_key.empty()) {
        // The title of an instanced rule is the rule's name; the instance goes
        // in the key (and in the evidence), not in the ID.
        result.check_id = finding.title;
    }
    result.timestamp = std::chrono::system_clock::now();

    // remediation/reference are first-class ScanResult fields (rendered
    // specially by the report), so they are not duplicated into details.
    if (!finding.category.empty()) result.details[L"Category"] = finding.category;
    if (!finding.evidence.empty()) result.details[L"Evidence"] = finding.evidence;

    scan_results_.push_back(result);
}

bool PrivEscAnalyzer::RunAllChecks() {
    if (!initialized_) return false;

    SYSRECON_LOG_INFO(L"Running privilege-escalation assessment checks...");

    if (check_services_) {
        CheckUnquotedServicePaths();
        CheckWeakServicePermissions();
        CheckWritableServiceBinaries();
    }
    if (check_registry_) {
        CheckAlwaysInstallElevated();
        CheckUacPosture();
    }
    if (check_filesystem_) {
        CheckWritablePathDirectories();
        CheckAutorunWritableTargets();
    }
    if (check_credentials_) {
        CheckStoredCredentials();
        CheckUnattendedInstallFiles();
    }
    if (check_tokens_) {
        CheckTokenPrivileges();
    }
    if (check_scheduled_tasks_) {
        CheckScheduledTasks();
    }
    if (check_registry_ || check_filesystem_) {
        CheckExtendedAutoruns();
    }
    if (check_patches_) {
        CheckMissingPatches();
    }
    if (check_credentials_) {
        CheckCredentialExposure();
    }
    if (check_defender_) {
        CheckDefenderPosture();
    }
    if (check_hardening_) {
        CheckHardeningBaseline();
    }

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
// Short signature + SHA-256 descriptor for a binary, appended to finding
// evidence so an analyst can triage (unsigned SYSTEM binaries are worth a look;
// the hash supports IOC lookups).
String DescribeBinary(const String& exe) {
    Core::Utils::SignatureInfo sig = Core::Utils::VerifySignature(exe);
    String sig_text;
    switch (sig.status) {
        case Core::Utils::SignatureStatus::Trusted:
            sig_text = L"signed"; if (!sig.signer.empty()) sig_text += L" (" + sig.signer + L")"; break;
        case Core::Utils::SignatureStatus::Unsigned:  sig_text = L"UNSIGNED"; break;
        case Core::Utils::SignatureStatus::Untrusted: sig_text = L"signature untrusted"; break;
        default:                                      sig_text = L"signature unknown"; break;
    }
    String sha = Core::Utils::CalculateSHA256(exe);
    String out = L"signature=" + sig_text;
    if (!sha.empty()) out += L" | sha256=" + sha;
    return out;
}

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

    // Only rights that let a principal hijack the service (reconfigure its
    // binary/account, or take over its DACL/owner) count -- see
    // Core::Text::GrantsServiceReconfiguration for why this is not
    // `mask & SERVICE_ALL_ACCESS`.
    bool weak = false;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;
        ACE_HEADER* hdr = reinterpret_cast<ACE_HEADER*>(ace);
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        if (!Core::Text::AceAppliesToObject(hdr->AceFlags)) continue;
        ACCESS_ALLOWED_ACE* allow = reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace);
        if (!Core::Text::GrantsServiceReconfiguration(allow->Mask)) continue;
        PSID aceSid = reinterpret_cast<PSID>(&allow->SidStart);
        for (const auto& w : watch) {
            if (w.sid && EqualSid(aceSid, w.sid)) {
                weak = true;
                if (std::find(principals.begin(), principals.end(), w.label) == principals.end()) {
                    principals.push_back(w.label);
                }
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
        if (verify_signatures_) f.evidence += L" | " + DescribeBinary(exe);
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
            if (verify_signatures_) f.evidence += L" | " + DescribeBinary(exe);
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
        f.fact_key = L"uac-disabled";
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

bool PrivEscAnalyzer::CheckTokenPrivileges() {
    const String integrity = Core::Utils::GetIntegrityLevel();
    const bool elevated = Core::Utils::IsTokenElevated();
    auto privs = Core::Utils::GetTokenPrivileges();

    // Informational context finding: who are we running as?
    {
        StringVector enabled_names;
        for (const auto& p : privs) if (p.second) enabled_names.push_back(p.first);
        PrivEscFinding f;
        f.category = L"Context";
        f.title = L"Current security context";
        f.risk_level = SecurityLevel::Low;
        f.description = L"Integrity level and token of the account SysRecon is running as. "
            L"Privilege-escalation findings should be read in this context.";
        f.evidence = L"IntegrityLevel=" + integrity +
                     L" | Elevated=" + String(elevated ? L"Yes" : L"No") +
                     L" | EnabledPrivileges=" + std::to_wstring(enabled_names.size());
        f.remediation = L"Informational; no action required.";
        f.reference = L"Context for the privilege-escalation findings below";
        Record(f);
    }

    // Dangerous privileges that provide a direct path to SYSTEM when held.
    struct Dangerous { const wchar_t* name; const wchar_t* note; const wchar_t* ref; };
    const Dangerous dangerous[] = {
        { L"SeImpersonatePrivilege",     L"impersonate a SYSTEM token (Potato family)", L"MITRE ATT&CK T1134.001" },
        { L"SeAssignPrimaryTokenPrivilege", L"assign a primary token to a new process (Potato family)", L"MITRE ATT&CK T1134.001" },
        { L"SeBackupPrivilege",          L"read any file, including SAM/SYSTEM hives", L"MITRE ATT&CK T1003.002" },
        { L"SeRestorePrivilege",         L"overwrite any file / protected registry key", L"MITRE ATT&CK T1574" },
        { L"SeTakeOwnershipPrivilege",   L"take ownership of any securable object", L"MITRE ATT&CK T1222.001" },
        { L"SeDebugPrivilege",           L"open and inject into any process (e.g. lsass)", L"MITRE ATT&CK T1134" },
        { L"SeLoadDriverPrivilege",      L"load a kernel driver (BYOVD)", L"MITRE ATT&CK T1068" },
        { L"SeManageVolumePrivilege",    L"raw volume access enabling arbitrary file write", L"MITRE ATT&CK T1068" },
        { L"SeTcbPrivilege",             L"act as part of the operating system", L"MITRE ATT&CK T1134" },
    };

    for (const auto& p : privs) {
        for (const auto& d : dangerous) {
            if (p.first != d.name) continue;
            PrivEscFinding f;
            f.category = L"Token";
            f.title = String(L"Sensitive privilege held: ") + d.name;
            // Held-and-enabled by a non-elevated/medium token is the strongest
            // signal; High/System integrity holding it is expected but noted.
            bool high_ctx = (integrity == L"High" || integrity == L"System");
            f.risk_level = (p.second && !high_ctx) ? SecurityLevel::High : SecurityLevel::Medium;
            f.description = String(L"The current token holds ") + d.name + L" (" +
                            (p.second ? L"enabled" : L"disabled") + L"), which lets the holder " +
                            d.note + L".";
            f.evidence = L"Privilege=" + p.first + L" | Enabled=" + String(p.second ? L"Yes" : L"No") +
                         L" | IntegrityLevel=" + integrity;
            f.remediation = L"Remove this privilege from the account/group unless the role "
                L"genuinely requires it (Local Security Policy > User Rights Assignment). "
                L"Service accounts rarely need it.";
            f.reference = d.ref;
            Record(f);
        }
    }
    return true;
}

bool PrivEscAnalyzer::CheckScheduledTasks() {
    HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool need_uninit = (init == S_OK || init == S_FALSE);
    if (init != S_OK && init != S_FALSE && init != RPC_E_CHANGED_MODE) {
        return true;
    }

    ITaskService* service = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_ITaskService, reinterpret_cast<void**>(&service))) && service) {
        VARIANT empty; VariantInit(&empty);
        if (SUCCEEDED(service->Connect(empty, empty, empty, empty))) {
            ITaskFolder* root = nullptr;
            BSTR root_path = SysAllocString(L"\\");
            if (SUCCEEDED(service->GetFolder(root_path, &root)) && root) {
                // Walk folders breadth-first.
                std::vector<ITaskFolder*> stack = { root };
                while (!stack.empty()) {
                    ITaskFolder* folder = stack.back();
                    stack.pop_back();

                    IRegisteredTaskCollection* tasks = nullptr;
                    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
                        LONG count = 0; tasks->get_Count(&count);
                        for (LONG i = 1; i <= count; ++i) {
                            IRegisteredTask* task = nullptr;
                            VARIANT vi; VariantInit(&vi); vi.vt = VT_I4; vi.lVal = i;
                            HRESULT gi = tasks->get_Item(vi, &task);
                            VariantClear(&vi);
                            if (FAILED(gi) || !task) continue;

                            BSTR xmlB = nullptr;
                            String xml;
                            if (SUCCEEDED(task->get_Xml(&xmlB)) && xmlB) {
                                xml.assign(xmlB, SysStringLen(xmlB));
                                SysFreeString(xmlB);
                            }
                            BSTR nameB = nullptr; String task_name;
                            if (SUCCEEDED(task->get_Name(&nameB)) && nameB) {
                                task_name.assign(nameB, SysStringLen(nameB));
                                SysFreeString(nameB);
                            }
                            task->Release();

                            // Parse the task XML for a highest/SYSTEM run level
                            // and the <Command> of an exec action. The COM
                            // action/principal objects are awkward under MinGW;
                            // the XML carries the same facts portably.
                            String lx = Core::Utils::ToLower(xml);
                            bool privileged =
                                lx.find(L"<runlevel>highestavailable</runlevel>") != String::npos ||
                                lx.find(L"<logontype>s4u</logontype>") != String::npos ||
                                lx.find(L"<userid>s-1-5-18</userid>") != String::npos ||
                                lx.find(L"localsystem") != String::npos;
                            if (!privileged) continue;

                            size_t cs = lx.find(L"<command>");
                            if (cs == String::npos) continue;
                            size_t ce = lx.find(L"</command>", cs);
                            if (ce == String::npos) continue;
                            // Use original-case slice for the value.
                            String cmd = xml.substr(cs + 9, ce - (cs + 9));
                            cmd = Core::Utils::Trim(cmd);
                            String exe = Core::Utils::ExtractExecutablePath(
                                Core::Utils::ExpandImagePath(cmd));
                            if (exe.empty()) continue;

                            StringVector who;
                            bool exe_w = Core::Utils::IsWritableByNonAdmin(exe, &who);
                            String dir = Core::Utils::GetDirectoryName(exe);
                            StringVector whoDir;
                            bool dir_w = !dir.empty() && Core::Utils::IsWritableByNonAdmin(dir, &whoDir);
                            if (!exe_w && !dir_w) continue;

                            PrivEscFinding f;
                            f.category = L"Scheduled Task";
                            f.title = L"Hijackable scheduled task: " + task_name;
                            f.risk_level = SecurityLevel::High;
                            f.description = L"A scheduled task runs with high/SYSTEM privileges and its "
                                L"executable" + String(exe_w ? L"" : L"'s directory") +
                                L" is writable by a non-administrative principal. Replacing/planting the "
                                L"binary runs code as the task's privileged principal at its next trigger.";
                            f.evidence = L"Task=" + task_name + L" | Binary=" + exe +
                                         L" | Writable by: " + Core::Utils::Join(exe_w ? who : whoDir, L", ") +
                                         L" | " + DescribeBinary(exe);
                            f.remediation = L"Restrict NTFS write/modify on the task binary and its "
                                L"directory to SYSTEM/Administrators, or re-point the task to a protected "
                                L"location.";
                            f.reference = L"MITRE ATT&CK T1053.005 (Scheduled Task)";
                            Record(f);
                        }
                        tasks->Release();
                    }

                    ITaskFolderCollection* subfolders = nullptr;
                    if (SUCCEEDED(folder->GetFolders(0, &subfolders)) && subfolders) {
                        LONG fcount = 0; subfolders->get_Count(&fcount);
                        for (LONG i = 1; i <= fcount; ++i) {
                            ITaskFolder* sub = nullptr;
                            VARIANT vf; VariantInit(&vf); vf.vt = VT_I4; vf.lVal = i;
                            HRESULT gf = subfolders->get_Item(vf, &sub);
                            VariantClear(&vf);
                            if (SUCCEEDED(gf) && sub) {
                                stack.push_back(sub);
                            }
                        }
                        subfolders->Release();
                    }

                    if (folder != root) folder->Release();
                }
                root->Release();
            }
            SysFreeString(root_path);
        }
        service->Release();
    }

    if (need_uninit) CoUninitialize();
    return true;
}

bool PrivEscAnalyzer::CheckExtendedAutoruns() {
    auto flagIfWritable = [&](const String& label, const String& raw_value,
                              const wchar_t* ref) {
        String exe = Core::Utils::ExtractExecutablePath(Core::Utils::ExpandImagePath(raw_value));
        if (exe.empty()) return;
        StringVector who;
        if (!Core::Utils::IsWritableByNonAdmin(exe, &who)) return;
        PrivEscFinding f;
        f.category = L"Autostart";
        f.title = L"Writable autostart target: " + label;
        f.risk_level = SecurityLevel::High;
        f.description = L"An auto-start/extension entry (" + label + L") resolves to a binary "
            L"writable by a non-administrative principal; replacing it executes code in the "
            L"context that loads the entry (often at logon, as the logging-on user or SYSTEM).";
        f.evidence = label + L" -> " + exe + L" | Writable by: " + Core::Utils::Join(who, L", ") +
                     L" | " + DescribeBinary(exe);
        f.remediation = L"Restrict NTFS write/modify on the target to SYSTEM/Administrators, "
            L"or remove the entry if it is not required.";
        f.reference = ref;
        Record(f);
    };

    const wchar_t* winlogon = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    for (const wchar_t* val : { L"Userinit", L"Shell", L"Taskman" }) {
        String v = Core::Utils::ReadRegistryString(HKEY_LOCAL_MACHINE, winlogon, val);
        // Userinit/Shell can be comma-separated lists of commands.
        for (const auto& part : Core::Utils::Split(v, L",")) {
            String p = Core::Utils::Trim(part);
            if (!p.empty()) flagIfWritable(String(L"Winlogon\\") + val, p,
                                           L"MITRE ATT&CK T1547.004 (Winlogon Helper DLL)");
        }
    }

    // AppInit_DLLs (and WOW6432Node): DLLs injected into most GUI processes.
    for (const wchar_t* key : {
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" }) {
        String v = Core::Utils::ReadRegistryString(HKEY_LOCAL_MACHINE, key, L"AppInit_DLLs");
        for (const auto& part : Core::Utils::Split(v, L",")) {
            String p = Core::Utils::Trim(part);
            if (!p.empty()) flagIfWritable(L"AppInit_DLLs", p,
                                           L"MITRE ATT&CK T1546.010 (AppInit DLLs)");
        }
    }

    // Image File Execution Options: a Debugger value hijacks the named program.
    const wchar_t* ifeo = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    for (const auto& sub : Core::Utils::EnumerateRegistrySubkeys(HKEY_LOCAL_MACHINE, ifeo)) {
        String dbg = Core::Utils::ReadRegistryString(HKEY_LOCAL_MACHINE,
                        String(ifeo) + L"\\" + sub, L"Debugger");
        if (!dbg.empty()) {
            flagIfWritable(L"IFEO Debugger for " + sub, dbg,
                           L"MITRE ATT&CK T1546.012 (Image File Execution Options Injection)");
        }
    }
    return true;
}

bool PrivEscAnalyzer::CheckMissingPatches() {
    std::set<String> kbs = Core::Utils::GetInstalledHotfixes();
    const uint32_t build = Core::Utils::GetOsBuildNumber();
    const uint32_t ubr = Core::Utils::GetOsUbr();
    const bool is_dc = Core::Utils::GetOsClassification().family == Core::Utils::OsFamily::DomainController;
    const auto hints = Core::Utils::MissingLpePatchHints(build, kbs, is_dc);
    if (hints.empty()) return true;

    for (const auto& hint : hints) {
        PrivEscFinding f;
        f.category = L"Patch";
        f.title = L"Potential missing LPE patch";
        f.instance_key = hint.cve;               // One finding per CVE, each with its own ID.
        f.confidence = Confidence::Low;          // A KB-list heuristic, not proof.
        f.risk_level = SecurityLevel::Medium;    // Candidate; cumulative updates may supersede.
        f.description = L"A well-known local-privilege-escalation issue has no fixing hotfix among "
            L"the installed KBs. Cumulative updates can supersede the listed KBs, so confirm the "
            L"effective patch level before relying on this.";
        f.evidence = hint.message + L" | OSBuild=" + std::to_wstring(build) +
                     (ubr ? L"." + std::to_wstring(ubr) : String()) +
                     L" | InstalledHotfixes=" + std::to_wstring(kbs.size());
        f.remediation = L"Verify the host's patch level (installed cumulative update) and apply "
            L"the latest security updates if the issue is genuinely unpatched.";
        f.reference = L"MITRE ATT&CK T1068 (Exploitation for Privilege Escalation) / " + hint.cve;
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckCredentialExposure() {
    // All checks are presence/configuration only - no secret value is read.
    const wchar_t* lsa = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";

    // WDigest caches cleartext credentials in LSASS when UseLogonCredential=1.
    auto wdigest = Core::Utils::TryReadRegistryDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"UseLogonCredential");
    if (wdigest && *wdigest == 1) {
        PrivEscFinding f;
        f.category = L"Credentials"; f.title = L"WDigest cleartext credential caching enabled";
        f.risk_level = SecurityLevel::High;
        f.description = L"UseLogonCredential=1 makes WDigest keep plaintext passwords in LSASS "
            L"memory, recoverable by anyone who can read LSASS.";
        f.evidence = L"HKLM\\...\\SecurityProviders\\WDigest\\UseLogonCredential=1";
        f.remediation = L"Set UseLogonCredential=0 (default on supported Windows) and reboot.";
        f.reference = L"MITRE ATT&CK T1003.001 / T1112";
        Record(f);
    }

    // LSASS protection (RunAsPPL) raises the bar for credential dumping.
    auto runasppl = Core::Utils::TryReadRegistryDword(HKEY_LOCAL_MACHINE, lsa, L"RunAsPPL");
    if (!runasppl || *runasppl == 0) {
        PrivEscFinding f;
        f.category = L"Credentials"; f.title = L"LSASS not running as a protected process (RunAsPPL)";
        f.risk_level = SecurityLevel::Medium;
        f.description = L"RunAsPPL is not enabled, so LSASS is not protected as a PPL and its "
            L"memory is easier to read for credential theft.";
        f.evidence = String(L"HKLM\\") + lsa + L"\\RunAsPPL=" + (runasppl ? L"0" : L"(absent)");
        f.remediation = L"Enable LSA protection: set RunAsPPL=1 (and RunAsPPLBoot where supported) "
            L"after confirming driver/AV compatibility; deploy Credential Guard where possible.";
        f.reference = L"MITRE ATT&CK T1003.001";
        Record(f);
    }

    // Credential Guard (LsaCfgFlags: 1=with UEFI lock, 2=without).
    auto credguard = Core::Utils::TryReadRegistryDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\LSA", L"LsaCfgFlags");
    if (!credguard || *credguard == 0) {
        PrivEscFinding f;
        f.category = L"Credentials"; f.title = L"Credential Guard not configured";
        f.risk_level = SecurityLevel::Low;
        f.description = L"Windows Defender Credential Guard is not enabled, so domain "
            L"credentials/secrets are not isolated in a VBS container.";
        f.evidence = L"HKLM\\...\\LSA\\LsaCfgFlags=" + String(credguard ? L"0" : L"(absent)");
        f.remediation = L"Where hardware supports VBS, enable Credential Guard via Group Policy "
            L"(Device Guard > Credential Guard) to isolate LSA secrets.";
        f.reference = L"Microsoft Credential Guard";
        Record(f);
    }

    // Artefacts that frequently hold recoverable secrets (presence only).
    String userprofile;
    {
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", nullptr, 0);
        if (n) { std::vector<wchar_t> b(n); if (GetEnvironmentVariableW(L"USERPROFILE", b.data(), n)) userprofile.assign(b.data()); }
    }
    if (!userprofile.empty()) {
        struct Art { String path; const wchar_t* what; const wchar_t* ref; const wchar_t* key; };
        const Art arts[] = {
            { userprofile + L"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt",
              L"PowerShell console history (often contains passwords in command lines)", L"MITRE ATT&CK T1552.003", L"powershell-history" },
            { userprofile + L"\\.aws\\credentials", L"AWS credentials file", L"MITRE ATT&CK T1552.001", L"aws-credentials" },
            { userprofile + L"\\.azure\\accessTokens.json", L"Azure CLI token cache", L"MITRE ATT&CK T1552.001", L"azure-token-cache" },
            { userprofile + L"\\.kube\\config", L"Kubernetes kubeconfig (cluster credentials)", L"MITRE ATT&CK T1552.001", L"kubeconfig" },
            { userprofile + L"\\AppData\\Roaming\\Microsoft\\Credentials", L"DPAPI-protected Credential Manager store", L"MITRE ATT&CK T1555.004", L"dpapi-credential-store" },
        };
        for (const auto& a : arts) {
            bool exists = Core::Utils::FileExists(a.path) || Core::Utils::DirectoryExists(a.path);
            if (!exists) continue;
            PrivEscFinding f;
            f.category = L"Credentials"; f.title = L"Credential artefact present";
            f.instance_key = a.key;   // Several artefacts, one rule: each gets its own ID.
            f.risk_level = SecurityLevel::Low;
            f.description = String(L"A file/location that commonly stores recoverable secrets is present: ") + a.what +
                L". SysRecon reports its presence only and does not read the contents.";
            f.evidence = L"Path=" + a.path;
            f.remediation = L"Review whether the stored secrets are necessary; remove or protect "
                L"them and rotate any exposed credentials.";
            f.reference = a.ref;
            Record(f);
        }
    }
    return true;
}

bool PrivEscAnalyzer::CheckDefenderPosture() {
    const wchar_t* polDef = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";

    // Defender disabled entirely (policy).
    auto disabled = Core::Utils::TryReadRegistryDword(HKEY_LOCAL_MACHINE, polDef, L"DisableAntiSpyware");
    if (disabled && *disabled == 1) {
        PrivEscFinding f;
        f.category = L"Defender"; f.title = L"Microsoft Defender disabled by policy";
        f.risk_level = SecurityLevel::High;
        f.description = L"DisableAntiSpyware=1 turns Defender off, removing a primary detection control.";
        f.evidence = String(L"HKLM\\") + polDef + L"\\DisableAntiSpyware=1";
        f.remediation = L"Remove the DisableAntiSpyware policy value (or set 0) and confirm Defender "
            L"real-time protection is running.";
        f.reference = L"MITRE ATT&CK T1562.001 (Disable or Modify Tools)";
        Record(f);
    }

    // Exclusions: prime attacker intel (and, for defenders, often over-broad).
    struct ExKind { const wchar_t* sub; const wchar_t* label; };
    const ExKind kinds[] = {
        { L"Paths", L"path" }, { L"Processes", L"process" }, { L"Extensions", L"extension" } };
    for (const wchar_t* root_key : {
            L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions",
            L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions" }) {
        for (const auto& k : kinds) {
            String key = String(root_key) + L"\\" + k.sub;
            StringVector vals = Core::Utils::EnumerateRegistryValues(HKEY_LOCAL_MACHINE, key);
            if (vals.empty()) continue;
            PrivEscFinding f;
            f.category = L"Defender"; f.title = String(L"Defender ") + k.label + L" exclusions configured";
            f.risk_level = SecurityLevel::Medium;
            f.description = L"Defender has " + std::to_wstring(vals.size()) + L" " + k.label +
                L" exclusion(s). Excluded locations are not scanned, so they are ideal staging "
                L"spots for tooling - valuable to an attacker and worth reviewing for over-breadth.";
            String joined = Core::Utils::Join(vals, L", ");
            if (joined.size() > 400) joined = joined.substr(0, 400) + L"...";
            f.evidence = key + L" -> " + joined;
            f.remediation = L"Review each exclusion; remove broad or user-writable paths. Exclusions "
                L"should be specific and justified.";
            f.reference = L"MITRE ATT&CK T1562.001";
            Record(f);
        }
    }

    // Tamper Protection state (informational; often unreadable without SYSTEM).
    auto tamper = Core::Utils::TryReadRegistryDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Features", L"TamperProtection");
    if (tamper && *tamper != 5) {
        PrivEscFinding f;
        f.category = L"Defender"; f.title = L"Defender Tamper Protection not enabled";
        f.risk_level = SecurityLevel::Low;
        f.description = L"Tamper Protection does not appear enabled (value != 5); Defender settings "
            L"are easier to disable by an attacker with local admin.";
        f.evidence = L"HKLM\\...\\Windows Defender\\Features\\TamperProtection=" + std::to_wstring(*tamper);
        f.remediation = L"Enable Tamper Protection (Windows Security > Virus & threat protection "
            L"settings), ideally enforced via Intune.";
        f.reference = L"MITRE ATT&CK T1562.001";
        Record(f);
    }
    return true;
}

bool PrivEscAnalyzer::CheckHardeningBaseline() {
    // Each check mirrors a control applied by hardening/Invoke-SysReconHardening.ps1,
    // so the audit flags exactly what the companion script remediates.
    auto dword = [](HKEY root, const wchar_t* key, const wchar_t* val) {
        return Core::Utils::TryReadRegistryDword(root, key, val);
    };

    // SMBv1 server still enabled.
    auto smb1 = dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SMB1");
    if (!smb1 || *smb1 != 0) {
        PrivEscFinding f;
        f.category = L"Hardening"; f.title = L"SMBv1 server not disabled";
        f.risk_level = SecurityLevel::Medium;
        f.description = L"The SMB1 value is not 0; the legacy SMBv1 protocol may be enabled, exposing "
            L"the host to well-known SMBv1 attacks.";
        f.evidence = L"LanmanServer\\Parameters\\SMB1=" + String(smb1 ? std::to_wstring(*smb1) : L"(absent)");
        f.remediation = L"Disable SMBv1 (set SMB1=0 / remove the SMB1 feature). CIS 18.3.1. The "
            L"companion hardening script applies this.";
        f.reference = L"CIS 18.3.1";
        Record(f);
    }

    // SMB server signing not required.
    auto smbsign = dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"RequireSecuritySignature");
    if (!smbsign || *smbsign != 1) {
        PrivEscFinding f;
        f.category = L"Hardening"; f.title = L"SMB signing not required (server)";
        f.risk_level = SecurityLevel::Medium;
        f.description = L"RequireSecuritySignature!=1: the SMB server does not require signing, "
            L"enabling SMB relay / man-in-the-middle.";
        f.evidence = L"LanmanServer\\Parameters\\RequireSecuritySignature=" +
                     String(smbsign ? std::to_wstring(*smbsign) : L"(absent)");
        f.remediation = L"Require SMB signing (RequireSecuritySignature=1). CIS 2.3.9.x.";
        f.reference = L"CIS 2.3.9 / MITRE ATT&CK T1557.001";
        Record(f);
    }

    // LLMNR still enabled (poisoning / relay).
    auto llmnr = dword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"EnableMulticast");
    if (!llmnr || *llmnr != 0) {
        PrivEscFinding f;
        f.category = L"Hardening"; f.title = L"LLMNR not disabled";
        f.risk_level = SecurityLevel::Medium;
        f.description = L"EnableMulticast!=0: LLMNR is active, which Responder-style tools abuse to "
            L"poison name resolution and capture NetNTLM hashes.";
        f.evidence = L"DNSClient\\EnableMulticast=" + String(llmnr ? std::to_wstring(*llmnr) : L"(absent)");
        f.remediation = L"Disable LLMNR (EnableMulticast=0) via GPO. CIS 18.5.4.2.";
        f.reference = L"CIS 18.5.4.2 / MITRE ATT&CK T1557.001";
        Record(f);
    }

    // LM/NTLMv1 permitted.
    auto lmcompat = dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LmCompatibilityLevel");
    if (!lmcompat || *lmcompat < 5) {
        PrivEscFinding f;
        f.category = L"Hardening"; f.title = L"Weak LAN Manager authentication level";
        f.risk_level = SecurityLevel::Medium;
        f.description = L"LmCompatibilityLevel<5 allows LM/NTLMv1 responses, which are trivially "
            L"crackable/relayable.";
        f.evidence = L"Lsa\\LmCompatibilityLevel=" + String(lmcompat ? std::to_wstring(*lmcompat) : L"(absent)");
        f.remediation = L"Set LmCompatibilityLevel=5 (send NTLMv2 only, refuse LM & NTLM). CIS 2.3.11.7.";
        f.reference = L"CIS 2.3.11.7";
        Record(f);
    }

    // PowerShell Script Block logging disabled.
    auto pslog = dword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        L"EnableScriptBlockLogging");
    if (!pslog || *pslog != 1) {
        PrivEscFinding f;
        f.category = L"Hardening"; f.title = L"PowerShell Script Block logging disabled";
        f.risk_level = SecurityLevel::Low;
        f.description = L"Script Block logging is not enabled, reducing visibility of malicious "
            L"PowerShell for defenders and incident response.";
        f.evidence = L"ScriptBlockLogging\\EnableScriptBlockLogging=" +
                     String(pslog ? std::to_wstring(*pslog) : L"(absent)");
        f.remediation = L"Enable Script Block logging (EnableScriptBlockLogging=1) via GPO.";
        f.reference = L"MITRE ATT&CK T1059.001 (defensive logging)";
        Record(f);
    }

    // LAPS presence (managed local-admin password rotation).
    bool laps = Core::Utils::RegistryKeyExists(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") ||
                Core::Utils::FileExists(L"C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll");
    if (!laps) {
        PrivEscFinding f;
        f.category = L"Hardening"; f.title = L"LAPS not detected";
        f.risk_level = SecurityLevel::Low;
        f.description = L"No sign of LAPS / Windows LAPS. Without managed, unique local-admin "
            L"passwords, a single recovered local-admin hash enables lateral movement across hosts.";
        f.evidence = L"No AdmPwd policy key or CSE present";
        f.remediation = L"Deploy Windows LAPS to randomise and rotate the local Administrator "
            L"password per machine.";
        f.reference = L"MITRE ATT&CK T1078.003 (mitigation)";
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
bool PrivEscAnalyzer::CheckTokenPrivileges()           { return true; }
bool PrivEscAnalyzer::CheckScheduledTasks()            { return true; }
bool PrivEscAnalyzer::CheckExtendedAutoruns()          { return true; }
bool PrivEscAnalyzer::CheckMissingPatches()            { return true; }
bool PrivEscAnalyzer::CheckCredentialExposure()        { return true; }
bool PrivEscAnalyzer::CheckDefenderPosture()           { return true; }
bool PrivEscAnalyzer::CheckHardeningBaseline()         { return true; }

#endif

} // namespace Modules
} // namespace SysRecon
