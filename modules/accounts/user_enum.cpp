#include "../../include/modules/accounts/user_enum.h"
#include "../../include/core/utils.h"

namespace SysRecon {
namespace Modules {

UserEnumerator::UserEnumerator() 
    : enumerate_groups_(true)
    , initialized_(false) {
}

UserEnumerator::~UserEnumerator() {
    Cleanup();
}

bool UserEnumerator::Initialize() {
    SYSRECON_LOG_INFO_CTX(L"UserEnumerator", L"Initialize", L"Initializing user enumeration module");
    
    if (initialized_) {
        return true;
    }
    
    // SeDebugPrivilege is enabled once by ScanEngine::Initialize; it is
    // process-wide and this module does not need it.

    initialized_ = true;
    return true;
}

bool UserEnumerator::EnumerateUsers() {
    if (!initialized_) {
        SYSRECON_LOG_ERROR_CTX(L"UserEnumerator", L"EnumerateUsers", L"Module not initialized");
        return false;
    }
    
    SYSRECON_LOG_INFO_CTX(L"UserEnumerator", L"EnumerateUsers", L"Starting user enumeration");
    
    users_.clear();
    LoadAdministratorMembers();

    bool success = true;
    if (!EnumerateLocalUsers()) {
        success = false;
    }
    
    if (!EnumerateDomainUsers()) {
        SYSRECON_LOG_DEBUG_CTX(L"UserEnumerator", L"EnumerateUsers", L"Domain user enumeration failed (expected on standalone systems)");
    }
    
    for (const auto& user : users_) {
        AnalyzeUserAccount(user);
    }
    
    SYSRECON_LOG_INFO_CTX(L"UserEnumerator", L"EnumerateUsers", 
                          L"Enumerated " + std::to_wstring(users_.size()) + L" user accounts");
    
    return success;
}

bool UserEnumerator::EnumerateGroups() {
    if (!initialized_ || !enumerate_groups_) {
        return true;
    }
    
    SYSRECON_LOG_INFO_CTX(L"UserEnumerator", L"EnumerateGroups", L"Starting group enumeration");
    
    groups_.clear();
    
    bool success = true;
    if (!EnumerateLocalGroups()) {
        success = false;
    }
    
    if (!EnumerateDomainGroups()) {
        SYSRECON_LOG_DEBUG_CTX(L"UserEnumerator", L"EnumerateGroups", L"Domain group enumeration failed");
    }
    
    SYSRECON_LOG_INFO_CTX(L"UserEnumerator", L"EnumerateGroups", 
                          L"Enumerated " + std::to_wstring(groups_.size()) + L" groups");
    
    return success;
}


void UserEnumerator::Cleanup() {
    users_.clear();
    groups_.clear();
    scan_results_.clear();
    error_messages_.clear();
    initialized_ = false;
}

bool UserEnumerator::EnumerateLocalUsers() {
#ifdef _WIN32
    SYSRECON_LOG_DEBUG_CTX(L"UserEnumerator", L"EnumerateLocalUsers", L"Enumerating local users");
    
    LPUSER_INFO_3 pBuffer = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS nStatus;
    
    do {
        nStatus = NetUserEnum(
            nullptr,                    // local computer
            3,                          // information level (USER_INFO_3)
            FILTER_NORMAL_ACCOUNT,     // filter normal accounts
            (LPBYTE*)&pBuffer,
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );
        
        if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                USER_INFO_3* pUserInfo = &pBuffer[i];
                
                UserAccount user;
                user.username = pUserInfo->usri3_name ? String(pUserInfo->usri3_name) : L"";
                user.full_name = pUserInfo->usri3_full_name ? String(pUserInfo->usri3_full_name) : L"";
                user.description = pUserInfo->usri3_comment ? String(pUserInfo->usri3_comment) : L"";
                user.home_directory = pUserInfo->usri3_home_dir ? String(pUserInfo->usri3_home_dir) : L"";
                user.profile_path = pUserInfo->usri3_profile ? String(pUserInfo->usri3_profile) : L"";
                user.user_id = pUserInfo->usri3_user_id;
                user.primary_group_id = pUserInfo->usri3_primary_group_id;
                user.flags = pUserInfo->usri3_flags;
                
                // Parse flags
                user.is_enabled = !(pUserInfo->usri3_flags & UF_ACCOUNTDISABLE);
                user.is_locked = (pUserInfo->usri3_flags & UF_LOCKOUT) != 0;
                user.password_never_expires = (pUserInfo->usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0;
                user.password_required = !(pUserInfo->usri3_flags & UF_PASSWD_NOTREQD);
                
                // Membership of BUILTIN\Administrators by SID, not by the
                // English group name, which does not exist on localised Windows.
                user.is_admin = IsAdministratorMember(user.username);
                
                // Get SID
                PSID pSid = nullptr;
                DWORD cbSid = 0;
                SID_NAME_USE sidType;
                wchar_t* domainName = nullptr;
                DWORD cbDomain = 0;
                
                // First call is expected to fail with ERROR_INSUFFICIENT_BUFFER
                // and report the required sizes. Any other failure (notably
                // ERROR_NONE_MAPPED) means there is no SID to look up, and
                // proceeding would allocate and read garbage.
                LookupAccountNameW(nullptr, user.username.c_str(), nullptr, &cbSid,
                                   nullptr, &cbDomain, &sidType);

                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cbSid > 0 && cbDomain > 0) {
                    pSid = (PSID)LocalAlloc(LPTR, cbSid);
                    domainName = (wchar_t*)LocalAlloc(LPTR, cbDomain * sizeof(wchar_t));

                    if (pSid && domainName &&
                        LookupAccountNameW(nullptr, user.username.c_str(), pSid, &cbSid,
                                           domainName, &cbDomain, &sidType)) {
                        user.sid = SidToString(pSid);
                    }

                    if (pSid) LocalFree(pSid);
                    if (domainName) LocalFree(domainName);
                }
                
                // Convert timestamps
                // USER_INFO_3 time fields are seconds since 1970-01-01 UTC, not
                // FILETIME. They were previously packed into a FILETIME and run
                // through the 1601-epoch conversion, which subtracted ~1.16e17
                // from a value of ~1.7e9 and produced dates roughly 3600 years
                // in the past.
                if (pUserInfo->usri3_last_logon != 0) {
                    user.last_logon = std::chrono::system_clock::from_time_t(
                        static_cast<time_t>(pUserInfo->usri3_last_logon));
                }

                if (pUserInfo->usri3_password_age != 0) {
                    auto now = std::chrono::system_clock::now();
                    user.password_last_set = now - std::chrono::seconds(pUserInfo->usri3_password_age);
                }

                if (pUserInfo->usri3_acct_expires != TIMEQ_FOREVER &&
                    pUserInfo->usri3_acct_expires != 0) {
                    user.account_expires = std::chrono::system_clock::from_time_t(
                        static_cast<time_t>(pUserInfo->usri3_acct_expires));
                }
                
                users_.push_back(user);
            }
            
            if (pBuffer != nullptr) {
                NetApiBufferFree(pBuffer);
                pBuffer = nullptr;
            }
        }
        else {
            SYSRECON_LOG_ERROR_CTX(L"UserEnumerator", L"EnumerateLocalUsers", 
                                   L"NetUserEnum failed with error: " + std::to_wstring(nStatus));
            return false;
        }
        
    } while (nStatus == ERROR_MORE_DATA);
    
    SYSRECON_LOG_DEBUG_CTX(L"UserEnumerator", L"EnumerateLocalUsers", 
                          L"Enumerated " + std::to_wstring(users_.size()) + L" local users");
    
    return true;
#else
    SYSRECON_LOG_WARNING_CTX(L"UserEnumerator", L"EnumerateLocalUsers", 
                             L"Not running on Windows - cross-compilation stub");
    return false;
#endif
}

bool UserEnumerator::EnumerateDomainUsers() {
    return false;
}

bool UserEnumerator::EnumerateLocalGroups() {
#ifdef _WIN32
    SYSRECON_LOG_DEBUG_CTX(L"UserEnumerator", L"EnumerateLocalGroups", L"Enumerating local groups");
    
    LPLOCALGROUP_INFO_1 pBuffer = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD_PTR dwResumeHandle = 0;
    NET_API_STATUS nStatus;
    
    do {
        nStatus = NetLocalGroupEnum(
            nullptr,                     // local computer
            1,                           // information level
            (LPBYTE*)&pBuffer,
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );
        
        if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                LOCALGROUP_INFO_1* pGroupInfo = &pBuffer[i];
                
                GroupInfo group;
                group.group_name = pGroupInfo->lgrpi1_name ? String(pGroupInfo->lgrpi1_name) : L"";
                group.description = pGroupInfo->lgrpi1_comment ? String(pGroupInfo->lgrpi1_comment) : L"";
                group.is_system_group = true;  // Local groups are considered system groups
                
                // Get group SID
                PSID pSid = nullptr;
                DWORD cbSid = 0;
                SID_NAME_USE sidType;
                wchar_t* domainName = nullptr;
                DWORD cbDomain = 0;
                
                LookupAccountNameW(nullptr, group.group_name.c_str(), nullptr, &cbSid, nullptr, &cbDomain, &sidType);
                
                if (cbSid > 0) {
                    pSid = (PSID)LocalAlloc(LPTR, cbSid);
                    domainName = (wchar_t*)LocalAlloc(LPTR, cbDomain * sizeof(wchar_t));
                    
                    if (LookupAccountNameW(nullptr, group.group_name.c_str(), pSid, &cbSid, domainName, &cbDomain, &sidType)) {
                        group.sid = SidToString(pSid);
                    }
                    
                    if (pSid) LocalFree(pSid);
                    if (domainName) LocalFree(domainName);
                }
                
                // Get group members
                GetGroupMembers(group.group_name, group.members);
                
                groups_.push_back(group);
            }
            
            if (pBuffer != nullptr) {
                NetApiBufferFree(pBuffer);
                pBuffer = nullptr;
            }
        }
        else {
            SYSRECON_LOG_ERROR_CTX(L"UserEnumerator", L"EnumerateLocalGroups",
                                   L"NetLocalGroupEnum failed with error: " + std::to_wstring(nStatus));
            return false;
        }
        
    } while (nStatus == ERROR_MORE_DATA);
    
    SYSRECON_LOG_DEBUG_CTX(L"UserEnumerator", L"EnumerateLocalGroups",
                          L"Enumerated " + std::to_wstring(groups_.size()) + L" local groups");
    
    return true;
#else
    SYSRECON_LOG_WARNING_CTX(L"UserEnumerator", L"EnumerateLocalGroups",
                             L"Not running on Windows - cross-compilation stub");
    return false;
#endif
}

bool UserEnumerator::EnumerateDomainGroups() {
    return false;
}

namespace {
// Well-known RIDs. The built-in accounts are identified by RID, not by name:
// renaming "Administrator" is a common (and CIS-recommended) step, and the
// name check let a renamed-but-enabled built-in admin go unreported.
constexpr DWORD kBuiltinAdministratorRid = 500;
constexpr DWORD kBuiltinGuestRid = 501;
}

void UserEnumerator::AnalyzeUserAccount(const UserAccount& user) {
    SecurityLevel risk_level = AssessUserRisk(user);

    ScanResult result;
    result.module_name = L"User Accounts";
    result.item_name = user.username;
    result.description = user.full_name.empty() ? L"Local user account"
                                                : L"Local user account: " + user.full_name;
    result.risk_level = risk_level;
    result.timestamp = std::chrono::system_clock::now();

    result.details[L"Full Name"] = user.full_name;
    result.details[L"Description"] = user.description;
    result.details[L"RID"] = std::to_wstring(user.user_id);
    if (!user.sid.empty()) {
        result.details[L"SID"] = user.sid;
    }
    result.details[L"Enabled"] = user.is_enabled ? L"Yes" : L"No";
    result.details[L"Admin"] = user.is_admin ? L"Yes" : L"No";
    result.details[L"Password Never Expires"] = user.password_never_expires ? L"Yes" : L"No";
    result.details[L"Password Required"] = user.password_required ? L"Yes" : L"No";

    StringVector issues;
    if (user.is_enabled && user.user_id == kBuiltinAdministratorRid) {
        issues.push_back(L"Built-in Administrator (RID 500) is enabled");
    }
    if (user.is_enabled && user.user_id == kBuiltinGuestRid) {
        issues.push_back(L"Guest account (RID 501) is enabled");
    }
    if (user.is_enabled && !user.password_required) {
        issues.push_back(L"Account may have an empty password (UF_PASSWD_NOTREQD)");
    }
    if (!issues.empty()) {
        result.details[L"Issues"] = Core::Utils::Join(issues, L"; ");
        result.details[L"Technique"] = L"T1078.001 Valid Accounts: Default Accounts";
    }

    scan_results_.push_back(result);
}

SecurityLevel UserEnumerator::AssessUserRisk(const UserAccount& user) {
    SecurityLevel risk = SecurityLevel::Low;
    if (!user.is_enabled) {
        return risk;
    }

    if (user.is_admin) {
        risk = SecurityLevel::High;
    }
    if (user.password_never_expires) {
        risk = std::max(risk, SecurityLevel::Medium);
    }
    if (!user.password_required) {
        risk = std::max(risk, SecurityLevel::High);
    }
    if (user.user_id == kBuiltinGuestRid) {
        risk = std::max(risk, SecurityLevel::High);
    }
    if (user.user_id == kBuiltinAdministratorRid) {
        risk = SecurityLevel::Critical;
    }
    return risk;
}

void UserEnumerator::LoadAdministratorMembers() {
    admin_members_.clear();
    admin_members_loaded_ = false;
#ifdef _WIN32
    // Resolve the localised name of BUILTIN\Administrators from its SID.
    BYTE sid_buffer[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid_buffer);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid_buffer, &sid_size)) {
        return;
    }
    wchar_t name[256];
    wchar_t domain[256];
    DWORD name_len = 256;
    DWORD domain_len = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, sid_buffer, name, &name_len, domain, &domain_len, &use)) {
        return;
    }

    StringVector members;
    if (!GetGroupMembers(String(name, name_len), members)) {
        return;
    }
    for (const auto& member : members) {
        const String lower = Core::Utils::ToLower(member);
        admin_members_.insert(lower);
        const size_t slash = lower.find(L'\\');
        if (slash != String::npos) {
            admin_members_.insert(lower.substr(slash + 1));
        }
    }
    admin_members_loaded_ = true;
#endif
}

bool UserEnumerator::IsAdministratorMember(const String& username) const {
    return admin_members_.count(Core::Utils::ToLower(username)) > 0;
}

bool UserEnumerator::AnalyzePasswordPolicy() {
    if (!initialized_) {
        return false;
    }
#ifdef _WIN32
    SYSRECON_LOG_INFO_CTX(L"UserEnumerator", L"AnalyzePasswordPolicy", L"Analyzing local password policy");

    USER_MODALS_INFO_0* policy = nullptr;
    NET_API_STATUS status = NetUserModalsGet(nullptr, 0, reinterpret_cast<LPBYTE*>(&policy));
    if (status != NERR_Success || policy == nullptr) {
        SYSRECON_LOG_ERROR_CTX(L"UserEnumerator", L"AnalyzePasswordPolicy",
                               L"NetUserModalsGet(0) failed: " + std::to_wstring(status));
        return false;
    }
    const DWORD min_len = policy->usrmod0_min_passwd_len;
    const DWORD max_age = policy->usrmod0_max_passwd_age;
    const DWORD history = policy->usrmod0_password_hist_len;
    NetApiBufferFree(policy);

    USER_MODALS_INFO_3* lockout = nullptr;
    status = NetUserModalsGet(nullptr, 3, reinterpret_cast<LPBYTE*>(&lockout));
    if (status != NERR_Success || lockout == nullptr) {
        SYSRECON_LOG_ERROR_CTX(L"UserEnumerator", L"AnalyzePasswordPolicy",
                               L"NetUserModalsGet(3) failed: " + std::to_wstring(status));
        return false;
    }
    const DWORD threshold = lockout->usrmod3_lockout_threshold;
    const DWORD duration = lockout->usrmod3_lockout_duration;
    NetApiBufferFree(lockout);

    auto add = [this](const String& item, const String& description, SecurityLevel level,
                      const String& current, const String& recommended, const String& technique) {
        ScanResult r;
        r.module_name = L"Account Policy";
        r.item_name = item;
        r.description = description;
        r.risk_level = level;
        r.details[L"Current"] = current;
        r.details[L"Recommended (CIS L1)"] = recommended;
        r.details[L"Technique"] = technique;
        r.details[L"Remediation"] = L"Invoke-SysReconHardening.ps1 -Include AccountPolicy";
        r.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(r);
    };

    const String brute = L"T1110 Brute Force";
    if (min_len < 14) {
        add(L"Minimum password length", L"Minimum password length is below the CIS baseline",
            min_len < 8 ? SecurityLevel::High : SecurityLevel::Medium,
            std::to_wstring(min_len), L">= 14", brute);
    }
    if (threshold == 0) {
        add(L"Account lockout", L"Account lockout is disabled: unlimited password guessing",
            SecurityLevel::Medium, L"0 (never lock)", L"1-5 attempts", brute);
    } else if (threshold > 5) {
        add(L"Account lockout", L"Account lockout threshold is above the CIS baseline",
            SecurityLevel::Low, std::to_wstring(threshold), L"1-5 attempts", brute);
    }
    if (threshold != 0 && duration != TIMEQ_FOREVER && duration < 15 * 60) {
        add(L"Lockout duration", L"Lockout duration is shorter than the CIS baseline",
            SecurityLevel::Low, std::to_wstring(duration / 60) + L" min", L">= 15 min", brute);
    }
    if (max_age == TIMEQ_FOREVER) {
        add(L"Maximum password age", L"Passwords never expire by policy",
            SecurityLevel::Low, L"Never", L"<= 365 days", L"T1078 Valid Accounts");
    }
    if (history < 24) {
        add(L"Password history", L"Password history is shorter than the CIS baseline",
            SecurityLevel::Low, std::to_wstring(history), L">= 24", L"T1078 Valid Accounts");
    }
    return true;
#else
    return true;
#endif
}

StringVector UserEnumerator::FindWeakPasswords() {
    StringVector weak_users;
    return weak_users;
}

StringVector UserEnumerator::FindUnusedAccounts() {
    StringVector unused_users;
    return unused_users;
}

StringVector UserEnumerator::FindPrivilegedAccounts() {
    StringVector privileged_users;
    
    for (const auto& user : users_) {
        if (user.is_admin) {
            privileged_users.push_back(user.username);
        }
    }
    
    return privileged_users;
}

bool UserEnumerator::IsUserAdmin(const String& username) {
    for (const auto& user : users_) {
        if (user.username == username) {
            return user.is_admin;
        }
    }
    return false;
}

bool UserEnumerator::IsUserInGroup(const String& username, const String& group_name) {
#ifdef _WIN32
    LPLOCALGROUP_MEMBERS_INFO_3 pBuffer = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    
    nStatus = NetLocalGroupGetMembers(
        nullptr,                          // local computer
        group_name.c_str(),              // group name
        3,                               // information level
        (LPBYTE*)&pBuffer,
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        nullptr
    );
    
    if (nStatus == NERR_Success) {
        for (DWORD i = 0; i < dwEntriesRead; i++) {
            if (pBuffer[i].lgrmi3_domainandname) {
                String member_name(pBuffer[i].lgrmi3_domainandname);
                // Extract just the username if domain\username format
                size_t backslash_pos = member_name.find(L'\\');
                if (backslash_pos != String::npos) {
                    member_name = member_name.substr(backslash_pos + 1);
                }
                
                if (Core::Utils::ToLower(member_name) == Core::Utils::ToLower(username)) {
                    NetApiBufferFree(pBuffer);
                    return true;
                }
            }
        }
        NetApiBufferFree(pBuffer);
    }
#endif
    return false;
}

bool UserEnumerator::GetGroupMembers(const String& group_name, StringVector& members) {
#ifdef _WIN32
    LPLOCALGROUP_MEMBERS_INFO_3 pBuffer = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    
    nStatus = NetLocalGroupGetMembers(
        nullptr,
        group_name.c_str(),
        3,
        (LPBYTE*)&pBuffer,
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        nullptr
    );
    
    if (nStatus == NERR_Success) {
        for (DWORD i = 0; i < dwEntriesRead; i++) {
            if (pBuffer[i].lgrmi3_domainandname) {
                members.push_back(String(pBuffer[i].lgrmi3_domainandname));
            }
        }
        NetApiBufferFree(pBuffer);
        return true;
    }
#endif
    return false;
}

String UserEnumerator::SidToString(PSID sid) {
#ifdef _WIN32
    if (!sid) return L"";
    
    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(sid, &sidString)) {
        String result(sidString);
        LocalFree(sidString);
        return result;
    }
#endif
    return L"";
}

std::chrono::system_clock::time_point UserEnumerator::FileTimeToSystemTime(const FILETIME& ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    
    // FILETIME is 100-nanosecond intervals since January 1, 1601
    // Convert to microseconds since Unix epoch
    const int64_t UNIX_TIME_START = 0x019DB1DED53E8000LL; // January 1, 1970 in FILETIME
    int64_t microseconds = (ull.QuadPart - UNIX_TIME_START) / 10;
    
    return std::chrono::system_clock::time_point(std::chrono::microseconds(microseconds));
}

bool UserEnumerator::GetUserDetails(const String& username, UserAccount& user) {
#ifdef _WIN32
    USER_INFO_3* pBuffer = nullptr;
    NET_API_STATUS nStatus = NetUserGetInfo(nullptr, username.c_str(), 3, (LPBYTE*)&pBuffer);
    
    if (nStatus == NERR_Success && pBuffer) {
        user.username = username;
        user.full_name = pBuffer->usri3_full_name ? String(pBuffer->usri3_full_name) : L"";
        user.description = pBuffer->usri3_comment ? String(pBuffer->usri3_comment) : L"";
        user.home_directory = pBuffer->usri3_home_dir ? String(pBuffer->usri3_home_dir) : L"";
        user.flags = pBuffer->usri3_flags;
        user.is_enabled = !(pBuffer->usri3_flags & UF_ACCOUNTDISABLE);
        user.password_never_expires = (pBuffer->usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0;
        
        NetApiBufferFree(pBuffer);
        return true;
    }
#endif
    return false;
}

DWORD UserEnumerator::GetUserFlags(const String& username) {
#ifdef _WIN32
    USER_INFO_1* pBuffer = nullptr;
    NET_API_STATUS nStatus = NetUserGetInfo(nullptr, username.c_str(), 1, (LPBYTE*)&pBuffer);
    
    if (nStatus == NERR_Success && pBuffer) {
        DWORD flags = pBuffer->usri1_flags;
        NetApiBufferFree(pBuffer);
        return flags;
    }
#endif
    return 0;
}

}
}
