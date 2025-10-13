#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

struct UserAccount {
    String username;
    String full_name;
    String description;
    String home_directory;
    String profile_path;
    String sid;
    DWORD user_id;
    DWORD primary_group_id;
    DWORD flags;
    std::chrono::system_clock::time_point last_logon;
    std::chrono::system_clock::time_point password_last_set;
    std::chrono::system_clock::time_point account_expires;
    bool is_enabled;
    bool is_locked;
    bool password_never_expires;
    bool password_required;
    bool is_admin;
    StringVector group_memberships;
    StringVector privileges;
};

struct GroupInfo {
    String group_name;
    String description;
    String sid;
    DWORD group_id;
    StringVector members;
    bool is_system_group;
};

class UserEnumerator {
public:
    UserEnumerator();
    ~UserEnumerator();
    
    // Main enumeration methods
    bool Initialize();
    bool EnumerateUsers();
    bool EnumerateGroups();
    bool AnalyzePermissions();
    bool CheckPasswordPolicies();
    void Cleanup();
    
    // Results access
    const std::vector<UserAccount>& GetUsers() const { return users_; }
    const std::vector<GroupInfo>& GetGroups() const { return groups_; }
    const ScanResults& GetScanResults() const { return scan_results_; }
    
    // Configuration
    void SetEnumerateGroups(bool enable) { enumerate_groups_ = enable; }
    void SetAnalyzePermissions(bool enable) { analyze_permissions_ = enable; }
    void SetCheckPasswords(bool enable) { check_passwords_ = enable; }
    
    // Analysis methods
    bool IsUserAdmin(const String& username);
    bool IsUserInGroup(const String& username, const String& group_name);
    SecurityLevel AssessUserRisk(const UserAccount& user);
    StringVector FindWeakPasswords();
    StringVector FindUnusedAccounts();
    StringVector FindPrivilegedAccounts();
    
private:
    // Internal enumeration methods
    bool EnumerateLocalUsers();
    bool EnumerateDomainUsers();
    bool EnumerateLocalGroups();
    bool EnumerateDomainGroups();
    bool GetUserDetails(const String& username, UserAccount& user);
    bool GetGroupMembers(const String& group_name, StringVector& members);
    bool GetUserPrivileges(const String& username, StringVector& privileges);
    
    // Analysis helpers
    void AnalyzeUserAccount(const UserAccount& user);
    void AnalyzeGroupMembership(const GroupInfo& group);
    void CheckPasswordPolicy();
    void CheckAccountLockoutPolicy();
    void CheckUserRights();
    
    // Utility methods
    String SidToString(PSID sid);
    bool GetAccountSid(const String& account_name, String& sid);
    DWORD GetUserFlags(const String& username);
    std::chrono::system_clock::time_point FileTimeToSystemTime(const FILETIME& ft);
    
    // Configuration
    bool enumerate_groups_;
    bool analyze_permissions_;
    bool check_passwords_;
    
    // Data storage
    std::vector<UserAccount> users_;
    std::vector<GroupInfo> groups_;
    ScanResults scan_results_;
    
    // State
    bool initialized_;
    StringVector error_messages_;
};

} // namespace Modules
} // namespace SysRecon
