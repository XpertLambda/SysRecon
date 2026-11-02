#include "../../include/modules/domain/domain_recon.h"
#include "../../include/core/utils.h"

#ifdef _WIN32
#include <dsgetdc.h>
#include <lm.h>
#endif

namespace SysRecon {
namespace Modules {

DomainReconAnalyzer::DomainReconAnalyzer() = default;
DomainReconAnalyzer::~DomainReconAnalyzer() { Cleanup(); }

bool DomainReconAnalyzer::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Domain Recon module");
    initialized_ = true;
    return true;
}

void DomainReconAnalyzer::Cleanup() {
    scan_results_.clear();
    initialized_ = false;
}

void DomainReconAnalyzer::Record(const String& item, const String& description,
                                 SecurityLevel risk, const StringMap& details,
                                 const String& remediation, const String& reference) {
    ScanResult r;
    r.module_name = L"Domain";
    r.item_name = item;
    r.description = description;
    r.risk_level = risk;
    r.details = details;
    r.remediation = remediation;
    r.reference = reference;
    r.timestamp = std::chrono::system_clock::now();
    scan_results_.push_back(r);
}

#ifdef _WIN32

bool DomainReconAnalyzer::IsDomainJoined(String& domain_out) {
    LPWSTR name = nullptr;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    if (NetGetJoinInformation(nullptr, &name, &status) != NERR_Success) {
        return false;
    }
    bool joined = (status == NetSetupDomainName);
    if (joined && name) domain_out = name;
    if (name) NetApiBufferFree(name);
    return joined;
}

void DomainReconAnalyzer::CheckDomainController(const String& domain) {
    PDOMAIN_CONTROLLER_INFOW dci = nullptr;
    DWORD rc = DsGetDcNameW(nullptr, domain.empty() ? nullptr : domain.c_str(),
                            nullptr, nullptr, DS_RETURN_DNS_NAME, &dci);
    StringMap d;
    d[L"Domain"] = domain;
    if (rc == ERROR_SUCCESS && dci) {
        if (dci->DomainControllerName) d[L"Domain Controller"] = dci->DomainControllerName;
        if (dci->DomainName) d[L"DNS Domain"] = dci->DomainName;
        if (dci->DnsForestName) d[L"Forest"] = dci->DnsForestName;
        NetApiBufferFree(dci);
    }
    Record(L"Domain membership", L"Host is joined to an Active Directory domain.",
           SecurityLevel::Low, d, L"Informational; confirms the AD context of the host.",
           L"Situational awareness");
}

void DomainReconAnalyzer::CheckPasswordPolicy() {
    // Account policy from the DC the host trusts. Level 0 carries the password
    // constraints; level 3 carries lockout.
    USER_MODALS_INFO_0* p0 = nullptr;
    if (NetUserModalsGet(nullptr, 0, reinterpret_cast<LPBYTE*>(&p0)) == NERR_Success && p0) {
        DWORD min_len = p0->usrmod0_min_passwd_len;
        DWORD max_age_days = (p0->usrmod0_max_passwd_age == TIMEQ_FOREVER)
                                 ? 0 : p0->usrmod0_max_passwd_age / 86400;
        StringMap d;
        d[L"Min password length"] = std::to_wstring(min_len);
        d[L"Max password age (days)"] = (max_age_days == 0) ? L"unlimited" : std::to_wstring(max_age_days);
        d[L"Password history"] = std::to_wstring(p0->usrmod0_password_hist_len);

        SecurityLevel risk = SecurityLevel::Low;
        String note;
        if (min_len < 14) { risk = SecurityLevel::Medium; note += L"Minimum length below 14. "; }
        if (max_age_days == 0) { note += L"Passwords never expire. "; }
        Record(L"Domain password policy",
               note.empty() ? L"Domain account password policy." : L"Weak domain password policy: " + note,
               risk, d,
               L"Align with policy: minimum length >= 14, enforce history and a rotation "
               L"period, per CIS Account Policies.",
               L"CIS 1.1 (Password Policy)");
        NetApiBufferFree(p0);
    }

    USER_MODALS_INFO_3* p3 = nullptr;
    if (NetUserModalsGet(nullptr, 3, reinterpret_cast<LPBYTE*>(&p3)) == NERR_Success && p3) {
        StringMap d;
        d[L"Lockout threshold"] = (p3->usrmod3_lockout_threshold == 0)
                                    ? L"disabled" : std::to_wstring(p3->usrmod3_lockout_threshold);
        SecurityLevel risk = (p3->usrmod3_lockout_threshold == 0) ? SecurityLevel::Medium : SecurityLevel::Low;
        Record(L"Domain account lockout policy",
               (p3->usrmod3_lockout_threshold == 0)
                   ? L"Account lockout is disabled, permitting unlimited online password guessing."
                   : L"Domain account lockout policy.",
               risk, d,
               L"Set a lockout threshold (e.g. 5-10 attempts) with an observation window, "
               L"per CIS Account Lockout Policy.",
               L"CIS 1.2 (Account Lockout Policy)");
        NetApiBufferFree(p3);
    }
}

void DomainReconAnalyzer::CheckDomainAdmins() {
    // Resolve a DC to query the domain group against.
    PDOMAIN_CONTROLLER_INFOW dci = nullptr;
    if (DsGetDcNameW(nullptr, nullptr, nullptr, nullptr, DS_RETURN_DNS_NAME, &dci) != ERROR_SUCCESS || !dci) {
        return;
    }
    const wchar_t* dc = dci->DomainControllerName;  // "\\\\dc.domain"

    StringVector members;
    LPGROUP_USERS_INFO_0 buf = nullptr;
    DWORD read = 0, total = 0;
    NET_API_STATUS rc = NetGroupGetUsers(dc, L"Domain Admins", 0,
                                         reinterpret_cast<LPBYTE*>(&buf), MAX_PREFERRED_LENGTH,
                                         &read, &total, nullptr);
    if ((rc == NERR_Success || rc == ERROR_MORE_DATA) && buf) {
        for (DWORD i = 0; i < read; ++i) {
            if (buf[i].grui0_name) members.push_back(buf[i].grui0_name);
        }
        NetApiBufferFree(buf);
    }
    NetApiBufferFree(dci);

    if (!members.empty()) {
        StringMap d;
        d[L"Member count"] = std::to_wstring(members.size());
        String joined = Core::Utils::Join(members, L", ");
        if (joined.size() > 500) joined = joined.substr(0, 500) + L"...";
        d[L"Members"] = joined;
        // A large Domain Admins group is a standing risk (big privileged blast radius).
        SecurityLevel risk = (members.size() > 10) ? SecurityLevel::Medium : SecurityLevel::Low;
        Record(L"Domain Admins membership",
               L"Members of the Domain Admins group (full control of the domain).",
               risk, d,
               L"Keep Domain Admins minimal; use tiered admin / PAW and just-in-time "
               L"elevation instead of standing membership.",
               L"MITRE ATT&CK T1078.002 (Domain Accounts)");
    }
}

void DomainReconAnalyzer::CheckTrusts() {
    PDS_DOMAIN_TRUSTSW trusts = nullptr;
    ULONG count = 0;
    DWORD rc = DsEnumerateDomainTrustsW(nullptr,
                   DS_DOMAIN_IN_FOREST | DS_DOMAIN_DIRECT_OUTBOUND | DS_DOMAIN_DIRECT_INBOUND,
                   &trusts, &count);
    if (rc != ERROR_SUCCESS || !trusts) return;

    for (ULONG i = 0; i < count; ++i) {
        if (!trusts[i].DnsDomainName && !trusts[i].NetbiosDomainName) continue;
        StringMap d;
        d[L"Trusted domain"] = trusts[i].DnsDomainName ? trusts[i].DnsDomainName
                                                       : trusts[i].NetbiosDomainName;
        d[L"Direction"] = (trusts[i].Flags & DS_DOMAIN_DIRECT_OUTBOUND) ? L"outbound"
                        : (trusts[i].Flags & DS_DOMAIN_DIRECT_INBOUND) ? L"inbound" : L"in-forest";
        Record(L"Domain trust", L"An Active Directory trust relationship exists.",
               SecurityLevel::Low, d,
               L"Review trust necessity and direction; trusts widen the attack surface "
               L"across domains/forests.",
               L"MITRE ATT&CK T1482 (Domain Trust Discovery)");
    }
    NetApiBufferFree(trusts);
}

bool DomainReconAnalyzer::RunAllChecks() {
    if (!initialized_) return false;

    String domain;
    if (!IsDomainJoined(domain)) {
        SYSRECON_LOG_INFO(L"Host is not domain-joined; domain recon skipped");
        return true;
    }
    SYSRECON_LOG_INFO(L"Running domain reconnaissance for: " + domain);

    CheckDomainController(domain);
    CheckPasswordPolicy();
    CheckDomainAdmins();
    CheckTrusts();
    return true;
}

#else  // non-Windows stub

bool DomainReconAnalyzer::RunAllChecks() {
    SYSRECON_LOG_INFO(L"Domain reconnaissance only available on Windows");
    return true;
}

#endif

} // namespace Modules
} // namespace SysRecon
