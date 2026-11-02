#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

// Opt-in, read-only domain situational-awareness pass for a domain-joined host.
// It performs only standard directory lookups a normal domain user can make
// (locate a DC, read the account/lockout policy, list Domain Admins, enumerate
// trusts). It never authenticates elsewhere, modifies the directory, or
// requests credentials. On a standalone/workgroup host it does nothing.
class DomainReconAnalyzer {
public:
    DomainReconAnalyzer();
    ~DomainReconAnalyzer();

    bool Initialize();
    bool RunAllChecks();
    void Cleanup();

    const ScanResults& GetScanResults() const { return scan_results_; }

private:
    void Record(const String& item, const String& description, SecurityLevel risk,
                const StringMap& details, const String& remediation = L"",
                const String& reference = L"");

#ifdef _WIN32
    bool IsDomainJoined(String& domain_out);
    void CheckDomainController(const String& domain);
    void CheckPasswordPolicy();
    void CheckDomainAdmins();
    void CheckTrusts();
#endif

    ScanResults scan_results_;
    bool initialized_ = false;
};

} // namespace Modules
} // namespace SysRecon
