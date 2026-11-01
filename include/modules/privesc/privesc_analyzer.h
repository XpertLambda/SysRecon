#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

// A single privilege-escalation / misconfiguration finding. In addition to the
// risk rating it always carries concrete remediation and a reference (MITRE
// ATT&CK technique or vendor doc) so the output is directly actionable during
// an authorised engagement and for the defender fixing the box afterwards.
struct PrivEscFinding {
    String title;
    String category;        // e.g. "Service", "Registry", "Filesystem"
    String description;
    String evidence;        // The concrete artefact (path, key, principal).
    String remediation;     // How to close the gap.
    String reference;       // MITRE ATT&CK ID / CVE / docs link.
    SecurityLevel risk_level = SecurityLevel::Medium;
};

// PrivEscAnalyzer performs read-only, host-local checks for common Windows
// local privilege-escalation vectors. It never modifies the system; it reports
// what an attacker with the current token could abuse and how to remediate it.
class PrivEscAnalyzer {
public:
    PrivEscAnalyzer();
    ~PrivEscAnalyzer();

    bool Initialize();
    // Runs every enabled check. Returns true if the pass completed (findings
    // are retrieved via GetScanResults()).
    bool RunAllChecks();
    void Cleanup();

    const std::vector<PrivEscFinding>& GetFindings() const { return findings_; }
    const ScanResults& GetScanResults() const { return scan_results_; }

    // Individual checks (public so selective/quick runs can call a subset).
    bool CheckUnquotedServicePaths();
    bool CheckWeakServicePermissions();
    bool CheckWritableServiceBinaries();
    bool CheckAlwaysInstallElevated();
    bool CheckWritablePathDirectories();
    bool CheckAutorunWritableTargets();
    bool CheckStoredCredentials();
    bool CheckUacPosture();
    bool CheckUnattendedInstallFiles();

private:
    // Records a finding both in the typed list and as a generic ScanResult
    // (so the existing report pipeline renders it with remediation/reference).
    void Record(const PrivEscFinding& finding);

#ifdef _WIN32
    // True when the caller can open the service's security descriptor and a
    // non-admin principal holds change-config / all-access over it.
    bool ServiceDaclIsWeak(const String& service_name, StringVector& principals);
#endif

    std::vector<PrivEscFinding> findings_;
    ScanResults scan_results_;
    bool initialized_ = false;
};

} // namespace Modules
} // namespace SysRecon
