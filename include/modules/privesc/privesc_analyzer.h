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
    // Runs every enabled check category. Returns true if the pass completed
    // (findings are retrieved via GetScanResults()).
    bool RunAllChecks();
    void Cleanup();

    // Per-category toggles, driven from config.json (modules.privesc.*).
    void SetCheckServices(bool enable)       { check_services_ = enable; }
    void SetCheckRegistry(bool enable)       { check_registry_ = enable; }
    void SetCheckFilesystem(bool enable)     { check_filesystem_ = enable; }
    void SetCheckCredentials(bool enable)    { check_credentials_ = enable; }
    void SetVerifySignatures(bool enable)    { verify_signatures_ = enable; }
    void SetCheckTokens(bool enable)         { check_tokens_ = enable; }
    void SetCheckScheduledTasks(bool enable) { check_scheduled_tasks_ = enable; }
    void SetCheckPatches(bool enable)        { check_patches_ = enable; }

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
    // Phase 1 (Tier 1 LPE) additions.
    bool CheckTokenPrivileges();       // current token: integrity, elevation, dangerous privileges
    bool CheckScheduledTasks();        // SYSTEM/highest tasks with a writable binary
    bool CheckExtendedAutoruns();      // Winlogon, AppInit_DLLs, IFEO, Startup folder
    bool CheckMissingPatches();        // installed hotfixes vs known-LPE table

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

    // Category toggles (all on by default; overridden by ApplyConfigToModules).
    bool check_services_ = true;
    bool check_registry_ = true;
    bool check_filesystem_ = true;
    bool check_credentials_ = true;
    bool verify_signatures_ = true;
    bool check_tokens_ = true;
    bool check_scheduled_tasks_ = true;
    bool check_patches_ = true;
};

} // namespace Modules
} // namespace SysRecon
