#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

struct ServiceInfo {
    String service_name;
    String display_name;
    String description;
    String executable_path;
    String service_account;
    String startup_type;
    String current_state;
    DWORD service_type;
    DWORD controls_accepted;
    DWORD exit_code;
    DWORD checkpoint;
    DWORD wait_hint;
    DWORD process_id;
    StringVector dependencies;
    StringVector dependents;
    bool is_signed;
    String file_version;
    String company;
    SecurityLevel risk_level;
};

enum class ServiceStartType {
    Boot = 0,
    System = 1,
    Automatic = 2,
    Manual = 3,
    Disabled = 4,
    AutomaticDelayed = 5
};

enum class ServiceState {
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7
};

class ServiceEnumerator {
public:
    ServiceEnumerator();
    ~ServiceEnumerator();
    
    // Main enumeration methods
    bool Initialize();
    bool EnumerateServices();
    bool AnalyzeStartupServices();
    bool CheckServicePermissions();
    bool VerifySignatures();
    void Cleanup();
    
    // Results access
    const std::vector<ServiceInfo>& GetServices() const { return services_; }
    const ScanResults& GetScanResults() const { return scan_results_; }
    
    // Configuration
    void SetAnalyzeStartup(bool enable) { analyze_startup_ = enable; }
    void SetCheckDependencies(bool enable) { check_dependencies_ = enable; }
    void SetVerifySignatures(bool enable) { verify_signatures_ = enable; }
    
    // Analysis methods
    SecurityLevel AssessServiceRisk(const ServiceInfo& service);
    StringVector FindSuspiciousServices();
    StringVector FindUnquotedServicePaths();
    StringVector FindServicesWithWeakPermissions();
    StringVector FindUnsignedServices();
    StringVector FindServicesRunningAsSystem();
    
    // Service control methods
    bool StartService(const String& service_name);
    bool StopService(const String& service_name);
    bool RestartService(const String& service_name);
    ServiceState GetServiceState(const String& service_name);
    
private:
    // Internal enumeration methods
    bool EnumerateAllServices();
    bool GetServiceDetails(const String& service_name, ServiceInfo& service);
    bool GetServiceDependencies(const String& service_name, StringVector& dependencies);
    bool GetServiceDependents(const String& service_name, StringVector& dependents);
    bool GetServiceExecutableInfo(const String& executable_path, ServiceInfo& service);
    
    // Analysis helpers
    void AnalyzeService(const ServiceInfo& service);
    void CheckServicePath(const ServiceInfo& service);
    void CheckServiceAccount(const ServiceInfo& service);
    void CheckServicePermissions(const ServiceInfo& service);
    void CheckServiceSignature(const ServiceInfo& service);
    
    // Utility methods
    String ServiceTypeToString(DWORD service_type);
    String StartTypeToString(DWORD start_type);
    String StateToString(DWORD state);
    bool IsServiceSigned(const String& executable_path);
    String GetFileCompany(const String& file_path);
    String GetFileVersion(const String& file_path);
    
    // Configuration
    bool analyze_startup_;
    bool check_dependencies_;
    bool verify_signatures_;
    
    // Data storage
    std::vector<ServiceInfo> services_;
    ScanResults scan_results_;
    
    // State
    bool initialized_;
    SC_HANDLE scm_handle_;
    StringVector error_messages_;
};

} // namespace Modules
} // namespace SysRecon
