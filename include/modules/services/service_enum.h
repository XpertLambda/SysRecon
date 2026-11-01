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
    void Cleanup();
    
    // Results access
    const std::vector<ServiceInfo>& GetServices() const { return services_; }
    const ScanResults& GetScanResults() const { return scan_results_; }
    
private:
    // Analysis helpers
    void AnalyzeService(const ServiceInfo& service);

    // Utility methods
    String StartTypeToString(DWORD start_type);
    String StateToString(DWORD state);

    // Data storage
    std::vector<ServiceInfo> services_;
    ScanResults scan_results_;

    // State
    bool initialized_;
    SC_HANDLE scm_handle_;
};

} // namespace Modules
} // namespace SysRecon
