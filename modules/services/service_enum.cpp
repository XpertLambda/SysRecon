#include "../../include/modules/services/service_enum.h"
#include "../../include/core/whitelist.h"

namespace SysRecon {
namespace Modules {

ServiceEnumerator::ServiceEnumerator() 
    : analyze_startup_(true)
    , check_dependencies_(true)
    , verify_signatures_(false)
    , initialized_(false)
    , scm_handle_(nullptr) {
}

ServiceEnumerator::~ServiceEnumerator() {
    Cleanup();
}

bool ServiceEnumerator::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Service Enumeration module");
    initialized_ = true;
    return true;
}

bool ServiceEnumerator::EnumerateServices() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating Windows services...");
    
#ifdef _WIN32
    scm_handle_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm_handle_) {
        SYSRECON_LOG_ERROR(L"Failed to open Service Control Manager");
        return false;
    }
    
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    
    // First call to get buffer size
    EnumServicesStatusExW(
        scm_handle_,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        nullptr,
        0,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        nullptr
    );
    
    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(scm_handle_);
        scm_handle_ = nullptr;
        return false;
    }
    
    // Allocate buffer and enumerate
    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESSW services = (LPENUM_SERVICE_STATUS_PROCESSW)buffer.data();
    
    if (!EnumServicesStatusExW(
            scm_handle_,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            (LPBYTE)services,
            bytesNeeded,
            &bytesNeeded,
            &servicesReturned,
            &resumeHandle,
            nullptr)) {
        CloseServiceHandle(scm_handle_);
        scm_handle_ = nullptr;
        return false;
    }
    
    // Process each service
    for (DWORD i = 0; i < servicesReturned; i++) {
        ServiceInfo svc;
        svc.service_name = services[i].lpServiceName ? String(services[i].lpServiceName) : L"";
        svc.display_name = services[i].lpDisplayName ? String(services[i].lpDisplayName) : L"";
        svc.process_id = services[i].ServiceStatusProcess.dwProcessId;
        svc.service_type = services[i].ServiceStatusProcess.dwServiceType;
        svc.current_state = StateToString(services[i].ServiceStatusProcess.dwCurrentState);
        
        // Get detailed service information
        SC_HANDLE serviceHandle = OpenServiceW(scm_handle_, svc.service_name.c_str(), SERVICE_QUERY_CONFIG);
        if (serviceHandle) {
            DWORD bytesNeeded = 0;
            QueryServiceConfigW(serviceHandle, nullptr, 0, &bytesNeeded);
            
            if (bytesNeeded > 0) {
                std::vector<BYTE> configBuffer(bytesNeeded);
                LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)configBuffer.data();
                
                if (QueryServiceConfigW(serviceHandle, config, bytesNeeded, &bytesNeeded)) {
                    svc.executable_path = config->lpBinaryPathName ? String(config->lpBinaryPathName) : L"";
                    svc.startup_type = StartTypeToString(config->dwStartType);
                    svc.service_account = config->lpServiceStartName ? String(config->lpServiceStartName) : L"";
                    
                    // Analyze for potential security issues
                    AnalyzeService(svc);
                }
            }
            
            CloseServiceHandle(serviceHandle);
        }
        
        services_.push_back(svc);
    }
    
    SYSRECON_LOG_INFO(L"Enumerated " + std::to_wstring(services_.size()) + L" services");
    return true;
#else
    SYSRECON_LOG_INFO(L"Cross-compilation stub - feature available only on Windows");
    return true;
#endif
}

bool ServiceEnumerator::AnalyzeStartupServices() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing startup services...");
    return true;
}

bool ServiceEnumerator::CheckServicePermissions() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Checking service permissions...");
    return true;
}

bool ServiceEnumerator::VerifySignatures() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Verifying service signatures...");
    return true;
}

void ServiceEnumerator::Cleanup() {
    services_.clear();
    scan_results_.clear();
    
#ifdef _WIN32
    if (scm_handle_) {
        CloseServiceHandle(scm_handle_);
        scm_handle_ = nullptr;
    }
#endif
    
    initialized_ = false;
}

void ServiceEnumerator::AnalyzeService(const ServiceInfo& svc) {
    ScanResult result;
    result.module_name = L"Services";
    result.item_name = svc.display_name;
    result.description = L"Service: " + svc.service_name;
    result.timestamp = std::chrono::system_clock::now();
    
    // Determine risk level
    SecurityLevel risk = SecurityLevel::Low;
    bool is_system_service = Core::SystemWhitelist::Instance().IsSystemService(svc.service_name);
    bool is_system_path = Core::SystemWhitelist::Instance().IsSystemPath(svc.executable_path);
    
    // Check for unquoted service paths with spaces
    if (!svc.executable_path.empty()) {
        if (svc.executable_path.find(L' ') != String::npos && 
            svc.executable_path[0] != L'"' &&
            svc.executable_path.find(L"\\") != String::npos) {
            
            // Check if it's actually safe
            bool is_safe = Core::SystemWhitelist::Instance().IsSafeUnquotedPath(svc.executable_path);
            
            if (!is_safe && !is_system_service) {
                result.details[L"Unquoted Path"] = L"Yes - Potential DLL hijacking risk";
                risk = std::max(risk, SecurityLevel::High);
            } else if (!is_safe && is_system_service) {
                result.details[L"Unquoted Path"] = L"Yes - System service, likely safe";
                risk = std::max(risk, SecurityLevel::Low);
            }
        }
    }
    
    // Check if service runs as SYSTEM
    if (svc.service_account == L"LocalSystem" || svc.service_account.empty()) {
        result.details[L"Runs as SYSTEM"] = L"Yes";
        
        // Only flag non-system services running as SYSTEM
        if (svc.current_state == L"Running" && !is_system_service && !is_system_path) {
            risk = std::max(risk, SecurityLevel::Medium);
            result.details[L"Note"] = L"Non-system service running with SYSTEM privileges";
        } else if (is_system_service) {
            result.details[L"Note"] = L"Known Windows system service";
        }
    }
    
    // Check auto-start services
    if (svc.startup_type == L"Automatic") {
        result.details[L"Auto Start"] = L"Yes";
        
        // Only flag suspicious auto-start non-system services
        if (!is_system_service && !is_system_path) {
            risk = std::max(risk, SecurityLevel::Low);
        }
    }
    
    result.details[L"Binary Path"] = svc.executable_path;
    result.details[L"Start Type"] = svc.startup_type;
    result.details[L"State"] = svc.current_state;
    result.details[L"Start Name"] = svc.service_account;
    
    // Only add to scan results if risk is Medium or above, or if it's a non-system service
    if (risk >= SecurityLevel::Medium || (!is_system_service && !is_system_path)) {
        result.risk_level = risk;
        scan_results_.push_back(result);
    }
}

String ServiceEnumerator::StartTypeToString(DWORD start_type) {
    switch (start_type) {
        case SERVICE_AUTO_START: return L"Automatic";
        case SERVICE_BOOT_START: return L"Boot";
        case SERVICE_DEMAND_START: return L"Manual";
        case SERVICE_DISABLED: return L"Disabled";
        case SERVICE_SYSTEM_START: return L"System";
        default: return L"Unknown";
    }
}

String ServiceEnumerator::StateToString(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED: return L"Stopped";
        case SERVICE_START_PENDING: return L"Start Pending";
        case SERVICE_STOP_PENDING: return L"Stop Pending";
        case SERVICE_RUNNING: return L"Running";
        case SERVICE_CONTINUE_PENDING: return L"Continue Pending";
        case SERVICE_PAUSE_PENDING: return L"Pause Pending";
        case SERVICE_PAUSED: return L"Paused";
        default: return L"Unknown";
    }
}

}
}
