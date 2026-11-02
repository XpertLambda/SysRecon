#include "../../include/modules/network/network_enum.h"
#include <iomanip>
#include <lm.h>
#include "../../include/core/text_utils.h"

#ifdef _WIN32
#include <netfw.h>
#endif

namespace SysRecon {
namespace Modules {

NetworkEnumerator::NetworkEnumerator() 
    : scan_listening_ports_(true)
    , analyze_connections_(true)
    , resolve_hostnames_(false)
    , initialized_(false) {
}

NetworkEnumerator::~NetworkEnumerator() {
    Cleanup();
}

bool NetworkEnumerator::Initialize() {
    SYSRECON_LOG_INFO(L"Initializing Network Enumeration module");
    initialized_ = true;
    return true;
}

bool NetworkEnumerator::LoadTables() {
#ifdef _WIN32
    connections_.clear();
    process_names_ = Core::Utils::GetProcessNameMap();

    DWORD dwSize = 0;
    // Size query. Anything other than ERROR_INSUFFICIENT_BUFFER means the
    // table cannot be read.
    DWORD dwRetVal = GetTcpTable2(nullptr, &dwSize, TRUE);
    if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
        SYSRECON_LOG_ERROR(L"GetTcpTable2 size query failed: " +
                           Core::Utils::GetLastErrorString(dwRetVal));
        return false;
    }

    // The table can grow between the size query and the read; retry a few
    // times with the size the failed call reports.
    std::vector<BYTE> tcp_buffer;
    for (int attempt = 0; attempt < 4; ++attempt) {
        tcp_buffer.resize(dwSize);
        dwRetVal = GetTcpTable2(reinterpret_cast<PMIB_TCPTABLE2>(tcp_buffer.data()), &dwSize, TRUE);
        if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
            break;
        }
    }
    if (dwRetVal != NO_ERROR) {
        SYSRECON_LOG_ERROR(L"GetTcpTable2 failed: " + Core::Utils::GetLastErrorString(dwRetVal));
        return false;
    }

    auto name_of = [this](DWORD pid) {
        auto it = process_names_.find(pid);
        return it == process_names_.end() ? String(L"(unknown)") : it->second;
    };

    const auto* pTcpTable = reinterpret_cast<const MIB_TCPTABLE2*>(tcp_buffer.data());
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        const MIB_TCPROW2& row = pTcpTable->table[i];

        NetworkConnection conn;
        conn.protocol = L"TCP";
        conn.local_address = Core::Utils::IpAddressToString(ntohl(row.dwLocalAddr));
        conn.local_port = ntohs((u_short)row.dwLocalPort);
        conn.remote_address = Core::Utils::IpAddressToString(ntohl(row.dwRemoteAddr));
        conn.remote_port = ntohs((u_short)row.dwRemotePort);
        conn.state = ConnectionStateToString(row.dwState);
        conn.process_id = row.dwOwningPid;
        conn.process_name = name_of(row.dwOwningPid);
        conn.risk_level = SecurityLevel::Low;
        connections_.push_back(conn);
    }

    dwSize = 0;
    dwRetVal = GetExtendedUdpTable(nullptr, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> udp_buffer;
        for (int attempt = 0; attempt < 4; ++attempt) {
            udp_buffer.resize(dwSize);
            dwRetVal = GetExtendedUdpTable(udp_buffer.data(), &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
                break;
            }
        }
        if (dwRetVal == NO_ERROR) {
            const auto* pUdpTable = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(udp_buffer.data());
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                const MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];

                NetworkConnection conn;
                conn.protocol = L"UDP";
                conn.local_address = Core::Utils::IpAddressToString(ntohl(row.dwLocalAddr));
                conn.local_port = ntohs((u_short)row.dwLocalPort);
                conn.remote_port = 0;
                conn.state = L"BOUND";  // UDP has no connection state.
                conn.process_id = row.dwOwningPid;
                conn.process_name = name_of(row.dwOwningPid);
                conn.risk_level = SecurityLevel::Low;
                connections_.push_back(conn);
            }
        } else {
            SYSRECON_LOG_WARNING(L"GetExtendedUdpTable failed: " + Core::Utils::GetLastErrorString(dwRetVal));
        }
    }

    tables_loaded_ = true;
    return true;
#else
    tables_loaded_ = true;
    return true;
#endif
}

bool NetworkEnumerator::EnumerateConnections() {
    if (!initialized_) return false;

    SYSRECON_LOG_INFO(L"Enumerating network connections...");
    if (!LoadTables()) {
        return false;
    }
    if (analyze_connections_) {
        ReportConnections();
    } else {
        SYSRECON_LOG_DEBUG(L"Connection analysis disabled by config (network.analyze_connections)");
    }
    SYSRECON_LOG_INFO(L"Enumerated " + std::to_wstring(connections_.size()) + L" connections");
    return true;
}

namespace {

#ifdef _WIN32
// Service names hosted by each running process, so a listening port can be
// attributed to "svchost.exe (RpcSs)" rather than just "svchost.exe".
std::map<DWORD, StringVector> ServicesByPid() {
    std::map<DWORD, StringVector> result;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == nullptr) {
        return result;
    }
    DWORD needed = 0, count = 0, resume = 0;
    std::vector<BYTE> buf;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, nullptr, 0,
                          &needed, &count, &resume, nullptr);
    if (GetLastError() == ERROR_MORE_DATA && needed > 0) {
        buf.resize(needed);
        resume = 0;
        if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buf.data(),
                                  static_cast<DWORD>(buf.size()), &needed, &count, &resume, nullptr)) {
            auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
            for (DWORD i = 0; i < count; ++i) {
                const DWORD pid = services[i].ServiceStatusProcess.dwProcessId;
                if (pid != 0 && services[i].lpServiceName) {
                    result[pid].push_back(services[i].lpServiceName);
                }
            }
        }
    }
    CloseServiceHandle(scm);
    return result;
}
#endif

}  // namespace

bool NetworkEnumerator::EnumerateListeningPorts() {
    if (!initialized_) return false;

    SYSRECON_LOG_INFO(L"Enumerating listening ports...");

    // Load on demand: the quick scan calls this without EnumerateConnections,
    // and previously always found zero listening ports as a result.
    if (!tables_loaded_ && !LoadTables()) {
        return false;
    }

    listening_ports_.clear();
#ifdef _WIN32
    const auto services = ServicesByPid();
#endif
    for (const auto& conn : connections_) {
        if (conn.state == L"LISTENING" || conn.protocol == L"UDP") {
            ListeningPort port;
            port.port = conn.local_port;
            port.protocol = conn.protocol;
            port.process_id = conn.process_id;
            port.process_name = conn.process_name;
            port.address = conn.local_address;
            port.is_system_port = (conn.local_port < 1024);
            port.is_filtered = false;
#ifdef _WIN32
            if (auto it = services.find(conn.process_id); it != services.end()) {
                StringVector names = it->second;
                const size_t total = names.size();
                if (names.size() > 3) names.resize(3);
                port.service_name = Core::Utils::Join(names, L", ") +
                                    (total > 3 ? L", +" + std::to_wstring(total - 3) : String());
            }
#endif
            port.risk_level = AssessPortRisk(port);
            listening_ports_.push_back(port);
        }
    }

    if (scan_listening_ports_) {
        ReportListeningPorts();
    } else {
        SYSRECON_LOG_DEBUG(L"Listening-port findings disabled by config (network.scan_listening_ports)");
    }

    SYSRECON_LOG_INFO(L"Found " + std::to_wstring(listening_ports_.size()) + L" listening ports");
    return true;
}

void NetworkEnumerator::ReportListeningPorts() {
    StringVector exposed;
    for (const auto& port : listening_ports_) {
        // Loopback-only listeners are not reachable from the network.
        if (Core::Text::IsLoopbackIpv4(port.address)) {
            continue;
        }
        if (port.protocol == L"TCP") {
            exposed.push_back(std::to_wstring(port.port) + L"/" + port.process_name +
                              (port.service_name.empty() ? String() : L" (" + port.service_name + L")"));
        }
        if (port.risk_level == SecurityLevel::Low) {
            continue;
        }

        ScanResult result;
        result.module_name = L"Network";
        result.item_name = port.protocol + L" " + std::to_wstring(port.port) + L" (" + port.process_name + L")";
        result.description = L"Network-reachable service on a commonly attacked port";
        result.risk_level = port.risk_level;
        result.details[L"Address"] = port.address;
        result.details[L"Port"] = std::to_wstring(port.port);
        result.details[L"Protocol"] = port.protocol;
        result.details[L"Process"] = port.process_name;
        result.details[L"PID"] = std::to_wstring(port.process_id);
        if (!port.service_name.empty()) {
            result.details[L"Service"] = port.service_name;
        }
        result.details[L"Note"] = L"Reachability also depends on the firewall; confirm the service is needed";
        result.details[L"Technique"] = L"T1133 External Remote Services / T1210 Exploitation of Remote Services";
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
    }

    // One inventory entry rather than a finding per port.
    std::sort(exposed.begin(), exposed.end());
    exposed.erase(std::unique(exposed.begin(), exposed.end()), exposed.end());
    ScanResult inventory;
    inventory.module_name = L"Network";
    inventory.item_name = L"Listening TCP ports";
    inventory.description = std::to_wstring(exposed.size()) + L" TCP ports listening on non-loopback addresses";
    inventory.risk_level = SecurityLevel::Low;
    inventory.details[L"Ports"] = exposed.empty() ? String(L"(none)") : Core::Utils::Join(exposed, L", ");
    inventory.timestamp = std::chrono::system_clock::now();
    scan_results_.push_back(inventory);
}

void NetworkEnumerator::ReportConnections() {
    for (auto& conn : connections_) {
        if (conn.protocol != L"TCP" || conn.state != L"ESTABLISHED") {
            continue;
        }
        conn.risk_level = AssessConnectionRisk(conn);
        if (conn.risk_level == SecurityLevel::Low) {
            continue;
        }
        ScanResult result;
        result.module_name = L"Network";
        result.item_name = conn.process_name + L" -> " + conn.remote_address + L":" + std::to_wstring(conn.remote_port);
        result.description = L"Established connection to a port commonly used by backdoors and C2 frameworks";
        result.risk_level = conn.risk_level;
        result.details[L"Process"] = conn.process_name;
        result.details[L"PID"] = std::to_wstring(conn.process_id);
        result.details[L"Local"] = conn.local_address + L":" + std::to_wstring(conn.local_port);
        result.details[L"Remote"] = conn.remote_address + L":" + std::to_wstring(conn.remote_port);
        result.details[L"Note"] = L"Port numbers alone prove nothing; verify the process and destination";
        result.details[L"Technique"] = L"T1571 Non-Standard Port";
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
    }
}

bool NetworkEnumerator::EnumerateInterfaces() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating network interfaces...");
    
#ifdef _WIN32
    interfaces_.clear();
    // Get adapter information
    ULONG buffer_size = 15000; // Initial buffer size
    PIP_ADAPTER_INFO adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);
    
    if (adapter_info == NULL) {
        SYSRECON_LOG_ERROR(L"Failed to allocate memory for adapter info");
        return false;
    }
    
    DWORD adapter_status = GetAdaptersInfo(adapter_info, &buffer_size);
    if (adapter_status == ERROR_BUFFER_OVERFLOW) {
        free(adapter_info);
        adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);
        if (adapter_info == NULL) {
            return false;
        }
        adapter_status = GetAdaptersInfo(adapter_info, &buffer_size);
    }
    
    if (adapter_status != ERROR_SUCCESS) {
        SYSRECON_LOG_ERROR(L"GetAdaptersInfo failed: " + std::to_wstring(adapter_status));
        free(adapter_info);
        return false;
    }
    
    // Process each adapter
    PIP_ADAPTER_INFO current_adapter = adapter_info;
    while (current_adapter) {
        NetworkInterface iface;
        
        // Adapter name (convert from ANSI to wide)
        int len = MultiByteToWideChar(CP_ACP, 0, current_adapter->AdapterName, -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> buf(len);
            MultiByteToWideChar(CP_ACP, 0, current_adapter->AdapterName, -1, buf.data(), len);
            iface.name = buf.data();
        }
        
        // Description
        len = MultiByteToWideChar(CP_ACP, 0, current_adapter->Description, -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> buf(len);
            MultiByteToWideChar(CP_ACP, 0, current_adapter->Description, -1, buf.data(), len);
            iface.description = buf.data();
        }
        
        // Physical address (MAC)
        if (current_adapter->AddressLength > 0) {
            std::wstringstream mac_stream;
            for (UINT i = 0; i < current_adapter->AddressLength; i++) {
                if (i > 0) mac_stream << L":";
                mac_stream << std::hex << std::setw(2) << std::setfill(L'0') 
                          << (int)current_adapter->Address[i];
            }
            iface.physical_address = mac_stream.str();
        }
        
        // IP addresses
        IP_ADDR_STRING* ip_addr = &current_adapter->IpAddressList;
        while (ip_addr) {
            if (ip_addr->IpAddress.String[0] != '0') {
                len = MultiByteToWideChar(CP_ACP, 0, ip_addr->IpAddress.String, -1, NULL, 0);
                if (len > 0) {
                    std::vector<wchar_t> buf(len);
                    MultiByteToWideChar(CP_ACP, 0, ip_addr->IpAddress.String, -1, buf.data(), len);
                    iface.ip_addresses.push_back(buf.data());
                }
            }
            ip_addr = ip_addr->Next;
        }
        
        // Gateway
        IP_ADDR_STRING* gateway = &current_adapter->GatewayList;
        while (gateway) {
            if (gateway->IpAddress.String[0] != '0') {
                len = MultiByteToWideChar(CP_ACP, 0, gateway->IpAddress.String, -1, NULL, 0);
                if (len > 0) {
                    std::vector<wchar_t> buf(len);
                    MultiByteToWideChar(CP_ACP, 0, gateway->IpAddress.String, -1, buf.data(), len);
                    iface.gateways.push_back(buf.data());
                }
            }
            gateway = gateway->Next;
        }
        
        // DHCP server
        if (current_adapter->DhcpEnabled) {
            len = MultiByteToWideChar(CP_ACP, 0, current_adapter->DhcpServer.IpAddress.String, -1, NULL, 0);
            if (len > 0) {
                std::vector<wchar_t> buf(len);
                MultiByteToWideChar(CP_ACP, 0, current_adapter->DhcpServer.IpAddress.String, -1, buf.data(), len);
                iface.dhcp_server = buf.data();
            }
        }
        
        iface.dhcp_enabled = current_adapter->DhcpEnabled != 0;
        iface.is_up = !iface.ip_addresses.empty();
        iface.interface_type = L"Ethernet"; // Simplified
        
        interfaces_.push_back(iface);
        
        // Create scan result
        ScanResult result;
        result.module_name = L"Network";
        result.item_name = iface.description;
        result.description = L"Network interface";
        result.risk_level = SecurityLevel::Low;
        result.details[L"mac_address"] = iface.physical_address;
        result.details[L"dhcp_enabled"] = iface.dhcp_enabled ? L"Yes" : L"No";
        if (!iface.ip_addresses.empty()) {
            result.details[L"ip_address"] = iface.ip_addresses[0];
        }
        scan_results_.push_back(result);
        
        current_adapter = current_adapter->Next;
    }
    
    free(adapter_info);
    
    SYSRECON_LOG_INFO(L"Found " + std::to_wstring(interfaces_.size()) + L" network interfaces");
    return true;
#else
    SYSRECON_LOG_INFO(L"Network interface enumeration only available on Windows");
    return false;
#endif
}

bool NetworkEnumerator::EnumerateShares() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating network shares...");
    
#ifdef _WIN32
    shares_.clear();
    NET_API_STATUS status;
    PSHARE_INFO_2 share_info = NULL;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD resume_handle = 0;
    
    // Enumerate shares on local computer
    status = NetShareEnum(
        NULL,               // Local computer
        2,                  // Level 2 (detailed info)
        (LPBYTE*)&share_info,
        MAX_PREFERRED_LENGTH,
        &entries_read,
        &total_entries,
        &resume_handle
    );
    
    if (status != NERR_Success && status != ERROR_MORE_DATA) {
        SYSRECON_LOG_ERROR(L"NetShareEnum failed: " + std::to_wstring(status));
        return false;
    }
    
    // Process each share
    for (DWORD i = 0; i < entries_read; i++) {
        NetworkShare share;
        share.share_name = share_info[i].shi2_netname;
        
        if (share_info[i].shi2_path) {
            share.path = share_info[i].shi2_path;
        }
        
        if (share_info[i].shi2_remark) {
            share.description = share_info[i].shi2_remark;
        }
        
        share.share_type = share_info[i].shi2_type;
        share.permissions = share_info[i].shi2_permissions;
        share.current_uses = share_info[i].shi2_current_uses;
        share.max_uses = share_info[i].shi2_max_uses;
        share.risk_level = AssessShareRisk(share);
        
        shares_.push_back(share);
        
        // Create scan result
        ScanResult result;
        result.module_name = L"Network Shares";
        result.item_name = share.share_name;
        result.description = share.description;
        result.risk_level = share.risk_level;
        result.details[L"path"] = share.path;
        result.details[L"current_uses"] = std::to_wstring(share.current_uses);

        // shi2_permissions is NOT reported here: it only ever applied to
        // share-level security (Win9x) and is always 0 on any modern Windows.
        // Treating 0 as "full access" flagged every share on every host as
        // High -- and contradicted AssessShareRisk, which had already cleared
        // admin shares. Effective access is governed by the share ACL, which
        // this build does not evaluate.
        result.details[L"note"] = L"Share ACLs are not evaluated; review access rights manually";

        if (!share.share_name.empty() && share.share_name.back() == L'$') {
            result.details[L"type"] = L"Administrative share";
        }

        scan_results_.push_back(result);
    }
    
    // Free the buffer
    if (share_info != NULL) {
        NetApiBufferFree(share_info);
    }
    
    SYSRECON_LOG_INFO(L"Found " + std::to_wstring(shares_.size()) + L" network shares");
    return true;
#else
    SYSRECON_LOG_INFO(L"Network share enumeration only available on Windows");
    return false;
#endif
}

bool NetworkEnumerator::AnalyzeFirewall() {
    if (!initialized_) return false;

    SYSRECON_LOG_INFO(L"Analyzing firewall configuration...");

#ifdef _WIN32
    // 1. Is the firewall service running at all?
    bool service_running = false;
    bool service_known = false;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm != NULL) {
        SC_HANDLE service = OpenServiceW(scm, L"MpsSvc", SERVICE_QUERY_STATUS);
        if (service != NULL) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(service, &status)) {
                service_known = true;
                service_running = (status.dwCurrentState == SERVICE_RUNNING);
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }
    if (!service_known) {
        SYSRECON_LOG_ERROR(L"Could not query the Windows Firewall service (MpsSvc)");
        return false;
    }

    if (!service_running) {
        ScanResult result;
        result.module_name = L"Firewall";
        result.item_name = L"Windows Firewall service";
        result.description = L"Windows Firewall service (MpsSvc) is not running";
        result.risk_level = SecurityLevel::High;
        result.details[L"Status"] = L"Stopped";
        result.details[L"Technique"] = L"T1562.004 Impair Defenses: Disable or Modify System Firewall";
        result.details[L"Remediation"] = L"Invoke-SysReconHardening.ps1 -Include Firewall";
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
    }

    // 2. Per-profile state. A running service with a disabled profile is the
    // common real-world case, and the old service-only check reported it as
    // "Windows Firewall is running". Group Policy values take precedence.
    struct Profile { const wchar_t* label; const wchar_t* local_key; const wchar_t* policy_key; };
    const Profile profiles[] = {
        { L"Domain",
          L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
          L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile" },
        { L"Private",
          L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
          L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile" },
        { L"Public",
          L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
          L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile" },
    };

    StringVector enabled_profiles;
    for (const auto& p : profiles) {
        auto policy = Core::Utils::TryReadRegistryDword(HKEY_LOCAL_MACHINE, p.policy_key, L"EnableFirewall");
        auto local = Core::Utils::TryReadRegistryDword(HKEY_LOCAL_MACHINE, p.local_key, L"EnableFirewall");
        const auto effective = policy ? policy : local;
        if (!effective) {
            continue;  // Unknown; do not guess.
        }
        if (*effective != 0) {
            enabled_profiles.push_back(p.label);
            continue;
        }
        ScanResult result;
        result.module_name = L"Firewall";
        result.item_name = String(p.label) + L" firewall profile";
        result.description = String(L"Windows Firewall is disabled for the ") + p.label + L" profile";
        result.risk_level = (std::wstring(p.label) == L"Public") ? SecurityLevel::High : SecurityLevel::Medium;
        result.details[L"Source"] = policy ? L"Group Policy" : L"Local setting";
        result.details[L"EnableFirewall"] = L"0";
        result.details[L"Technique"] = L"T1562.004 Impair Defenses: Disable or Modify System Firewall";
        result.details[L"Remediation"] = L"Invoke-SysReconHardening.ps1 -Include Firewall";
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
    }

    if (service_running && enabled_profiles.size() == 3) {
        ScanResult result;
        result.module_name = L"Firewall";
        result.item_name = L"Windows Firewall";
        result.description = L"Windows Firewall is running with all profiles enabled";
        result.risk_level = SecurityLevel::Low;
        result.details[L"Profiles"] = Core::Utils::Join(enabled_profiles, L", ");
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
    }

    SYSRECON_LOG_INFO(L"Firewall analysis complete");
    return true;
#else
    SYSRECON_LOG_INFO(L"Firewall analysis only available on Windows");
    return false;
#endif
}

bool NetworkEnumerator::AnalyzeFirewallRules() {
    if (!initialized_) return false;

    SYSRECON_LOG_INFO(L"Analyzing firewall rules...");

#ifdef _WIN32
    // GUIDs spelled out so the build does not depend on which import library
    // (uuid, firewallapi) a toolchain defines them in.
    static const CLSID kClsidNetFwPolicy2 =
        {0xE2B3C97F, 0x6AE1, 0x41AC, {0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}};
    static const IID kIidINetFwPolicy2 =
        {0x98325047, 0xC671, 0x4174, {0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}};
    static const IID kIidINetFwRule =
        {0xAF230D27, 0xBABA, 0x4E42, {0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2}};
    static const IID kIidINetFwRule3 =
        {0xB21563FF, 0xD696, 0x4222, {0xAB, 0x46, 0x4E, 0x89, 0xB7, 0x3A, 0xB3, 0x4A}};
    static const IID kIidIEnumVARIANT =
        {0x00020404, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

    const HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool need_uninit = (init == S_OK || init == S_FALSE);
    if (init != S_OK && init != S_FALSE && init != RPC_E_CHANGED_MODE) {
        SYSRECON_LOG_ERROR(L"COM initialization failed; firewall rules not analyzed");
        return false;
    }

    bool ok = false;
    INetFwPolicy2* policy = nullptr;
    INetFwRules* rules = nullptr;
    IUnknown* enum_unknown = nullptr;
    IEnumVARIANT* rule_enum = nullptr;

    struct Flagged {
        int severity; String name; String ports; String remote; String program; String service; long profiles;
        String package; String owner; String grouping;
    };
    std::map<String, Flagged> flagged;   // keyed by rule name: built-in rules are often duplicated
    size_t total_rules = 0;

    auto bstr = [](BSTR b) {
        String s = b ? String(b, SysStringLen(b)) : String();
        if (b) SysFreeString(b);
        return s;
    };

    if (SUCCEEDED(CoCreateInstance(kClsidNetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER, kIidINetFwPolicy2,
                                   reinterpret_cast<void**>(&policy))) && policy &&
        SUCCEEDED(policy->get_Rules(&rules)) && rules &&
        SUCCEEDED(rules->get__NewEnum(&enum_unknown)) && enum_unknown &&
        SUCCEEDED(enum_unknown->QueryInterface(kIidIEnumVARIANT, reinterpret_cast<void**>(&rule_enum))) &&
        rule_enum) {
        ok = true;
        VARIANT var;
        VariantInit(&var);
        ULONG fetched = 0;
        while (rule_enum->Next(1, &var, &fetched) == S_OK && fetched == 1) {
            INetFwRule* rule = nullptr;
            if (var.vt == VT_DISPATCH && var.pdispVal &&
                SUCCEEDED(var.pdispVal->QueryInterface(kIidINetFwRule, reinterpret_cast<void**>(&rule))) && rule) {
                ++total_rules;
                Core::Text::FirewallRuleView view;
                VARIANT_BOOL enabled = VARIANT_FALSE;
                NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
                NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
                long profiles = 0, protocol = 256;
                BSTR b = nullptr;
                rule->get_Enabled(&enabled);
                rule->get_Direction(&direction);
                rule->get_Action(&action);
                rule->get_Profiles(&profiles);
                rule->get_Protocol(&protocol);
                view.enabled = (enabled == VARIANT_TRUE);
                view.inbound = (direction == NET_FW_RULE_DIR_IN);
                view.allow = (action == NET_FW_ACTION_ALLOW);
                view.public_profile = (profiles & NET_FW_PROFILE2_PUBLIC) != 0;
                view.protocol = static_cast<int>(protocol);
                // Cheap fields first: most rules are disabled or outbound.
                if (view.enabled && view.inbound && view.allow) {
                    if (SUCCEEDED(rule->get_RemoteAddresses(&b))) view.remote_addresses = bstr(b);
                    b = nullptr;
                    if (SUCCEEDED(rule->get_LocalPorts(&b))) view.local_ports = bstr(b);
                    b = nullptr;
                    if (SUCCEEDED(rule->get_ApplicationName(&b))) view.application = bstr(b);
                    b = nullptr;
                    if (SUCCEEDED(rule->get_ServiceName(&b))) view.service = bstr(b);
                    b = nullptr;
                    // Store-app rules are scoped by package SID, not by path.
                    INetFwRule3* rule3 = nullptr;
                    String owner;
                    if (SUCCEEDED(rule->QueryInterface(kIidINetFwRule3, reinterpret_cast<void**>(&rule3))) &&
                        rule3) {
                        if (SUCCEEDED(rule3->get_LocalAppPackageId(&b))) view.app_package = bstr(b);
                        b = nullptr;
                        if (SUCCEEDED(rule3->get_LocalUserOwner(&b))) owner = bstr(b);
                        b = nullptr;
                        rule3->Release();
                    }
                    const int severity = Core::Text::FirewallRuleSeverity(view);
                    if (severity > 0) {
                        String name, grouping;
                        if (SUCCEEDED(rule->get_Name(&b))) name = bstr(b);
                        b = nullptr;
                        if (SUCCEEDED(rule->get_Grouping(&b))) grouping = bstr(b);
                        b = nullptr;
                        if (name.empty()) name = L"(unnamed rule)";
                        auto& f = flagged[name];
                        if (severity > f.severity) {
                            f = {severity, name, view.local_ports, view.remote_addresses,
                                 view.application, view.service, profiles,
                                 view.app_package, owner, grouping};
                        }
                    }
                }
                rule->Release();
            }
            VariantClear(&var);
        }
    }

    if (rule_enum) rule_enum->Release();
    if (enum_unknown) enum_unknown->Release();
    if (rules) rules->Release();
    if (policy) policy->Release();
    if (need_uninit) CoUninitialize();

    if (!ok) {
        SYSRECON_LOG_ERROR(L"Could not enumerate Windows Firewall rules (INetFwPolicy2)");
        return false;
    }

    for (const auto& [name, f] : flagged) {
        auto profile_names = [](long p) {
            if ((p & 0x7) == 0x7) return String(L"All");
            StringVector v;
            if (p & NET_FW_PROFILE2_DOMAIN) v.push_back(L"Domain");
            if (p & NET_FW_PROFILE2_PRIVATE) v.push_back(L"Private");
            if (p & NET_FW_PROFILE2_PUBLIC) v.push_back(L"Public");
            return Core::Utils::Join(v, L", ");
        };
        ScanResult result;
        result.module_name = L"Firewall";
        result.details[L"Rule"] = name;
        result.details[L"Local Ports"] = f.ports.empty() ? String(L"*") : f.ports;
        result.details[L"Remote Addresses"] = f.remote.empty() ? String(L"*") : f.remote;
        result.details[L"Program"] = f.program.empty() ? String(L"Any") : f.program;
        result.details[L"Service"] = (f.service.empty() || f.service == L"*") ? String(L"Any") : f.service;
        result.details[L"Profiles"] = profile_names(f.profiles);
        if (!f.package.empty()) result.details[L"App Package"] = f.package;
        if (!f.owner.empty()) result.details[L"Local User Owner"] = f.owner;
        if (!f.grouping.empty()) result.details[L"Group"] = f.grouping;
        result.details[L"Technique"] = L"T1562.004 Impair Defenses: Disable or Modify System Firewall";
        if (f.severity >= 3) {
            result.item_name = L"Inbound rule allows all traffic: " + name;
            result.description = L"An enabled inbound firewall rule allows any program on any port from any "
                                 L"address, so the firewall filters nothing for that traffic";
            result.risk_level = SecurityLevel::High;
        } else {
            result.item_name = L"Inbound admin port open to any address: " + name;
            result.description = L"An enabled inbound rule exposes a remote-administration or file-sharing port "
                                 L"to any address on Public networks";
            result.risk_level = SecurityLevel::Medium;
        }
        result.remediation = L"Disable the rule if it is not needed, or restrict it: "
                             L"Set-NetFirewallRule -Name '<rule>' -RemoteAddress LocalSubnet "
                             L"(or the management network).";
        result.reference = L"T1562.004";
        result.timestamp = std::chrono::system_clock::now();
        scan_results_.push_back(result);
    }

    ScanResult inventory;
    inventory.module_name = L"Firewall";
    inventory.item_name = L"Firewall rules";
    inventory.description = std::to_wstring(total_rules) + L" firewall rules reviewed; " +
                            std::to_wstring(flagged.size()) + L" inbound rule(s) open to any address flagged";
    inventory.risk_level = SecurityLevel::Low;
    inventory.timestamp = std::chrono::system_clock::now();
    scan_results_.push_back(inventory);

    SYSRECON_LOG_INFO(L"Firewall rule analysis complete");
    return true;
#else
    return false;
#endif
}

void NetworkEnumerator::Cleanup() {
    tables_loaded_ = false;
    process_names_.clear();
    connections_.clear();
    listening_ports_.clear();
    interfaces_.clear();
    shares_.clear();
    scan_results_.clear();
    initialized_ = false;
}

String NetworkEnumerator::ConnectionStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return L"CLOSED";
        case MIB_TCP_STATE_LISTEN: return L"LISTENING";
        case MIB_TCP_STATE_SYN_SENT: return L"SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return L"SYN_RECEIVED";
        case MIB_TCP_STATE_ESTAB: return L"ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return L"FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2: return L"FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return L"CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return L"LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return L"TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
        default: return L"UNKNOWN";
    }
}

SecurityLevel NetworkEnumerator::AssessConnectionRisk(const NetworkConnection& connection) {
    // Default ports of common post-exploitation frameworks and IRC botnets. A
    // port number is a weak signal on its own, hence Medium, never High.
    switch (connection.remote_port) {
        case 4444: case 4445: case 5555: case 1337: case 31337:
        case 6666: case 6667: case 6697: case 12345: case 54321:
            return SecurityLevel::Medium;
        default:
            return SecurityLevel::Low;
    }
}

SecurityLevel NetworkEnumerator::AssessPortRisk(const ListeningPort& port) {
    if (port.protocol == L"TCP") {
        switch (port.port) {
            case 23:                                       // Telnet: cleartext remote shell.
                return SecurityLevel::High;
            case 21:                                       // FTP: cleartext credentials.
            case 3389:                                     // RDP.
            case 5985: case 5986:                          // WinRM.
            case 5900: case 5901: case 5902: case 5903:    // VNC.
            case 1433:                                     // SQL Server.
            case 4444: case 1337: case 31337:              // Backdoor defaults.
                return SecurityLevel::Medium;
            default:
                return SecurityLevel::Low;
        }
    }
    // UDP
    switch (port.port) {
        case 69:   // TFTP: unauthenticated file transfer.
        case 161:  // SNMP: frequently left with default communities.
            return SecurityLevel::Medium;
        default:
            return SecurityLevel::Low;
    }
}

SecurityLevel NetworkEnumerator::AssessShareRisk(const NetworkShare& share) {
    // Admin shares (ending with $) are created by Windows itself.
    if (!share.share_name.empty() && share.share_name.back() == L'$') {
        return SecurityLevel::Low;
    }

    // A user-created share is worth an analyst's attention, but it is not
    // High on its own. shi2_permissions cannot be used to decide: it is
    // always 0 on modern Windows, so the previous check reported every
    // share as High regardless of its actual ACL.
    return SecurityLevel::Medium;
}


} // namespace Modules
} // namespace SysRecon
