#include "../../include/modules/network/network_enum.h"
#include <iomanip>
#include <lm.h>
#include "../../include/core/text_utils.h"

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

bool NetworkEnumerator::EnumerateListeningPorts() {
    if (!initialized_) return false;

    SYSRECON_LOG_INFO(L"Enumerating listening ports...");

    // Load on demand: the quick scan calls this without EnumerateConnections,
    // and previously always found zero listening ports as a result.
    if (!tables_loaded_ && !LoadTables()) {
        return false;
    }

    listening_ports_.clear();
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
            exposed.push_back(std::to_wstring(port.port) + L"/" + port.process_name);
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
    
    DWORD result = GetAdaptersInfo(adapter_info, &buffer_size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        free(adapter_info);
        adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);
        if (adapter_info == NULL) {
            return false;
        }
        result = GetAdaptersInfo(adapter_info, &buffer_size);
    }
    
    if (result != ERROR_SUCCESS) {
        SYSRECON_LOG_ERROR(L"GetAdaptersInfo failed: " + std::to_wstring(result));
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
