#include "../../include/modules/network/network_enum.h"
#include <iomanip>
#include <lm.h>

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

bool NetworkEnumerator::EnumerateConnections() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating network connections...");
    
#ifdef _WIN32
    PMIB_TCPTABLE2 pTcpTable = nullptr;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    
    // Get TCP table size
    dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE);
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE2*)malloc(dwSize);
        if (pTcpTable == nullptr) {
            SYSRECON_LOG_ERROR(L"Failed to allocate memory for TCP table");
            return false;
        }
    }
    
    // Get TCP connections
    if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW2 row = pTcpTable->table[i];
            
            NetworkConnection conn;
            conn.protocol = L"TCP";
            conn.local_address = Core::Utils::IpAddressToString(ntohl(row.dwLocalAddr));
            conn.local_port = ntohs((u_short)row.dwLocalPort);
            conn.remote_address = Core::Utils::IpAddressToString(ntohl(row.dwRemoteAddr));
            conn.remote_port = ntohs((u_short)row.dwRemotePort);
            conn.state = ConnectionStateToString(row.dwState);
            conn.process_id = row.dwOwningPid;
            conn.risk_level = SecurityLevel::Low;
            
            connections_.push_back(conn);
        }
        
        free(pTcpTable);
    }
    
    // Get UDP table
    PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;
    dwSize = 0;
    dwRetVal = GetExtendedUdpTable(nullptr, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
        if (pUdpTable != nullptr) {
            if (GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                    MIB_UDPROW_OWNER_PID row = pUdpTable->table[i];
                    
                    NetworkConnection conn;
                    conn.protocol = L"UDP";
                    conn.local_address = Core::Utils::IpAddressToString(ntohl(row.dwLocalAddr));
                    conn.local_port = ntohs((u_short)row.dwLocalPort);
                    conn.remote_address = L"";
                    conn.remote_port = 0;
                    conn.state = L"LISTENING";
                    conn.process_id = row.dwOwningPid;
                    conn.risk_level = SecurityLevel::Low;
                    
                    connections_.push_back(conn);
                }
            }
            free(pUdpTable);
        }
    }
    
    SYSRECON_LOG_INFO(L"Enumerated " + std::to_wstring(connections_.size()) + L" connections");
    return true;
#else
    SYSRECON_LOG_INFO(L"Cross-compilation stub - feature available only on Windows");
    return true;
#endif
}

bool NetworkEnumerator::EnumerateListeningPorts() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating listening ports...");
    
    listening_ports_.clear();
    for (const auto& conn : connections_) {
        if (conn.state == L"LISTENING" || conn.state == L"LISTEN" || conn.protocol == L"UDP") {
            ListeningPort listening_port;
            listening_port.port = conn.local_port;
            listening_port.protocol = conn.protocol;
            listening_port.process_id = conn.process_id;
            listening_port.address = conn.local_address;
            listening_port.is_system_port = (conn.local_port < 1024);
            listening_port.risk_level = SecurityLevel::Low;
            listening_ports_.push_back(listening_port);
        }
    }
    
    SYSRECON_LOG_INFO(L"Found " + std::to_wstring(listening_ports_.size()) + L" listening ports");
    return true;
}

bool NetworkEnumerator::EnumerateInterfaces() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating network interfaces...");
    
#ifdef _WIN32
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
        result.details[L"permissions"] = std::to_wstring(share.permissions);
        
        // Check for risky shares
        if (share.permissions == 0 || share.permissions == ACCESS_ALL) {
            result.details[L"warning"] = L"Share has full access permissions";
            result.risk_level = SecurityLevel::High;
        }
        
        // Check for admin shares (ending with $)
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
    // Check if Windows Firewall is enabled
    // This requires COM and Windows Firewall API
    
    // Simplified check: look for firewall service
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        SYSRECON_LOG_ERROR(L"Failed to open service control manager");
        return false;
    }
    
    // Check Windows Firewall service (MpsSvc)
    SC_HANDLE service = OpenServiceW(scm, L"MpsSvc", SERVICE_QUERY_STATUS);
    if (service == NULL) {
        SYSRECON_LOG_WARNING(L"Windows Firewall service not found");
        CloseServiceHandle(scm);
        return false;
    }
    
    SERVICE_STATUS status;
    if (QueryServiceStatus(service, &status)) {
        ScanResult result;
        result.module_name = L"Firewall";
        result.item_name = L"Windows Firewall";
        
        if (status.dwCurrentState == SERVICE_RUNNING) {
            result.description = L"Windows Firewall is running";
            result.risk_level = SecurityLevel::Low;
            result.details[L"status"] = L"Running";
        } else {
            result.description = L"Windows Firewall is not running";
            result.risk_level = SecurityLevel::High;
            result.details[L"status"] = L"Stopped";
            result.details[L"warning"] = L"Firewall is disabled - system is unprotected";
        }
        
        scan_results_.push_back(result);
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    
    SYSRECON_LOG_INFO(L"Firewall analysis complete");
    return true;
#else
    SYSRECON_LOG_INFO(L"Firewall analysis only available on Windows");
    return false;
#endif
}

void NetworkEnumerator::Cleanup() {
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
    // Connections to suspicious ports or addresses
    if (connection.remote_port == 4444 || connection.remote_port == 5555) {
        return SecurityLevel::High; // Common backdoor ports
    }
    return SecurityLevel::Low;
}

SecurityLevel NetworkEnumerator::AssessPortRisk(const ListeningPort& port) {
    // Check for risky open ports
    if (port.port == 445 || port.port == 139) { // SMB
        return SecurityLevel::Medium;
    }
    if (port.port == 3389) { // RDP
        return SecurityLevel::Medium;
    }
    return SecurityLevel::Low;
}

SecurityLevel NetworkEnumerator::AssessShareRisk(const NetworkShare& share) {
    // Admin shares (ending with $) are normal
    if (!share.share_name.empty() && share.share_name.back() == L'$') {
        return SecurityLevel::Low;
    }
    
    // Shares with full access are risky
    if (share.permissions == 0 || share.permissions == ACCESS_ALL) {
        return SecurityLevel::High;
    }
    
    return SecurityLevel::Low;
}

// Stub implementations for unimplemented methods
StringVector NetworkEnumerator::FindSuspiciousConnections() { return StringVector(); }
StringVector NetworkEnumerator::FindOpenPorts() { return StringVector(); }
StringVector NetworkEnumerator::FindUnsecureShares() { return StringVector(); }
StringVector NetworkEnumerator::FindSuspiciousPorts() { return StringVector(); }
bool NetworkEnumerator::IsPortKnown(USHORT, const String&) { return false; }
bool NetworkEnumerator::IsAddressPrivate(const String&) { return false; }
bool NetworkEnumerator::IsAddressSuspicious(const String&) { return false; }
String NetworkEnumerator::ResolveHostname(const String&) { return L""; }
String NetworkEnumerator::GetPortDescription(USHORT, const String&) { return L""; }

} // namespace Modules
} // namespace SysRecon
