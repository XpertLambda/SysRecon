#include "../../include/modules/network/network_enum.h"

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
    return true;
}

bool NetworkEnumerator::EnumerateShares() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Enumerating network shares...");
    return true;
}

bool NetworkEnumerator::AnalyzeFirewall() {
    if (!initialized_) return false;
    
    SYSRECON_LOG_INFO(L"Analyzing firewall configuration...");
    return true;
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

}
}
