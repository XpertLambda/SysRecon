#pragma once

#include "../../sysrecon.h"

namespace SysRecon {
namespace Modules {

struct NetworkConnection {
    String protocol;
    String local_address;
    USHORT local_port;
    String remote_address;
    USHORT remote_port;
    String state;
    DWORD process_id;
    String process_name;
    std::chrono::system_clock::time_point creation_time;
    SecurityLevel risk_level;
};

struct ListeningPort {
    String protocol;
    String address;
    USHORT port;
    DWORD process_id;
    String process_name;
    String service_name;
    bool is_system_port;
    bool is_filtered;
    SecurityLevel risk_level;
};

struct NetworkInterface {
    String name;
    String description;
    String physical_address;
    StringVector ip_addresses;
    StringVector dns_servers;
    StringVector gateways;
    String dhcp_server;
    bool is_up;
    bool dhcp_enabled;
    DWORD mtu;
    DWORD speed;
    String interface_type;
};

struct NetworkShare {
    String share_name;
    String path;
    String description;
    DWORD share_type;
    DWORD permissions;
    DWORD current_uses;
    DWORD max_uses;
    SecurityLevel risk_level;
};

class NetworkEnumerator {
public:
    NetworkEnumerator();
    ~NetworkEnumerator();
    
    // Main enumeration methods
    bool Initialize();
    bool EnumerateConnections();
    bool EnumerateListeningPorts();
    bool EnumerateInterfaces();
    bool EnumerateShares();
    bool AnalyzeFirewall();
    void Cleanup();
    
    // Results access
    const std::vector<NetworkConnection>& GetConnections() const { return connections_; }
    const std::vector<ListeningPort>& GetListeningPorts() const { return listening_ports_; }
    const std::vector<NetworkInterface>& GetInterfaces() const { return interfaces_; }
    const std::vector<NetworkShare>& GetShares() const { return shares_; }
    const ScanResults& GetScanResults() const { return scan_results_; }
    
    // Configuration
    void SetScanListeningPorts(bool enable) { scan_listening_ports_ = enable; }
    void SetAnalyzeConnections(bool enable) { analyze_connections_ = enable; }
    void SetResolveHostnames(bool enable) { resolve_hostnames_ = enable; }
    
    // Analysis methods
    SecurityLevel AssessConnectionRisk(const NetworkConnection& connection);
    SecurityLevel AssessPortRisk(const ListeningPort& port);
    SecurityLevel AssessShareRisk(const NetworkShare& share);
    
    StringVector FindSuspiciousConnections();
    StringVector FindOpenPorts();
    StringVector FindUnsecureShares();
    StringVector FindSuspiciousPorts();
    
    // Network analysis
    bool IsPortKnown(USHORT port, const String& protocol);
    bool IsAddressPrivate(const String& address);
    bool IsAddressSuspicious(const String& address);
    String ResolveHostname(const String& ip_address);
    String GetPortDescription(USHORT port, const String& protocol);
    
private:
    // Internal enumeration methods
    bool EnumerateTcpConnections();
    bool EnumerateUdpConnections();
    bool EnumerateTcpListeners();
    bool EnumerateUdpListeners();
    bool EnumerateNetworkAdapters();
    bool EnumerateNetworkShares();
    
    // Connection analysis
    void AnalyzeConnection(const NetworkConnection& connection);
    void AnalyzeListeningPort(const ListeningPort& port);
    void AnalyzeNetworkShare(const NetworkShare& share);
    
    // Firewall analysis
    bool CheckWindowsFirewall();
    bool GetFirewallRules(StringVector& rules);
    bool IsFirewallEnabled();
    
    // Helper methods
    String GetProcessNameById(DWORD process_id);
    String ConnectionStateToString(DWORD state);
    String ProtocolToString(DWORD protocol);
    String MacAddressToString(const BYTE* mac_address, DWORD length);
    String InterfaceTypeToString(DWORD type);
    
    // IP geolocation and reputation
    String GetCountryFromIP(const String& ip_address);
    bool IsIPMalicious(const String& ip_address);
    bool IsPortSuspicious(USHORT port, const String& protocol);
    
    // Configuration
    bool scan_listening_ports_;
    bool analyze_connections_;
    bool resolve_hostnames_;
    
    // Data storage
    std::vector<NetworkConnection> connections_;
    std::vector<ListeningPort> listening_ports_;
    std::vector<NetworkInterface> interfaces_;
    std::vector<NetworkShare> shares_;
    ScanResults scan_results_;
    
    // Caches
    std::map<String, String> hostname_cache_;
    std::map<DWORD, String> process_name_cache_;
    std::map<USHORT, String> port_description_cache_;
    
    // State
    bool initialized_;
    StringVector error_messages_;
};

} // namespace Modules
} // namespace SysRecon
