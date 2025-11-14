#pragma once

#include "../sysrecon.h"
#include <set>
#include <algorithm>

namespace SysRecon {
namespace Core {

class SystemWhitelist {
public:
    static SystemWhitelist& Instance() {
        static SystemWhitelist instance;
        return instance;
    }
    
    // Check if a process is a known Windows system process
    bool IsSystemProcess(const String& process_name) const;
    
    // Check if a path is in a trusted system directory
    bool IsSystemPath(const String& path) const;
    
    // Check if a service is a known Windows service
    bool IsSystemService(const String& service_name) const;
    
    // Check if a DLL is a known system DLL
    bool IsSystemDll(const String& dll_name) const;
    
    // Check if a registry key is a known persistence location
    bool IsKnownPersistenceKey(const String& key_path) const;
    
    // Check if unquoted path is actually safe
    bool IsSafeUnquotedPath(const String& path) const;
    
private:
    SystemWhitelist();
    
    std::set<String> system_processes_;
    std::set<String> system_services_;
    std::set<String> system_dlls_;
    std::set<String> system_paths_;
    std::set<String> known_persistence_keys_;
    std::set<String> safe_unquoted_paths_;
};

// Inline implementation
inline SystemWhitelist::SystemWhitelist() {
    // Common Windows system processes
    system_processes_ = {
        L"system", L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
        L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe",
        L"dwm.exe", L"taskhost.exe", L"taskhostw.exe", L"spoolsv.exe",
        L"runtimebroker.exe", L"searchindexer.exe", L"wuauclt.exe",
        L"wmiprvse.exe", L"dllhost.exe", L"msdtc.exe", L"conhost.exe",
        L"fontdrvhost.exe", L"sihost.exe", L"ctfmon.exe", L"audiodg.exe",
        L"dashost.exe", L"searchapp.exe", L"startmenuexperiencehost.exe",
        L"shellexperiencehost.exe", L"textinputhost.exe", L"securityhealthservice.exe",
        L"securityhealthsystray.exe", L"msmpeng.exe", L"nissrv.exe",
        L"sgrmbroker.exe", L"searchprotocolhost.exe", L"searchfilterhost.exe"
    };
    
    // Common Windows services
    system_services_ = {
        L"wuauserv", L"bits", L"eventlog", L"schedule", L"winmgmt",
        L"lanmanserver", L"lanmanworkstation", L"dnscache", L"dhcp",
        L"nsi", L"nlasvc", L"mpssvc", L"wscsvc", L"windefend",
        L"securityhealthservice", L"sense", L"diagtrack", L"dmwappushservice",
        L"spooler", L"stisvc", L"themes", L"audiosrv", L"cryptsvc",
        L"dcomlaunch", L"eventlog", L"gpsvc", L"profiler", L"rpcss",
        L"samss", L"shellhwdetection", L"sysmain", L"tokenbroker",
        L"usosvc", L"wersvc", L"wlidsvc", L"wsearch", L"wuauserv"
    };
    
    // Common system DLLs
    system_dlls_ = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll",
        L"gdi32.dll", L"advapi32.dll", L"ole32.dll", L"oleaut32.dll",
        L"shell32.dll", L"comctl32.dll", L"comdlg32.dll", L"ws2_32.dll",
        L"msvcrt.dll", L"msvcp140.dll", L"vcruntime140.dll",
        L"ucrtbase.dll", L"bcrypt.dll", L"crypt32.dll", L"sechost.dll",
        L"rpcrt4.dll", L"imm32.dll", L"msctf.dll", L"clbcatq.dll"
    };
    
    // System paths (case-insensitive comparison)
    system_paths_ = {
        L"c:\\windows\\system32",
        L"c:\\windows\\syswow64",
        L"c:\\windows",
        L"c:\\program files\\windows defender",
        L"c:\\program files (x86)\\windows defender"
    };
    
    // Known persistence keys (legitimate)
    known_persistence_keys_ = {
        L"Windows Defender",
        L"SecurityHealth",
        L"OneDrive",
        L"Microsoft Edge Update",
        L"Windows Security"
    };
    
    // Safe unquoted paths (these are in root directories without spaces)
    safe_unquoted_paths_ = {
        L"c:\\windows\\",
        L"c:\\program files\\windows"
    };
}

inline bool SystemWhitelist::IsSystemProcess(const String& process_name) const {
    String lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);
    return system_processes_.find(lower_name) != system_processes_.end();
}

inline bool SystemWhitelist::IsSystemPath(const String& path) const {
    String lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::towlower);
    
    for (const auto& sys_path : system_paths_) {
        if (lower_path.find(sys_path) == 0) {
            return true;
        }
    }
    return false;
}

inline bool SystemWhitelist::IsSystemService(const String& service_name) const {
    String lower_name = service_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);
    return system_services_.find(lower_name) != system_services_.end();
}

inline bool SystemWhitelist::IsSystemDll(const String& dll_name) const {
    String lower_name = dll_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);
    return system_dlls_.find(lower_name) != system_dlls_.end();
}

inline bool SystemWhitelist::IsKnownPersistenceKey(const String& key_path) const {
    for (const auto& known : known_persistence_keys_) {
        if (key_path.find(known) != String::npos) {
            return true;
        }
    }
    return false;
}

inline bool SystemWhitelist::IsSafeUnquotedPath(const String& path) const {
    String lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::towlower);
    
    // Check if it's a safe system path
    for (const auto& safe_path : safe_unquoted_paths_) {
        if (lower_path.find(safe_path) == 0) {
            return true;
        }
    }
    
    // If path has no spaces before the executable, it's safe
    size_t exe_pos = lower_path.find(L".exe");
    if (exe_pos != String::npos) {
        String path_before_exe = lower_path.substr(0, exe_pos);
        if (path_before_exe.find(L' ') == String::npos) {
            return true;
        }
    }
    
    return false;
}

}
}
