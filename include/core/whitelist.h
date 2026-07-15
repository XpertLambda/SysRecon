#pragma once

#include "../sysrecon.h"
#include "text_utils.h"
#include <set>
#include <algorithm>

namespace SysRecon {
namespace Core {

// Suppression rules for known-good system components.
//
// Design rule: a name alone must NEVER be enough to suppress a finding. Every
// name in these lists is trivially attacker-chosen -- a service display name, a
// registry Run value name, an implant renamed to csrss.exe. Suppression
// therefore always requires corroborating evidence that the referenced image
// actually lives in a system directory (MITRE T1036.005, masquerading).
class SystemWhitelist {
public:
    static SystemWhitelist& Instance() {
        static SystemWhitelist instance;
        return instance;
    }

    // True only if the name is a known system process AND the image it runs
    // from is inside a system directory. An `svchost.exe` in %TEMP% is not a
    // system process. An empty image_path is treated as unverified -> false.
    bool IsSystemProcess(const String& process_name, const String& image_path) const;
    bool IsSystemService(const String& service_name, const String& image_path) const;
    bool IsSystemDll(const String& dll_name, const String& image_path) const;

    // True if `path` resolves inside a trusted system directory. Respects path
    // boundaries: "C:\WindowsUpdate\evil.exe" is NOT under "C:\Windows".
    bool IsSystemPath(const String& path) const;

    // True only for an exact (case-insensitive) name match whose referenced
    // image also lives under a system path. Substring matching is deliberately
    // not used: it let a Run entry named "OneDrive Updater" suppress itself.
    bool IsKnownPersistenceEntry(const String& entry_name, const String& image_path) const;

    // Implements the actual unquoted-service-path rule: a raw ImagePath is safe
    // if it is quoted, or if the executable token contains no space. Anything
    // else is hijackable (e.g. C:\Program Files\X\y.exe -> C:\Program.exe).
    bool IsSafeUnquotedPath(const String& image_path) const;

    // Operator-supplied known-good entries, so real deployments are not forced
    // to choose between drowning in false positives and patching the binary.
    void AddTrustedPath(const String& path);
    void AddTrustedServiceName(const String& service_name);

private:
    SystemWhitelist();

    bool IsKnownName(const std::set<String>& names, const String& name) const;

    std::set<String> system_processes_;
    std::set<String> system_services_;
    std::set<String> system_dlls_;
    std::set<String> system_paths_;
    std::set<String> known_persistence_names_;
};

inline SystemWhitelist::SystemWhitelist() {
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

    system_services_ = {
        L"wuauserv", L"bits", L"eventlog", L"schedule", L"winmgmt",
        L"lanmanserver", L"lanmanworkstation", L"dnscache", L"dhcp",
        L"nsi", L"nlasvc", L"mpssvc", L"wscsvc", L"windefend",
        L"securityhealthservice", L"sense", L"diagtrack", L"dmwappushservice",
        L"spooler", L"stisvc", L"themes", L"audiosrv", L"cryptsvc",
        L"dcomlaunch", L"gpsvc", L"profiler", L"rpcss",
        L"samss", L"shellhwdetection", L"sysmain", L"tokenbroker",
        L"usosvc", L"wersvc", L"wlidsvc", L"wsearch"
    };

    system_dlls_ = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll",
        L"gdi32.dll", L"advapi32.dll", L"ole32.dll", L"oleaut32.dll",
        L"shell32.dll", L"comctl32.dll", L"comdlg32.dll", L"ws2_32.dll",
        L"msvcrt.dll", L"msvcp140.dll", L"vcruntime140.dll",
        L"ucrtbase.dll", L"bcrypt.dll", L"crypt32.dll", L"sechost.dll",
        L"rpcrt4.dll", L"imm32.dll", L"msctf.dll", L"clbcatq.dll"
    };

    system_paths_ = {
        L"c:\\windows\\system32",
        L"c:\\windows\\syswow64",
        L"c:\\windows",
        L"c:\\program files\\windows defender",
        L"c:\\program files (x86)\\windows defender"
    };

    known_persistence_names_ = {
        L"windows defender",
        L"securityhealth",
        L"onedrive",
        L"microsoft edge update",
        L"windows security"
    };
}

inline bool SystemWhitelist::IsKnownName(const std::set<String>& names, const String& name) const {
    return names.find(Text::ToLowerAscii(name)) != names.end();
}

inline bool SystemWhitelist::IsSystemPath(const String& path) const {
    if (path.empty()) {
        return false;
    }
    for (const auto& sys_path : system_paths_) {
        if (Text::IsPathUnder(path, sys_path)) {
            return true;
        }
    }
    return false;
}

inline bool SystemWhitelist::IsSystemProcess(const String& process_name, const String& image_path) const {
    return IsKnownName(system_processes_, process_name) && IsSystemPath(image_path);
}

inline bool SystemWhitelist::IsSystemService(const String& service_name, const String& image_path) const {
    return IsKnownName(system_services_, service_name) && IsSystemPath(image_path);
}

inline bool SystemWhitelist::IsSystemDll(const String& dll_name, const String& image_path) const {
    return IsKnownName(system_dlls_, dll_name) && IsSystemPath(image_path);
}

inline bool SystemWhitelist::IsKnownPersistenceEntry(const String& entry_name, const String& image_path) const {
    return IsKnownName(known_persistence_names_, entry_name) && IsSystemPath(image_path);
}

inline bool SystemWhitelist::IsSafeUnquotedPath(const String& image_path) const {
    String path = image_path;

    size_t first = path.find_first_not_of(L" \t");
    if (first == String::npos) {
        return true;  // Nothing to hijack.
    }
    path = path.substr(first);

    // A quoted image path cannot be hijacked -- the shell will not split it.
    if (path.front() == L'"') {
        return true;
    }

    // Unquoted: everything up to the first space is what Windows will execute
    // first. If that token is itself the full executable, there is no ambiguity.
    size_t space = path.find(L' ');
    if (space == String::npos) {
        return true;  // No spaces anywhere.
    }

    const String first_token = Text::ToLowerAscii(path.substr(0, space));
    return first_token.size() >= 4 &&
           first_token.compare(first_token.size() - 4, 4, L".exe") == 0;
}

inline void SystemWhitelist::AddTrustedPath(const String& path) {
    system_paths_.insert(Text::ToLowerAscii(path));
}

inline void SystemWhitelist::AddTrustedServiceName(const String& service_name) {
    system_services_.insert(Text::ToLowerAscii(service_name));
}

}
}
