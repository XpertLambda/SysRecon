#include "../../include/core/scan_plan.h"

#include <cwctype>

namespace SysRecon {
namespace Core {

bool ModuleSelection::IsEnabled(ModuleType module) const {
    switch (module) {
        case ModuleType::Accounts:  return accounts;
        case ModuleType::Services:  return services;
        case ModuleType::Processes: return processes;
        case ModuleType::Network:   return network;
        case ModuleType::Registry:  return registry;
        case ModuleType::Memory:    return memory;
        case ModuleType::PrivEsc:   return privesc;
        default:                    return false;
    }
}

void ModuleSelection::Set(ModuleType module, bool enabled) {
    switch (module) {
        case ModuleType::Accounts:  accounts = enabled; break;
        case ModuleType::Services:  services = enabled; break;
        case ModuleType::Processes: processes = enabled; break;
        case ModuleType::Network:   network = enabled; break;
        case ModuleType::Registry:  registry = enabled; break;
        case ModuleType::Memory:    memory = enabled; break;
        case ModuleType::PrivEsc:   privesc = enabled; break;
        default: break;
    }
}

bool ModuleSelection::Any() const {
    return Count() > 0;
}

size_t ModuleSelection::Count() const {
    size_t n = 0;
    for (ModuleType m : AllScanModules()) {
        if (IsEnabled(m)) ++n;
    }
    return n;
}

StringVector ModuleSelection::Names() const {
    StringVector names;
    for (ModuleType m : AllScanModules()) {
        if (IsEnabled(m)) names.push_back(ModuleDisplayName(m));
    }
    return names;
}

ModuleSelection ModuleSelection::All() {
    ModuleSelection s;
    for (ModuleType m : AllScanModules()) s.Set(m, true);
    return s;
}

ModuleSelection ModuleSelection::FromConfig(const ScanConfig& c) {
    ModuleSelection s;
    s.accounts = c.accounts.enabled;
    s.services = c.services.enabled;
    s.processes = c.processes.enabled;
    s.network = c.network.enabled;
    s.registry = c.registry.enabled;
    s.memory = c.memory.enabled;
    s.privesc = c.privesc.enabled;
    return s;
}

const std::vector<ModuleType>& AllScanModules() {
    static const std::vector<ModuleType> modules = {
        ModuleType::Accounts, ModuleType::Services, ModuleType::Processes,
        ModuleType::Network,  ModuleType::Registry, ModuleType::Memory,
        ModuleType::PrivEsc,
    };
    return modules;
}

String ModuleDisplayName(ModuleType module) {
    switch (module) {
        case ModuleType::Accounts:  return L"Accounts";
        case ModuleType::Services:  return L"Services";
        case ModuleType::Processes: return L"Processes";
        case ModuleType::Network:   return L"Network";
        case ModuleType::Registry:  return L"Registry";
        case ModuleType::Memory:    return L"Memory";
        case ModuleType::PrivEsc:   return L"Privilege Escalation";
        default:                    return L"Unknown";
    }
}

ModuleSelection ResolveModules(const ScanConfig& config, const CliModuleRequest& cli,
                               bool stealth, StringVector* notes) {
    ModuleSelection selection = cli.explicit_selection ? cli.modules
                                                       : ModuleSelection::FromConfig(config);

    if (cli.explicit_selection && notes) {
        for (ModuleType m : AllScanModules()) {
            if (selection.IsEnabled(m) && !ModuleSelection::FromConfig(config).IsEnabled(m)) {
                notes->push_back(ModuleDisplayName(m) +
                                 L" is disabled in the config file but was requested on the command line");
            }
        }
    }

    if (stealth && selection.memory) {
        selection.memory = false;
        if (notes) {
            notes->push_back(L"Memory module skipped: stealth mode does not read other processes' memory");
        }
    }
    return selection;
}

StringVector ResolveFormats(const StringVector& cli_formats, const ScanConfig& config) {
    if (!cli_formats.empty()) {
        StringVector unique;
        for (const auto& f : cli_formats) {
            if (std::find(unique.begin(), unique.end(), f) == unique.end()) {
                unique.push_back(f);
            }
        }
        return unique;
    }
    StringVector formats;
    if (config.output.generate_json) formats.push_back(L"json");
    if (config.output.generate_csv)  formats.push_back(L"csv");
    if (config.output.generate_html) formats.push_back(L"html");
    if (formats.empty()) {
        formats = {L"json", L"csv", L"html"};  // Validation forbids this; stay safe anyway.
    }
    return formats;
}

std::optional<SecurityLevel> ParseSeverity(const String& text) {
    String t;
    for (wchar_t c : text) t.push_back(static_cast<wchar_t>(::towlower(c)));
    if (t == L"low")      return SecurityLevel::Low;
    if (t == L"medium")   return SecurityLevel::Medium;
    if (t == L"high")     return SecurityLevel::High;
    if (t == L"critical") return SecurityLevel::Critical;
    return std::nullopt;
}

int SeverityExitCode(SecurityLevel level, bool any_findings) {
    if (!any_findings) return 0;
    switch (level) {
        case SecurityLevel::Critical: return 30;
        case SecurityLevel::High:     return 20;
        case SecurityLevel::Medium:   return 10;
        case SecurityLevel::Low:      return 0;
    }
    return 0;
}

String ResolveConfigPath(const String& cli_path, const String& exe_dir,
                         const std::function<bool(const String&)>& file_exists) {
    if (!cli_path.empty()) {
        return cli_path;
    }
    const String local = L"config.json";
    if (file_exists(local)) {
        return local;
    }
    if (!exe_dir.empty()) {
        const String beside_exe = ResolveAgainst(exe_dir, L"config.json");
        if (file_exists(beside_exe)) {
            return beside_exe;
        }
    }
    return String();
}

bool IsAbsolutePath(const String& path) {
    if (path.empty()) {
        return false;
    }
    if (path[0] == L'\\' || path[0] == L'/') {
        return true;  // Root-relative, UNC (\\server\share) or POSIX absolute.
    }
    // Drive-qualified: "C:\..." or "C:/...". ("C:foo" is drive-relative, which
    // we deliberately treat as relative.)
    return path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/') &&
           ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
}

String ParentDirectory(const String& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == String::npos) {
        return String();
    }
    if (slash == 0) {
        return path.substr(0, 1);
    }
    return path.substr(0, slash);
}

String ResolveAgainst(const String& base_dir, const String& path) {
    if (base_dir.empty() || IsAbsolutePath(path)) {
        return path;
    }
    String rel = path;
    while (rel.size() >= 2 && rel[0] == L'.' && (rel[1] == L'\\' || rel[1] == L'/')) {
        rel = rel.substr(2);
    }
    if (rel.empty() || rel == L".") {
        return base_dir;
    }
    const wchar_t last = base_dir.back();
    const bool has_sep = (last == L'\\' || last == L'/');
    // Match the separator style already used by the base.
    const wchar_t sep = (base_dir.find(L'/') != String::npos && base_dir.find(L'\\') == String::npos)
                            ? L'/' : L'\\';
    return has_sep ? base_dir + rel : base_dir + sep + rel;
}

}
}
