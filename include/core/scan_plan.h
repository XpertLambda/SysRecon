#pragma once

#include "config.h"
#include <functional>

// Pure, platform-independent decisions about what a run will do: which
// modules, which report formats, which config file, where output goes.
//
// These used to be spread across main.cpp and the engine, and the order in
// which they were applied was itself the bug -- e.g. modules were constructed
// from the config selection *before* the command-line selection was applied,
// so `--memory` against a config with memory disabled silently did nothing.
// Keeping them here makes every precedence rule unit-testable.

namespace SysRecon {
namespace Core {

struct ModuleSelection {
    bool accounts = false;
    bool services = false;
    bool processes = false;
    bool network = false;
    bool registry = false;
    bool memory = false;
    bool privesc = false;
    bool domain = false;

    bool IsEnabled(ModuleType module) const;
    void Set(ModuleType module, bool enabled);
    bool Any() const;
    size_t Count() const;
    StringVector Names() const;

    static ModuleSelection All();
    static ModuleSelection FromConfig(const ScanConfig& config);
};

// The scan modules in execution order.
const std::vector<ModuleType>& AllScanModules();
String ModuleDisplayName(ModuleType module);

struct CliModuleRequest {
    // True if any module flag (--accounts, --memory, --all, ...) was given.
    bool explicit_selection = false;
    ModuleSelection modules;
};

// Precedence: an explicit command-line selection replaces the config file's
// selection entirely; otherwise the config's `enabled` flags apply (or the
// built-in defaults when no config was loaded, which keep Memory off).
// Stealth mode removes the Memory module regardless of how it was selected,
// because walking other processes' address spaces is the opposite of a
// low-footprint run. Each override is explained in `notes` when non-null.
ModuleSelection ResolveModules(const ScanConfig& config, const CliModuleRequest& cli,
                               bool stealth, StringVector* notes = nullptr);

// Report formats: explicit -f values win; otherwise the config's
// generate_json/csv/html flags apply. Never returns an empty list.
StringVector ResolveFormats(const StringVector& cli_formats, const ScanConfig& config);

// Parses a --min-severity value ("low"/"medium"/"high"/"critical", any case)
// into a SecurityLevel. Returns nullopt for an unrecognised value.
std::optional<SecurityLevel> ParseSeverity(const String& text);
// Process exit code derived from the highest finding severity, for CI/triage:
// none/low=0 (informational), medium=10, high=20, critical=30.
int SeverityExitCode(SecurityLevel level, bool any_findings);

// Locates the config file. An explicit -c path is returned as-is (the caller
// reports it if missing). Otherwise ./config.json is tried, then config.json
// next to the executable -- an elevated shell starts in System32, so the
// working directory alone made an installed copy run with no config at all.
// Returns an empty string if nothing was found.
String ResolveConfigPath(const String& cli_path, const String& exe_dir,
                         const std::function<bool(const String&)>& file_exists);

// Path helpers that treat both '\' and '/' as separators and recognise drive
// letters and UNC paths regardless of host OS, so they test identically on
// Linux and Windows.
bool IsAbsolutePath(const String& path);
String ParentDirectory(const String& path);
// Resolves a relative `path` against `base_dir`; absolute paths and an empty
// base are returned unchanged. A leading ".\" or "./" is dropped.
String ResolveAgainst(const String& base_dir, const String& path);

}
}
