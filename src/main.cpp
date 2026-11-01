#include "../include/sysrecon.h"
#include "../include/core/engine.h"
#include <map>
#include <algorithm>
#include <iostream>
#include <windows.h>
#include <cstdio>
#include <clocale>

using namespace SysRecon;
using namespace SysRecon::Core;

// Command-line options structure
struct CommandLineOptions {
    bool show_help = false;
    bool show_version = false;
    bool verbose = false;
    bool quiet = false;
    bool stealth = false;
    bool quick = false;
    // Empty means "not specified": the config is then looked up in the
    // working directory and next to sysrecon.exe (scan_plan.h).
    String config_file;
    // Empty means "not specified on the command line", so config.json's
    // output_directory is not clobbered by a CLI default. The engine resolves
    // the effective value (CLI flag > config file > ./reports).
    String output_dir;
    // Empty means "use config.json's generate_json/csv/html".
    StringVector formats;

    // Module selection (empty = all modules)
    bool accounts_only = false;
    bool services_only = false;
    bool processes_only = false;
    bool network_only = false;
    bool registry_only = false;
    bool memory_only = false;
    bool selective_scan = false;
};

void PrintBanner() {
    std::wcout << L"\n";
    std::wcout << L"███████╗██╗   ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n";
    std::wcout << L"██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n";
    std::wcout << L"███████╗ ╚████╔╝ ███████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n";
    std::wcout << L"╚════██║  ╚██╔╝  ╚════██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n";
    std::wcout << L"███████║   ██║   ███████║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n";
    std::wcout << L"╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\n";
    std::wcout << L"\n";
    std::wcout << L"Windows Security Audit & Reconnaissance Tool v" << SYSRECON_VERSION << L"\n";
    std::wcout << L"Copyright (C) 2025 - XpertLambda\n";
    std::wcout << L"═══════════════════════════════════════════════════════════════════════\n\n";
}

void PrintHelp() {
    PrintBanner();
    std::wcout << L"USAGE:\n";
    std::wcout << L"  sysrecon.exe [OPTIONS]\n\n";
    
    std::wcout << L"OPTIONS:\n";
    std::wcout << L"  -h, --help              Show this help message and exit\n";
    std::wcout << L"  -v, --version           Show version information\n";
    std::wcout << L"  --verbose               Enable verbose output\n";
    std::wcout << L"  --quiet                 Suppress non-essential output\n";
    std::wcout << L"  --stealth               Low-footprint scan: no console log, no per-process\n";
    std::wcout << L"                          DLL snapshots, Memory module skipped\n";
    std::wcout << L"  --quick                 Quick scan: accounts, services, listening ports,\n";
    std::wcout << L"                          firewall and Run keys only\n";
    std::wcout << L"\n";

    std::wcout << L"CONFIGURATION:\n";
    std::wcout << L"  -c, --config FILE       Load configuration from FILE. Default: ./config.json,\n";
    std::wcout << L"                          then config.json next to sysrecon.exe\n";
    std::wcout << L"  -o, --output DIR        Set output directory (default: config's\n";
    std::wcout << L"                          output_directory, relative to the config file)\n";
    std::wcout << L"  -f, --format FORMAT     Report format: json, csv, html, all\n";
    std::wcout << L"                          (default: config's generate_* settings)\n";
    std::wcout << L"                          Can specify multiple: -f json -f csv\n";
    std::wcout << L"\n";

    std::wcout << L"MODULE SELECTION (replaces the config's module selection):\n";
    std::wcout << L"  --accounts              User accounts, groups and password policy\n";
    std::wcout << L"  --services              Windows services\n";
    std::wcout << L"  --processes             Running processes and loaded DLLs\n";
    std::wcout << L"  --network               Connections, listening ports, shares, firewall\n";
    std::wcout << L"  --registry              Persistence keys, security policy, key ACLs\n";
    std::wcout << L"  --memory                Process memory analysis (slow; EDR-visible)\n";
    std::wcout << L"  --all                   All six modules, including Memory\n";
    std::wcout << L"  Without a module flag, the modules enabled in config.json run\n";
    std::wcout << L"  (Memory is off by default).\n";
    std::wcout << L"\n";

    std::wcout << L"EXIT CODES:\n";
    std::wcout << L"  0  scan completed and all reports were written\n";
    std::wcout << L"  1  invalid arguments/config, initialization failure, or a report failed\n";
    std::wcout << L"\n";

    std::wcout << L"EXAMPLES:\n";
    std::wcout << L"  sysrecon.exe                          # Interactive menu\n";
    std::wcout << L"  sysrecon.exe --verbose                # Scan config-enabled modules, verbose\n";
    std::wcout << L"  sysrecon.exe --quick                  # Quick scan\n";
    std::wcout << L"  sysrecon.exe --accounts --services    # Scan only accounts and services\n";
    std::wcout << L"  sysrecon.exe --all                    # Everything, including memory\n";
    std::wcout << L"  sysrecon.exe -f json -o .\\output      # JSON report to .\\output\n";
    std::wcout << L"  sysrecon.exe --stealth --quiet        # Low-footprint silent scan\n";
    std::wcout << L"\n";
}

void PrintVersion() {
    PrintBanner();
    std::wcout << L"Version:      " << SYSRECON_VERSION << L"\n";
    std::wcout << L"Build Date:   " << __DATE__ << L" " << __TIME__ << L"\n";
    std::wcout << L"Target:       Windows x64\n";
    std::wcout << L"Compiler:     MinGW-w64 (C++20)\n";
    std::wcout << L"\n";
    std::wcout << L"New in v1.1.0:\n";
    std::wcout << L"  * Interactive menu mode for easy navigation\n";
    std::wcout << L"  * Enhanced module selection interface\n";
    std::wcout << L"  * Real-time configuration changes\n";
    std::wcout << L"  * Improved user experience\n";
    std::wcout << L"\n";
}

// True if a standard handle points at a file or pipe rather than a console.
// Redirected output must never be reattached to a console.
bool StdHandleIsRedirected(DWORD std_handle) {
    HANDLE handle = GetStdHandle(std_handle);
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD mode = 0;
    // GetConsoleMode succeeds only for real console handles.
    return GetConsoleMode(handle, &mode) == 0;
}

// Interactive menu functions
void ClearScreen() {
    // Never write escape sequences into a redirected file or pipe.
    if (StdHandleIsRedirected(STD_OUTPUT_HANDLE)) {
        return;
    }
    // Deliberately not system("cls"): that spawns cmd.exe on every redraw,
    // which resolves through PATH/%COMSPEC% and is a hijack surface when
    // running elevated. VT is enabled in wmain.
    std::wcout << L"\033[2J\033[H";
    std::wcout.flush();
}

void WaitForKey() {
    std::wcout << L"\nPress any key to continue...";
    std::wcout.flush();

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    // With redirected or invalid stdin there is no key to wait for. Returning
    // matters: WaitForKey is called from the fatal-error path, and spinning
    // here would hang the process instead of reporting the failure.
    if (hStdin == NULL || hStdin == INVALID_HANDLE_VALUE || !GetConsoleMode(hStdin, &mode)) {
        std::wcout << L"\n";
        return;
    }

    SetConsoleMode(hStdin, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));

    INPUT_RECORD inputRecord;
    DWORD events = 0;
    while (ReadConsoleInput(hStdin, &inputRecord, 1, &events)) {
        if (events > 0 && inputRecord.EventType == KEY_EVENT &&
            inputRecord.Event.KeyEvent.bKeyDown) {
            break;
        }
    }

    SetConsoleMode(hStdin, mode);
    std::wcout << L"\n";
}

int GetMenuChoice(int min, int max) {
    int choice;
    while (true) {
        std::wcout << L"\nEnter choice (" << min << L"-" << max << L"): ";
        std::wcin >> choice;

        // End of input (stdin redirected from a file, or closed): treat as
        // "exit". Clearing and retrying here looped forever, so
        // `sysrecon.exe < NUL` hung instead of returning.
        if (std::wcin.eof() || std::wcin.bad()) {
            std::wcout << L"\n";
            return 0;
        }

        if (std::wcin.fail()) {
            std::wcin.clear();
            std::wcin.ignore(10000, L'\n');
            std::wcout << L"Invalid input. Please enter a number.\n";
            continue;
        }
        
        if (choice >= min && choice <= max) {
            std::wcin.ignore(10000, L'\n');
            return choice;
        }
        
        std::wcout << L"Invalid choice. Please enter a number between " << min << L" and " << max << L".\n";
    }
}

String GetStringInput(const wchar_t* prompt, const String& defaultValue = L"") {
    std::wcout << prompt;
    if (!defaultValue.empty()) {
        std::wcout << L" [" << defaultValue << L"]";
    }
    std::wcout << L": ";
    
    String input;
    std::getline(std::wcin, input);
    
    if (input.empty() && !defaultValue.empty()) {
        return defaultValue;
    }
    
    return input;
}

void ShowMainMenu() {
    ClearScreen();
    PrintBanner();
    
    std::wcout << L"╔══════════════════════════════════════════════════════════════════════╗\n";
    std::wcout << L"║                           MAIN MENU                                  ║\n";
    std::wcout << L"╚══════════════════════════════════════════════════════════════════════╝\n";
    std::wcout << L"\n";
    std::wcout << L"  1. Run Full System Scan (modules enabled in config)\n";
    std::wcout << L"  2. Run Selective Module Scan\n";
    std::wcout << L"  3. Quick Scan Mode\n";
    std::wcout << L"  4. Stealth Mode Scan\n";
    std::wcout << L"  5. Configure Settings\n";
    std::wcout << L"  6. View Report Options\n";
    std::wcout << L"  7. About / Version Info\n";
    std::wcout << L"  8. Help & Command-Line Usage\n";
    std::wcout << L"  0. Exit\n";
    std::wcout << L"\n";
    std::wcout << L"══════════════════════════════════════════════════════════════════════\n";
}

void ShowModuleSelectionMenu(CommandLineOptions& options) {
    ClearScreen();
    PrintBanner();
    
    std::wcout << L"╔══════════════════════════════════════════════════════════════════════╗\n";
    std::wcout << L"║                     SELECT MODULES TO SCAN                           ║\n";
    std::wcout << L"╚══════════════════════════════════════════════════════════════════════╝\n";
    std::wcout << L"\n";
    std::wcout << L"  1. User Accounts & Groups\n";
    std::wcout << L"  2. Windows Services\n";
    std::wcout << L"  3. Running Processes\n";
    std::wcout << L"  4. Network Connections & Ports\n";
    std::wcout << L"  5. Registry Persistence Keys\n";
    std::wcout << L"  6. Process Memory Analysis (Slow)\n";
    std::wcout << L"  7. Select All Modules (including Memory)\n";
    std::wcout << L"  8. Start Scan with Selected Modules\n";
    std::wcout << L"  0. Back to Main Menu\n";
    std::wcout << L"\n";
    std::wcout << L"══════════════════════════════════════════════════════════════════════\n";
    std::wcout << L"Selected: ";
    
    const bool any_selected = options.accounts_only || options.services_only ||
                              options.processes_only || options.network_only ||
                              options.registry_only || options.memory_only;
    if (!options.selective_scan || !any_selected) {
        std::wcout << L"None";
    } else {
        bool first = true;
        if (options.accounts_only) { std::wcout << (first ? L"" : L", ") << L"Accounts"; first = false; }
        if (options.services_only) { std::wcout << (first ? L"" : L", ") << L"Services"; first = false; }
        if (options.processes_only) { std::wcout << (first ? L"" : L", ") << L"Processes"; first = false; }
        if (options.network_only) { std::wcout << (first ? L"" : L", ") << L"Network"; first = false; }
        if (options.registry_only) { std::wcout << (first ? L"" : L", ") << L"Registry"; first = false; }
        if (options.memory_only) { std::wcout << (first ? L"" : L", ") << L"Memory"; first = false; }
    }
    std::wcout << L"\n";
}

void ShowConfigurationMenu(CommandLineOptions& options) {
    ClearScreen();
    PrintBanner();
    
    std::wcout << L"╔══════════════════════════════════════════════════════════════════════╗\n";
    std::wcout << L"║                       CONFIGURATION SETTINGS                         ║\n";
    std::wcout << L"╚══════════════════════════════════════════════════════════════════════╝\n";
    std::wcout << L"\n";
    std::wcout << L"Current Settings:\n";
    std::wcout << L"────────────────────────────────────────────────────────────────────\n";
    std::wcout << L"  Config File:    "
               << (options.config_file.empty() ? L"(auto: .\\config.json, then next to sysrecon.exe)"
                                               : options.config_file.c_str())
               << L"\n";
    std::wcout << L"  Output Dir:     "
               << (options.output_dir.empty() ? L"(from config, default ./reports)" : options.output_dir)
               << L"\n";
    std::wcout << L"  Report Formats: "
               << (options.formats.empty() ? L"(from config)" : Core::Utils::Join(options.formats, L", "))
               << L"\n";
    std::wcout << L"  Verbose Mode:   " << (options.verbose ? L"Enabled" : L"Disabled") << L"\n";
    std::wcout << L"  Quiet Mode:     " << (options.quiet ? L"Enabled" : L"Disabled") << L"\n";
    std::wcout << L"────────────────────────────────────────────────────────────────────\n";
    std::wcout << L"\n";
    std::wcout << L"  1. Change Output Directory\n";
    std::wcout << L"  2. Change Report Formats\n";
    std::wcout << L"  3. Toggle Verbose Mode\n";
    std::wcout << L"  4. Toggle Quiet Mode\n";
    std::wcout << L"  5. Load Config File\n";
    std::wcout << L"  0. Back to Main Menu\n";
    std::wcout << L"\n";
    std::wcout << L"══════════════════════════════════════════════════════════════════════\n";
}

void ShowReportOptionsMenu(CommandLineOptions& options) {
    ClearScreen();
    PrintBanner();
    
    std::wcout << L"╔══════════════════════════════════════════════════════════════════════╗\n";
    std::wcout << L"║                         REPORT OPTIONS                               ║\n";
    std::wcout << L"╚══════════════════════════════════════════════════════════════════════╝\n";
    std::wcout << L"\n";
    std::wcout << L"Select report format(s) to generate:\n";
    std::wcout << L"\n";
    std::wcout << L"  1. JSON Format (Machine-readable, detailed)\n";
    std::wcout << L"  2. CSV Format (Spreadsheet-compatible)\n";
    std::wcout << L"  3. HTML Format (Human-readable, visual)\n";
    std::wcout << L"  4. All Formats\n";
    std::wcout << L"  0. Back to Main Menu\n";
    std::wcout << L"\n";
    std::wcout << L"══════════════════════════════════════════════════════════════════════\n";
    std::wcout << L"Current Formats: "
               << (options.formats.empty() ? L"(from config)" : Core::Utils::Join(options.formats, L", "))
               << L"\n";
}

bool ParseArguments(int argc, wchar_t* argv[], CommandLineOptions& options) {
    for (int i = 1; i < argc; i++) {
        String arg = argv[i];
        
        // Help
        if (arg == L"-h" || arg == L"--help") {
            options.show_help = true;
            return true;
        }
        
        // Version
        if (arg == L"-v" || arg == L"--version") {
            options.show_version = true;
            return true;
        }
        
        // Verbosity
        if (arg == L"--verbose") {
            options.verbose = true;
            continue;
        }
        
        if (arg == L"--quiet") {
            options.quiet = true;
            continue;
        }
        
        // Scan modes
        if (arg == L"--stealth") {
            options.stealth = true;
            continue;
        }
        
        if (arg == L"--quick") {
            options.quick = true;
            continue;
        }
        
        // Config file
        if (arg == L"-c" || arg == L"--config") {
            if (i + 1 < argc) {
                options.config_file = argv[++i];
            } else {
                std::wcerr << L"Error: --config requires a filename\n";
                return false;
            }
            continue;
        }
        
        // Output directory
        if (arg == L"-o" || arg == L"--output") {
            if (i + 1 < argc) {
                options.output_dir = argv[++i];
            } else {
                std::wcerr << L"Error: --output requires a directory path\n";
                return false;
            }
            continue;
        }
        
        // Format
        if (arg == L"-f" || arg == L"--format") {
            if (i + 1 < argc) {
                String format = argv[++i];
                std::transform(format.begin(), format.end(), format.begin(), ::towlower);
                
                if (format == L"all") {
                    options.formats = {L"json", L"csv", L"html"};
                } else if (format == L"json" || format == L"csv" || format == L"html") {
                    options.formats.push_back(format);  // Duplicates are dropped by ResolveFormats.
                } else {
                    std::wcerr << L"Error: Invalid format '" << format << L"'. Use json, csv, html, or all\n";
                    return false;
                }
            } else {
                std::wcerr << L"Error: --format requires a format type\n";
                return false;
            }
            continue;
        }
        
        // Module selection
        if (arg == L"--accounts") {
            options.accounts_only = true;
            options.selective_scan = true;
            continue;
        }
        
        if (arg == L"--services") {
            options.services_only = true;
            options.selective_scan = true;
            continue;
        }
        
        if (arg == L"--processes") {
            options.processes_only = true;
            options.selective_scan = true;
            continue;
        }
        
        if (arg == L"--network") {
            options.network_only = true;
            options.selective_scan = true;
            continue;
        }
        
        if (arg == L"--registry") {
            options.registry_only = true;
            options.selective_scan = true;
            continue;
        }
        
        if (arg == L"--memory") {
            options.memory_only = true;
            options.selective_scan = true;
            continue;
        }

        if (arg == L"--all") {
            options.accounts_only = options.services_only = options.processes_only = true;
            options.network_only = options.registry_only = options.memory_only = true;
            options.selective_scan = true;
            continue;
        }
        
        // Unknown option
        std::wcerr << L"Error: Unknown option '" << arg << L"'\n";
        std::wcerr << L"Use --help for usage information\n";
        return false;
    }
    
    return true;
}

// Log level precedence: --verbose > --quiet > config verbose_output > Info.
// Applied after the config is loaded; previously LoadConfig reset the level
// from config.json and silently overrode --verbose and --quiet.
void ApplyLogLevel(const CommandLineOptions& options, bool config_verbose) {
    LogLevel level = LogLevel::Info;
    if (options.verbose) {
        level = LogLevel::Debug;
    } else if (options.quiet) {
        level = LogLevel::Error;
    } else if (config_verbose) {
        level = LogLevel::Debug;
    }
    Logger::Instance().SetLogLevel(level);
}

CliModuleRequest BuildModuleRequest(const CommandLineOptions& options) {
    CliModuleRequest req;
    req.explicit_selection = options.selective_scan;
    req.modules.accounts = options.accounts_only;
    req.modules.services = options.services_only;
    req.modules.processes = options.processes_only;
    req.modules.network = options.network_only;
    req.modules.registry = options.registry_only;
    req.modules.memory = options.memory_only;
    return req;
}

// Function to run the actual scan. Follows the lifecycle documented in
// engine.h: everything that decides *what* runs is resolved before
// Initialize() constructs the modules.
int RunScan(CommandLineOptions& options) {
    Logger& log = Logger::Instance();
    log.CloseLogFile();
    // --stealth silences console logging from the very first line; config's
    // stealth_mode can only take effect once the config has been read.
    log.SetConsoleOutput(!options.stealth);
    ApplyLogLevel(options, false);

    if (!options.quiet) {
        ClearScreen();
        PrintBanner();
    }

    log.Info(L"SysRecon starting...");

    ScanEngine& engine = ScanEngine::Instance();
    engine.Reset();

    // 1. Configuration.
    const String config_path = ResolveConfigPath(options.config_file, Core::Utils::GetExecutableDirectory(),
                                                 [](const String& p) { return Core::Utils::FileExists(p); });
    if (!options.config_file.empty() && !Core::Utils::FileExists(options.config_file)) {
        // An explicit -c that does not exist is an operator error, not a
        // reason to scan with settings nobody asked for.
        std::wcerr << L"[-] Configuration file not found: " << options.config_file << L"\n";
        return 1;
    }
    if (config_path.empty()) {
        log.Info(L"No config.json found (working directory or next to sysrecon.exe); using built-in defaults");
    } else if (!engine.LoadConfig(config_path)) {
        // A config file that exists but is invalid aborts the run: carrying on
        // with defaults would silently drop the operator's module selection,
        // output location and require_admin setting.
        std::wcerr << L"[-] Invalid configuration file: " << config_path << L"\n";
        for (const auto& err : ConfigManager::Instance().GetValidationErrors()) {
            std::wcerr << L"    * " << err << L"\n";
        }
        return 1;
    }
    const ScanConfig& cfg = ConfigManager::Instance().GetConfig();
    ApplyLogLevel(options, cfg.verbose_output);

    // 2. What to run.
    const bool stealth = options.stealth || cfg.stealth_mode;
    StringVector plan_notes;
    const ModuleSelection selection = ResolveModules(cfg, BuildModuleRequest(options), stealth, &plan_notes);
    for (const auto& note : plan_notes) {
        log.Info(note);
    }
    if (!selection.Any()) {
        std::wcerr << L"[-] No scan modules selected";
        if (stealth && options.memory_only) {
            std::wcerr << L" (stealth mode does not run the Memory module)";
        }
        std::wcerr << L"\n";
        return 1;
    }
    engine.SetModuleSelection(selection);
    const StringVector formats = ResolveFormats(options.formats, cfg);

    // 3. Where output goes. CLI flags win over the config file; a relative -o
    // is relative to the working directory, as for any command-line tool.
    if (!options.output_dir.empty()) {
        engine.SetOutputDirectory(options.output_dir);
    }
    engine.SetStealthMode(stealth);

    // 4. Construct and configure exactly the selected modules.
    if (!engine.Initialize()) {
        log.Error(L"Failed to initialize scan engine");
        if (engine.HasErrors()) {
            for (const auto& err : engine.GetErrors()) {
                std::wcerr << L"  * " << err << L"\n";
            }
        }
        return 1;
    }
    engine.ApplyConfigToModules();

    const String output_dir = engine.GetOutputDirectory();
    {
        const String log_path = output_dir + L"\\sysrecon.log";
        log.SetLogFile(log_path);
        log.Info(L"Log file: " + log_path);
    }

    // Display scan information
    if (!options.quiet) {
        std::wcout << L"[*] Starting system scan...\n";
        std::wcout << L"  Config:   " << (engine.IsConfigLoaded() ? engine.GetConfigPath() : String(L"(built-in defaults)")) << L"\n";
        std::wcout << L"  Modules:  " << Core::Utils::Join(selection.Names(), L", ") << L"\n";
        std::wcout << L"  Formats:  " << Core::Utils::Join(formats, L", ") << L"\n";
        std::wcout << L"  Output:   " << output_dir << L"\n";
        if (stealth) {
            std::wcout << L"  [STEALTH] Low-footprint mode: no DLL snapshots, no memory module\n";
        }
        if (options.quick) {
            std::wcout << L"  [QUICK] Quick scan: essential checks only\n";
        }
        for (const auto& note : plan_notes) {
            std::wcout << L"  [i] " << note << L"\n";
        }
        for (const auto& warning : ConfigManager::Instance().GetWarnings()) {
            std::wcout << L"  [!] " << warning << L"\n";
        }
        std::wcout << L"\n";
    }

    log.Info(L"Starting scan...");
    Core::Utils::Timer timer;
    timer.Start();

    // --quick runs the essential checks only.
    const bool success = options.quick ? engine.RunQuickScan() : engine.RunFullScan();
    timer.Stop();

    if (!success) {
        log.Error(L"Scan failed");
        engine.Cleanup();
        return 1;
    }

    // Individual modules may fail (missing privileges, an API unavailable on
    // this host) without invalidating the rest of the scan. Surface those
    // rather than letting the run look clean; they are also in every report.
    if (engine.HasErrors() && !options.quiet) {
        std::wcout << L"\n[WARNING] Some checks did not complete:\n";
        for (const auto& err : engine.GetErrors()) {
            std::wcout << L"  * " << err << L"\n";
        }
        std::wcout << L"  Reports below cover the checks that did complete.\n";
    }

    log.Info(L"Scan completed in " + timer.GetElapsedString());

    if (!options.quiet) {
        std::wcout << L"\n[+] Scan completed in " << timer.GetElapsedString() << L"\n\n";
        std::wcout << L"[REPORTS] Generating reports...\n";
    }

    const String timestamp = Core::Utils::GetCurrentTimestamp();
    if (!Core::Utils::DirectoryExists(output_dir)) {
        log.Info(L"Creating output directory: " + output_dir);
        Core::Utils::CreateDirectory(output_dir);
    }

    int reports_generated = 0;
    int reports_failed = 0;

    for (const auto& format : formats) {
        const String file_path = output_dir + L"\\scan_" + timestamp + L"." + format;

        if (engine.ExportResults(format, file_path)) {
            reports_generated++;
            if (!options.quiet) {
                std::wcout << L"  [+] " << format << L" report: " << file_path << L"\n";
            }
            log.Info(L"Generated " + format + L" report: " + file_path);
        } else {
            reports_failed++;
            std::wcerr << L"  [-] Failed to generate " << format << L" report\n";
            log.Error(L"Failed to generate " + format + L" report");
        }
    }

    if (!options.quiet) {
        // Severity summary, so the operator sees what matters without opening a file.
        size_t counts[4] = {0, 0, 0, 0};
        for (const auto& r : engine.GetResults()) {
            counts[static_cast<int>(r.risk_level)]++;
        }
        std::wcout << L"\n[SUMMARY] " << engine.GetResults().size() << L" findings: "
                   << counts[3] << L" critical, " << counts[2] << L" high, "
                   << counts[1] << L" medium, " << counts[0] << L" low\n";

        if (reports_generated > 0) {
            std::wcout << L"[+] Successfully generated " << reports_generated << L" report(s)\n";
        }
        if (reports_failed > 0) {
            std::wcout << L"[!] Failed to generate " << reports_failed << L" report(s)\n";
        }
        std::wcout << L"\n[OUTPUT] Reports saved to: " << output_dir << L"\n";
        std::wcout << L"\nScan complete! Review the reports for detailed findings.\n";
    }

    engine.Cleanup();
    log.Info(L"SysRecon finished");
    log.CloseLogFile();

    return (reports_failed > 0) ? 1 : 0;
}

// Interactive menu mode
int InteractiveMode() {
    try {
        CommandLineOptions options;
        bool running = true;
        
        while (running) {
            ShowMainMenu();
            int choice = GetMenuChoice(0, 8);
            
            switch (choice) {
                case 1: { // Full scan
                    std::wcout << L"\n[*] Running full system scan...\n";
                    WaitForKey();
                    // Start from the persistent settings but force a genuine
                    // full scan: `options` is shared across menu actions, so a
                    // prior visit to the module-selection menu would otherwise
                    // silently turn "Full System Scan" into a selective one.
                    CommandLineOptions full = options;
                    full.selective_scan = false;
                    full.quick = false;
                    full.accounts_only = full.services_only = full.processes_only = false;
                    full.network_only = full.registry_only = full.memory_only = false;
                    int result = RunScan(full);
                    if (result == 0) {
                        std::wcout << L"\n[+] Scan completed successfully!\n";
                    } else {
                        std::wcout << L"\n[-] Scan failed! Check the logs for details.\n";
                    }
                    WaitForKey();
                    break;
                }
            
            case 2: { // Selective scan
                bool selecting = true;
                while (selecting) {
                    ShowModuleSelectionMenu(options);
                    int modChoice = GetMenuChoice(0, 8);
                    
                    switch (modChoice) {
                        case 1:
                            options.accounts_only = !options.accounts_only;
                            options.selective_scan = true;
                            break;
                        case 2:
                            options.services_only = !options.services_only;
                            options.selective_scan = true;
                            break;
                        case 3:
                            options.processes_only = !options.processes_only;
                            options.selective_scan = true;
                            break;
                        case 4:
                            options.network_only = !options.network_only;
                            options.selective_scan = true;
                            break;
                        case 5:
                            options.registry_only = !options.registry_only;
                            options.selective_scan = true;
                            break;
                        case 6:
                            options.memory_only = !options.memory_only;
                            options.selective_scan = true;
                            break;
                        case 7:
                            options.accounts_only = true;
                            options.services_only = true;
                            options.processes_only = true;
                            options.network_only = true;
                            options.registry_only = true;
                            options.memory_only = true;
                            options.selective_scan = true;
                            break;
                        case 8: {
                            // Check that a module is actually selected, not
                            // merely that the selection menu was visited:
                            // selective_scan is sticky, so toggling every
                            // module back off still passed this guard and ran
                            // a zero-module scan reported as a success.
                            const bool any_selected =
                                options.accounts_only || options.services_only ||
                                options.processes_only || options.network_only ||
                                options.registry_only || options.memory_only;

                            if (!any_selected) {
                                std::wcout << L"\n[!] Please select at least one module!\n";
                                WaitForKey();
                                break;
                            }

                            options.selective_scan = true;
                            std::wcout << L"\n[*] Starting selective scan...\n";
                            WaitForKey();
                            int result = RunScan(options);
                            if (result == 0) {
                                std::wcout << L"\n[+] Scan completed successfully!\n";
                            } else {
                                std::wcout << L"\n[-] Scan failed! Check the logs for details.\n";
                            }
                            WaitForKey();
                            selecting = false;
                            break;
                        }
                        case 0:
                            selecting = false;
                            break;
                    }
                }
                break;
            }
            
            case 3: { // Quick scan
                std::wcout << L"\n[QUICK] Running quick scan (skipping deep analysis)...\n";
                options.quick = true;
                WaitForKey();
                int result = RunScan(options);
                options.quick = false;
                if (result == 0) {
                    std::wcout << L"\n[+] Quick scan completed successfully!\n";
                } else {
                    std::wcout << L"\n[-] Quick scan failed! Check the logs for details.\n";
                }
                WaitForKey();
                break;
            }
            
            case 4: { // Stealth mode
                std::wcout << L"\n[STEALTH] Running stealth mode scan (minimal footprint)...\n";
                options.stealth = true;
                options.quiet = true;
                WaitForKey();
                int result = RunScan(options);
                options.stealth = false;
                options.quiet = false;
                if (result == 0) {
                    std::wcout << L"\n[+] Stealth scan completed successfully!\n";
                } else {
                    std::wcout << L"\n[-] Stealth scan failed! Check the logs for details.\n";
                }
                WaitForKey();
                break;
            }
            
            case 5: { // Configuration
                bool configuring = true;
                while (configuring) {
                    ShowConfigurationMenu(options);
                    int confChoice = GetMenuChoice(0, 5);
                    
                    switch (confChoice) {
                        case 1: {
                            String newDir = GetStringInput(L"Enter output directory", options.output_dir);
                            if (!newDir.empty()) {
                                options.output_dir = newDir;
                                std::wcout << L"[+] Output directory changed to: " << newDir << L"\n";
                            }
                            WaitForKey();
                            break;
                        }
                        case 2: {
                            ShowReportOptionsMenu(options);
                            int repChoice = GetMenuChoice(0, 4);
                            switch (repChoice) {
                                case 1:
                                    options.formats = {L"json"};
                                    std::wcout << L"[+] Report format set to JSON\n";
                                    break;
                                case 2:
                                    options.formats = {L"csv"};
                                    std::wcout << L"[+] Report format set to CSV\n";
                                    break;
                                case 3:
                                    options.formats = {L"html"};
                                    std::wcout << L"[+] Report format set to HTML\n";
                                    break;
                                case 4:
                                    options.formats = {L"json", L"csv", L"html"};
                                    std::wcout << L"[+] Report format set to ALL formats\n";
                                    break;
                            }
                            WaitForKey();
                            break;
                        }
                        case 3:
                            options.verbose = !options.verbose;
                            if (options.verbose) options.quiet = false;
                            std::wcout << L"[+] Verbose mode " << (options.verbose ? L"enabled" : L"disabled") << L"\n";
                            WaitForKey();
                            break;
                        case 4:
                            options.quiet = !options.quiet;
                            if (options.quiet) options.verbose = false;
                            std::wcout << L"[+] Quiet mode " << (options.quiet ? L"enabled" : L"disabled") << L"\n";
                            WaitForKey();
                            break;
                        case 5: {
                            String newConfig = GetStringInput(L"Enter config file path", options.config_file);
                            if (!newConfig.empty()) {
                                options.config_file = newConfig;
                                std::wcout << L"[+] Config file changed to: " << newConfig << L"\n";
                            }
                            WaitForKey();
                            break;
                        }
                        case 0:
                            configuring = false;
                            break;
                    }
                }
                break;
            }
            
            case 6: { // Report options
                ShowReportOptionsMenu(options);
                int repChoice = GetMenuChoice(0, 4);
                
                switch (repChoice) {
                    case 1:
                        options.formats = {L"json"};
                        std::wcout << L"\n[+] Report format set to JSON\n";
                        WaitForKey();
                        break;
                    case 2:
                        options.formats = {L"csv"};
                        std::wcout << L"\n[+] Report format set to CSV\n";
                        WaitForKey();
                        break;
                    case 3:
                        options.formats = {L"html"};
                        std::wcout << L"\n[+] Report format set to HTML\n";
                        WaitForKey();
                        break;
                    case 4:
                        options.formats = {L"json", L"csv", L"html"};
                        std::wcout << L"\n[+] Report format set to ALL formats\n";
                        WaitForKey();
                        break;
                }
                break;
            }
            
            case 7: { // About
                PrintVersion();
                WaitForKey();
                break;
            }
            
            case 8: { // Help
                PrintHelp();
                WaitForKey();
                break;
            }
            
            case 0: { // Exit
                std::wcout << L"\nThank you for using SysRecon! Goodbye.\n";
                running = false;
                break;
            }
        }
    }
    
    return 0;
    
    } catch (const std::exception& e) {
        std::wcerr << L"\n[ERROR] FATAL ERROR: " << e.what() << L"\n";
        std::wcerr << L"Press any key to exit...\n";
        WaitForKey();
        return 1;
    } catch (...) {
        std::wcerr << L"\n[ERROR] FATAL ERROR: Unknown exception occurred\n";
        std::wcerr << L"Press any key to exit...\n";
        WaitForKey();
        return 1;
    }
}

// Entry point. MinGW builds use -municode (CMakeLists.txt) so the CRT calls
// wmain with real wide arguments; MSVC does so natively. The previous
// `int main() { return wmain(__argc, __wargv); }` shim crashed on every
// real Windows run with arguments: without -municode the CRT never fills
// __wargv, so argv was NULL. Wine fills it regardless, which hid the bug.
int wmain(int argc, wchar_t* argv[]) {
    try {
        // Console attachment.
        //
        // Do NOT reopen the standard streams onto CONOUT$ when they are already
        // valid: if stdout is a file or a pipe (sysrecon.exe --scan > out.txt),
        // GetConsoleWindow() still returns NULL, and reopening would silently
        // redirect every byte of output to an invisible console -- leaving the
        // analyst with an empty file. Redirection must always win.
        if (GetConsoleWindow() == NULL && !StdHandleIsRedirected(STD_OUTPUT_HANDLE)) {
            // Prefer the parent's console (launched from an existing cmd.exe);
            // only allocate a fresh one if there is genuinely none to attach to.
            if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
                AllocConsole();
            }

            FILE* fp = nullptr;
            if (!StdHandleIsRedirected(STD_OUTPUT_HANDLE)) {
                freopen_s(&fp, "CONOUT$", "w", stdout);
            }
            if (!StdHandleIsRedirected(STD_ERROR_HANDLE)) {
                freopen_s(&fp, "CONOUT$", "w", stderr);
            }
            if (!StdHandleIsRedirected(STD_INPUT_HANDLE)) {
                freopen_s(&fp, "CONIN$", "r", stdin);
            }
        }
        
        // Initialize console for Unicode output
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        
        // Set console mode to support ANSI escape codes and Unicode
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD consoleMode;
        if (GetConsoleMode(hStdout, &consoleMode)) {
            consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hStdout, consoleMode);
        }
        
        // Set locale for proper wide character output
        setlocale(LC_ALL, ".UTF8");
        
        // Sync C++ streams with C streams
        std::ios::sync_with_stdio(true);
        
        // If no arguments provided, launch interactive menu
        if (argc == 1) {
            return InteractiveMode();
        }
        
        // Parse command-line arguments
        CommandLineOptions options;
        
        if (!ParseArguments(argc, argv, options)) {
            return 1;
        }
        
        // Handle help and version
        if (options.show_help) {
            PrintHelp();
            return 0;
        }
        
        if (options.show_version) {
            PrintVersion();
            return 0;
        }
        
        // Run scan with command-line options
        return RunScan(options);
        
    } catch (const std::exception& e) {
        std::wcerr << L"\n[ERROR] FATAL ERROR: " << e.what() << L"\n";
        std::wcerr << L"Press ENTER to exit...\n";
        std::wcin.get();
        return 1;
    } catch (...) {
        std::wcerr << L"\n[ERROR] FATAL ERROR: Unknown exception occurred\n";
        std::wcerr << L"Press ENTER to exit...\n";
        std::wcin.get();
        return 1;
    }
}
