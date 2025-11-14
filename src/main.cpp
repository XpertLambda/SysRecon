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
    String config_file = L"config.json";
    String output_dir = L"./reports";
    StringVector formats = {L"json", L"csv", L"html"};
    
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
    std::wcout << L"Windows Security Audit & Reconnaissance Tool v1.1.0\n";
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
    std::wcout << L"  --stealth               Run in stealth mode (minimal footprint)\n";
    std::wcout << L"  --quick                 Quick scan mode (skip deep analysis)\n";
    std::wcout << L"\n";
    
    std::wcout << L"CONFIGURATION:\n";
    std::wcout << L"  -c, --config FILE       Load configuration from FILE (default: config.json)\n";
    std::wcout << L"  -o, --output DIR        Set output directory (default: ./reports)\n";
    std::wcout << L"  -f, --format FORMAT     Report format: json, csv, html, all (default: all)\n";
    std::wcout << L"                          Can specify multiple: -f json -f csv\n";
    std::wcout << L"\n";
    
    std::wcout << L"MODULE SELECTION (scan specific modules only):\n";
    std::wcout << L"  --accounts              Scan user accounts and groups\n";
    std::wcout << L"  --services              Scan Windows services\n";
    std::wcout << L"  --processes             Scan running processes\n";
    std::wcout << L"  --network               Scan network connections and ports\n";
    std::wcout << L"  --registry              Scan registry for persistence\n";
    std::wcout << L"  --memory                Scan process memory (slow)\n";
    std::wcout << L"\n";
    
    std::wcout << L"EXAMPLES:\n";
    std::wcout << L"  sysrecon.exe                          # Full scan with default settings\n";
    std::wcout << L"  sysrecon.exe --quick --verbose        # Quick verbose scan\n";
    std::wcout << L"  sysrecon.exe --accounts --services    # Scan only accounts and services\n";
    std::wcout << L"  sysrecon.exe -f json -o ./output      # JSON report to ./output\n";
    std::wcout << L"  sysrecon.exe --stealth --quiet        # Stealthy silent scan\n";
    std::wcout << L"\n";
}

void PrintVersion() {
    PrintBanner();
    std::wcout << L"Version:      1.1.0\n";
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

// Interactive menu functions
void ClearScreen() {
    system("cls");
}

void WaitForKey() {
    std::wcout << L"\nPress any key to continue...";
    std::wcout.flush();
    
    // Use Windows API instead of _getch()
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
    
    INPUT_RECORD inputRecord;
    DWORD events;
    
    // Wait for a key press
    while (true) {
        ReadConsoleInput(hStdin, &inputRecord, 1, &events);
        if (inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown) {
            break;
        }
    }
    
    // Restore console mode
    SetConsoleMode(hStdin, mode);
    std::wcout << L"\n";
}

int GetMenuChoice(int min, int max) {
    int choice;
    while (true) {
        std::wcout << L"\nEnter choice (" << min << L"-" << max << L"): ";
        std::wcin >> choice;
        
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
    std::wcout << L"  1. Run Full System Scan (All Modules)\n";
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
    std::wcout << L"  7. Select All Modules\n";
    std::wcout << L"  8. Start Scan with Selected Modules\n";
    std::wcout << L"  0. Back to Main Menu\n";
    std::wcout << L"\n";
    std::wcout << L"══════════════════════════════════════════════════════════════════════\n";
    std::wcout << L"Selected: ";
    
    if (!options.selective_scan) {
        std::wcout << L"None (will scan all)";
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
    std::wcout << L"  Config File:    " << options.config_file << L"\n";
    std::wcout << L"  Output Dir:     " << options.output_dir << L"\n";
    std::wcout << L"  Report Formats: ";
    for (size_t i = 0; i < options.formats.size(); i++) {
        if (i > 0) std::wcout << L", ";
        std::wcout << options.formats[i];
    }
    std::wcout << L"\n";
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
    std::wcout << L"Current Formats: ";
    for (size_t i = 0; i < options.formats.size(); i++) {
        if (i > 0) std::wcout << L", ";
        std::wcout << options.formats[i];
    }
    std::wcout << L"\n";
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
                    if (options.formats.size() == 3) {
                        options.formats.clear();
                    }
                    options.formats.push_back(format);
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
        
        // Unknown option
        std::wcerr << L"Error: Unknown option '" << arg << L"'\n";
        std::wcerr << L"Use --help for usage information\n";
        return false;
    }
    
    return true;
}

// Function to run the actual scan
int RunScan(CommandLineOptions& options) {
    // Print banner unless quiet
    if (!options.quiet) {
        ClearScreen();
        PrintBanner();
    }
    
    // Initialize logger
    Logger::Instance().SetConsoleOutput(true);
    
    if (options.verbose) {
        Logger::Instance().SetLogLevel(LogLevel::Debug);
    } else if (options.quiet) {
        Logger::Instance().SetLogLevel(LogLevel::Error);
    } else {
        Logger::Instance().SetLogLevel(LogLevel::Info);
    }
    
    Logger::Instance().Info(L"SysRecon starting...");
    
    if (options.verbose) {
        Logger::Instance().Debug(L"Configuration file: " + options.config_file);
        Logger::Instance().Debug(L"Output directory: " + options.output_dir);
        Logger::Instance().Debug(L"Stealth mode: " + String(options.stealth ? L"enabled" : L"disabled"));
        Logger::Instance().Debug(L"Quick scan: " + String(options.quick ? L"enabled" : L"disabled"));
    }
    
    // Create scan engine
    ScanEngine& engine = ScanEngine::Instance();
    
    // Load configuration if file exists
    if (Core::Utils::FileExists(options.config_file)) {
        Logger::Instance().Info(L"Loading configuration from: " + options.config_file);
        // TODO: Load config into engine
    } else if (options.config_file != L"config.json") {
        Logger::Instance().Warning(L"Configuration file not found: " + options.config_file);
    }
    
    // Initialize engine
    if (!engine.Initialize()) {
        Logger::Instance().Error(L"Failed to initialize scan engine");
        return 1;
    }
    
    // Configure selective module scanning
    if (options.selective_scan) {
        // Disable all modules first
        engine.DisableModule(ModuleType::Accounts);
        engine.DisableModule(ModuleType::Services);
        engine.DisableModule(ModuleType::Processes);
        engine.DisableModule(ModuleType::Network);
        engine.DisableModule(ModuleType::Registry);
        engine.DisableModule(ModuleType::Memory);
        
        // Enable only selected modules
        if (options.accounts_only) {
            engine.EnableModule(ModuleType::Accounts);
            Logger::Instance().Debug(L"Enabled Accounts module");
        }
        if (options.services_only) {
            engine.EnableModule(ModuleType::Services);
            Logger::Instance().Debug(L"Enabled Services module");
        }
        if (options.processes_only) {
            engine.EnableModule(ModuleType::Processes);
            Logger::Instance().Debug(L"Enabled Processes module");
        }
        if (options.network_only) {
            engine.EnableModule(ModuleType::Network);
            Logger::Instance().Debug(L"Enabled Network module");
        }
        if (options.registry_only) {
            engine.EnableModule(ModuleType::Registry);
            Logger::Instance().Debug(L"Enabled Registry module");
        }
        if (options.memory_only) {
            engine.EnableModule(ModuleType::Memory);
            Logger::Instance().Debug(L"Enabled Memory module");
        }
    } else {
        // Full scan - ensure all modules are enabled
        engine.EnableModule(ModuleType::Accounts);
        engine.EnableModule(ModuleType::Services);
        engine.EnableModule(ModuleType::Processes);
        engine.EnableModule(ModuleType::Network);
        engine.EnableModule(ModuleType::Registry);
        engine.EnableModule(ModuleType::Memory);
    }
    
    // Display scan information
    if (!options.quiet) {
        std::wcout << L"[*] Starting system scan...\n";
        
        if (options.stealth) {
            std::wcout << L"  [STEALTH] Stealth Mode: Enabled\n";
        }
        
        if (options.quick) {
            std::wcout << L"  [QUICK] Quick Scan: Enabled\n";
        }
        
        if (options.selective_scan) {
            std::wcout << L"\n[MODULES] Scanning selected modules:\n";
            if (options.accounts_only) std::wcout << L"  * User Accounts & Groups\n";
            if (options.services_only) std::wcout << L"  * Windows Services\n";
            if (options.processes_only) std::wcout << L"  * Running Processes\n";
            if (options.network_only) std::wcout << L"  * Network Connections\n";
            if (options.registry_only) std::wcout << L"  * Registry Keys\n";
            if (options.memory_only) std::wcout << L"  * Process Memory\n";
            std::wcout << L"\n";
        } else {
            std::wcout << L"  [FULL] Full system scan (all modules)\n\n";
        }
    }
    
    Logger::Instance().Info(L"Starting scan...");
    
    // Run the scan
    bool success = engine.RunFullScan();
    
    if (!success) {
        Logger::Instance().Error(L"Scan failed");
        return 1;
    }
    
    Logger::Instance().Info(L"Scan completed successfully!");
    
    if (!options.quiet) {
        std::wcout << L"\n[+] Scan completed!\n\n";
    }
    
    // Generate reports
    Logger::Instance().Info(L"Generating reports...");
    
    if (!options.quiet) {
        std::wcout << L"[REPORTS] Generating reports...\n";
    }
    
    String timestamp = Core::Utils::GetCurrentTimestamp();
    
    // Create output directory
    if (!Core::Utils::DirectoryExists(options.output_dir)) {
        Logger::Instance().Info(L"Creating output directory: " + options.output_dir);
        Core::Utils::CreateDirectory(options.output_dir);
    }
    
    // Generate reports in requested formats
    int reports_generated = 0;
    int reports_failed = 0;
    
    for (const auto& format : options.formats) {
        String extension = format;
        String file_path = options.output_dir + L"/scan_" + timestamp + L"." + extension;
        
        if (engine.ExportResults(format, file_path)) {
            reports_generated++;
            if (!options.quiet) {
                std::wcout << L"  [+] " << format << L" report: " << file_path << L"\n";
            }
            Logger::Instance().Info(L"Generated " + format + L" report: " + file_path);
        } else {
            reports_failed++;
            std::wcerr << L"  [-] Failed to generate " << format << L" report\n";
            Logger::Instance().Error(L"Failed to generate " + format + L" report");
        }
    }
    
    if (!options.quiet) {
        std::wcout << L"\n";
        if (reports_generated > 0) {
            std::wcout << L"[+] Successfully generated " << reports_generated << L" report(s)\n";
        }
        if (reports_failed > 0) {
            std::wcout << L"[!] Failed to generate " << reports_failed << L" report(s)\n";
        }
        
        std::wcout << L"\n[OUTPUT] Reports saved to: " << options.output_dir << L"\n";
        std::wcout << L"\nScan complete! Review the reports for detailed findings.\n";
    }
    
    // Cleanup
    engine.Cleanup();
    
    Logger::Instance().Info(L"SysRecon finished");
    
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
                    int result = RunScan(options);
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
                        case 8:
                            if (options.selective_scan) {
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
                            } else {
                                std::wcout << L"\n[!] Please select at least one module!\n";
                                WaitForKey();
                            }
                            break;
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

int wmain(int argc, wchar_t* argv[]);

int main() {
    return wmain(__argc, __wargv);
}

int wmain(int argc, wchar_t* argv[]) {
    try {
        // Check if we already have a console attached
        HWND consoleWindow = GetConsoleWindow();
        
        // Only allocate a new console if we don't have one
        if (consoleWindow == NULL) {
            if (!AllocConsole()) {
                // If AllocConsole fails, we might already have one
                // This is not a critical error, continue
            }
            
            // Reopen standard streams only if we just created a console
            FILE* fpStdout = nullptr;
            FILE* fpStderr = nullptr;
            FILE* fpStdin = nullptr;
            
            freopen_s(&fpStdout, "CONOUT$", "w", stdout);
            freopen_s(&fpStderr, "CONOUT$", "w", stderr);
            freopen_s(&fpStdin, "CONIN$", "r", stdin);
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
