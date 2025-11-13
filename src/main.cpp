#include "../include/sysrecon.h"
#include "../include/core/engine.h"
#include <map>
#include <algorithm>

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
    std::wcout << L"Windows Security Audit & Reconnaissance Tool v1.0\n";
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
    std::wcout << L"Version:      1.0.0\n";
    std::wcout << L"Build Date:   " << __DATE__ << L" " << __TIME__ << L"\n";
    std::wcout << L"Target:       Windows x64\n";
    std::wcout << L"Compiler:     MinGW-w64 (C++20)\n";
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

int wmain(int argc, wchar_t* argv[]);

int main() {
    return wmain(__argc, __wargv);
}

int wmain(int argc, wchar_t* argv[]) {
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
    
    // Print banner unless quiet
    if (!options.quiet) {
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
    
    // Display scan information
    if (!options.quiet) {
        std::wcout << L"🔍 Starting system scan...\n";
        
        if (options.selective_scan) {
            std::wcout << L"\n📋 Scanning selected modules:\n";
            if (options.accounts_only) std::wcout << L"  ✓ User Accounts & Groups\n";
            if (options.services_only) std::wcout << L"  ✓ Windows Services\n";
            if (options.processes_only) std::wcout << L"  ✓ Running Processes\n";
            if (options.network_only) std::wcout << L"  ✓ Network Connections\n";
            if (options.registry_only) std::wcout << L"  ✓ Registry Keys\n";
            if (options.memory_only) std::wcout << L"  ✓ Process Memory\n";
            std::wcout << L"\n";
        } else {
            std::wcout << L"  📦 Full system scan (all modules)\n\n";
        }
    }
    
    Logger::Instance().Info(L"Starting scan...");
    
    // Run the scan
    // TODO: Implement selective module scanning based on options
    bool success = engine.RunFullScan();
    
    if (!success) {
        Logger::Instance().Error(L"Scan failed");
        return 1;
    }
    
    Logger::Instance().Info(L"Scan completed successfully!");
    
    if (!options.quiet) {
        std::wcout << L"\n✅ Scan completed!\n\n";
    }
    
    // Generate reports
    Logger::Instance().Info(L"Generating reports...");
    
    if (!options.quiet) {
        std::wcout << L"📄 Generating reports...\n";
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
                std::wcout << L"  ✓ " << format << L" report: " << file_path << L"\n";
            }
            Logger::Instance().Info(L"Generated " + format + L" report: " + file_path);
        } else {
            reports_failed++;
            std::wcerr << L"  ✗ Failed to generate " << format << L" report\n";
            Logger::Instance().Error(L"Failed to generate " + format + L" report");
        }
    }
    
    if (!options.quiet) {
        std::wcout << L"\n";
        if (reports_generated > 0) {
            std::wcout << L"✅ Successfully generated " << reports_generated << L" report(s)\n";
        }
        if (reports_failed > 0) {
            std::wcout << L"⚠️  Failed to generate " << reports_failed << L" report(s)\n";
        }
        
        std::wcout << L"\n📁 Reports saved to: " << options.output_dir << L"\n";
        std::wcout << L"\nScan complete! Review the reports for detailed findings.\n\n";
    }
    
    // Cleanup
    engine.Cleanup();
    
    Logger::Instance().Info(L"SysRecon finished");
    
    return (reports_failed > 0) ? 1 : 0;
}
