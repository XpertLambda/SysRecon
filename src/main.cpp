#include "../include/sysrecon.h"
#include "../include/core/engine.h"

using namespace SysRecon;
using namespace SysRecon::Core;

int wmain(int argc, wchar_t* argv[]);

int main() {
    return wmain(__argc, __wargv);
}

int wmain(int argc, wchar_t* argv[]) {
    (void)argc;
    (void)argv;
    
    std::wcout << L"\n";
    std::wcout << L"╔═══════════════════════════════════════════════════════════════╗\n";
    std::wcout << L"║         SysRecon - Windows Audit Tool 2025                    ║\n";
    std::wcout << L"║         Professional Security Assessment Platform             ║\n";
    std::wcout << L"╚═══════════════════════════════════════════════════════════════╝\n";
    std::wcout << L"\n";
    
    // Initialize logging
    Logger::Instance().SetConsoleOutput(true);
    Logger::Instance().SetLogLevel(LogLevel::Info);
    Logger::Instance().Info(L"SysRecon v1.0.0 starting...");
    Logger::Instance().Info(L"System: " + Core::Utils::GetComputerName());
    Logger::Instance().Info(L"OS: " + Core::Utils::GetWindowsVersion());
    Logger::Instance().Info(L"User: " + Core::Utils::GetCurrentUserName());
    
    // Check privileges
    if (Core::Utils::IsRunningAsAdmin()) {
        Logger::Instance().Info(L"Running with Administrator privileges");
    } else {
        Logger::Instance().Warning(L"NOT running as Administrator - some features may be limited");
    }
    
    std::wcout << L"\n";
    
    // Initialize scan engine
    ScanEngine& engine = ScanEngine::Instance();
    
    if (!engine.Initialize()) {
        Logger::Instance().Error(L"Failed to initialize scan engine");
        return 1;
    }
    
    Logger::Instance().Info(L"Scan engine initialized successfully");
    std::wcout << L"\n";
    
    // Run full scan
    Logger::Instance().Info(L"═══════════════════════════════════════════");
    Logger::Instance().Info(L"  Starting comprehensive system scan...   ");
    Logger::Instance().Info(L"═══════════════════════════════════════════");
    std::wcout << L"\n";
    
    bool success = engine.RunFullScan();
    
    std::wcout << L"\n";
    
    if (!success) {
        Logger::Instance().Error(L"Scan completed with errors");
    }
    
    // Create output directory
    String output_dir = L"./reports";
    if (!Core::Utils::DirectoryExists(output_dir)) {
        Core::Utils::CreateDirectory(output_dir);
    }
    
    // Generate timestamp for filename
    String timestamp = Core::Utils::GetCurrentTimestamp();
    String base_filename = output_dir + L"/sysrecon_report_" + timestamp;
    
    // Export results in all formats
    Logger::Instance().Info(L"═══════════════════════════════════════════");
    Logger::Instance().Info(L"  Generating security reports...          ");
    Logger::Instance().Info(L"═══════════════════════════════════════════");
    std::wcout << L"\n";
    
    bool json_success = engine.ExportResults(L"json", base_filename + L".json");
    bool csv_success = engine.ExportResults(L"csv", base_filename + L".csv");
    bool html_success = engine.ExportResults(L"html", base_filename + L".html");
    
    std::wcout << L"\n";
    Logger::Instance().Info(L"═══════════════════════════════════════════");
    Logger::Instance().Info(L"  Scan Complete!                          ");
    Logger::Instance().Info(L"═══════════════════════════════════════════");
    
    if (json_success) {
        Logger::Instance().Info(L"✓ JSON report: " + base_filename + L".json");
    }
    if (csv_success) {
        Logger::Instance().Info(L"✓ CSV report: " + base_filename + L".csv");
    }
    if (html_success) {
        Logger::Instance().Info(L"✓ HTML report: " + base_filename + L".html");
    }
    
    std::wcout << L"\n";
    Logger::Instance().Info(L"Total findings: " + std::to_wstring(engine.GetResults().size()));
    
    if (engine.HasErrors()) {
        Logger::Instance().Warning(L"Scan completed with " + std::to_wstring(engine.GetErrors().size()) + L" errors");
    }
    
    // Cleanup
    engine.Cleanup();
    
    std::wcout << L"\n";
    std::wcout << L"Press Enter to exit...";
    std::wcin.get();
    
    return success ? 0 : 1;
}
