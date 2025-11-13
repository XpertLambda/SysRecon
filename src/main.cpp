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
    
    std::wcout << L"SysRecon - Windows Audit Tool 2025\n";
    std::wcout << L"=========================================\n\n";
    
    // Initialize logger
    Logger::Instance().SetConsoleOutput(true);
    Logger::Instance().SetLogLevel(LogLevel::Info);
    Logger::Instance().Info(L"SysRecon starting...");
    
    // Create scan engine
    ScanEngine& engine = ScanEngine::Instance();
    
    // Initialize engine
    if (!engine.Initialize()) {
        Logger::Instance().Error(L"Failed to initialize scan engine");
        return 1;
    }
    
    Logger::Instance().Info(L"Starting full system scan...");
    std::wcout << L"\n🔍 Scanning system for security issues...\n\n";
    
    // Run the scan
    bool success = engine.RunFullScan();
    
    if (!success) {
        Logger::Instance().Error(L"Scan failed");
        return 1;
    }
    
    Logger::Instance().Info(L"Scan completed successfully!");
    std::wcout << L"\n✓ Scan completed!\n\n";
    
    // Generate reports
    Logger::Instance().Info(L"Generating reports...");
    std::wcout << L"📄 Generating reports...\n";
    
    String timestamp = Core::Utils::GetCurrentTimestamp();
    String output_dir = L"./reports";
    
    // Create output directory
    if (!Core::Utils::DirectoryExists(output_dir)) {
        Core::Utils::CreateDirectory(output_dir);
    }
    
    // Generate JSON report
    String json_file = output_dir + L"/scan_" + timestamp + L".json";
    if (engine.ExportResults(L"json", json_file)) {
        std::wcout << L"  ✓ JSON report: " << json_file << L"\n";
    } else {
        std::wcout << L"  ✗ Failed to generate JSON report\n";
    }
    
    // Generate CSV report
    String csv_file = output_dir + L"/scan_" + timestamp + L".csv";
    if (engine.ExportResults(L"csv", csv_file)) {
        std::wcout << L"  ✓ CSV report: " << csv_file << L"\n";
    } else {
        std::wcout << L"  ✗ Failed to generate CSV report\n";
    }
    
    // Generate HTML report
    String html_file = output_dir + L"/scan_" + timestamp + L".html";
    if (engine.ExportResults(L"html", html_file)) {
        std::wcout << L"  ✓ HTML report: " << html_file << L"\n";
    } else {
        std::wcout << L"  ✗ Failed to generate HTML report\n";
    }
    
    std::wcout << L"\n✅ All reports generated successfully!\n";
    std::wcout << L"\nScan complete. Check the reports directory for detailed results.\n";
    
    // Cleanup
    engine.Cleanup();
    
    return 0;
}
