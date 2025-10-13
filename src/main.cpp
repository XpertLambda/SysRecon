#include "../include/sysrecon.h"
#include "../include/core/engine.h"

using namespace SysRecon;
using namespace SysRecon::Core;

// Forward declaration
int wmain(int argc, wchar_t* argv[]);

// Standard main function for console applications
int main() {
    return wmain(__argc, __wargv);
}

int wmain(int argc, wchar_t* argv[]) {
    (void)argc; // Suppress unused parameter warning
    (void)argv; // Suppress unused parameter warning
    
    std::wcout << L"SysRecon - Windows Audit Tool 2025\n";
    std::wcout << L"Initializing logger...\n";
    
    // Setup basic logging
    Logger::Instance().SetConsoleOutput(true);
    Logger::Instance().SetLogLevel(LogLevel::Info);
    Logger::Instance().Info(L"SysRecon starting...");
    
    // Create engine
    ScanEngine& engine = ScanEngine::Instance();
    Logger::Instance().Info(L"Engine created");
    
    // Simple test run
    Logger::Instance().Info(L"Running basic scan...");
    bool success = engine.RunFullScan();
    
    if (success) {
        Logger::Instance().Info(L"Scan completed successfully!");
        return 0;
    } else {
        Logger::Instance().Error(L"Scan failed");
        return 1;
    }
}
