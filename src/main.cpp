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
    std::wcout << L"Initializing logger...\n";
    
    Logger::Instance().SetConsoleOutput(true);
    Logger::Instance().SetLogLevel(LogLevel::Info);
    Logger::Instance().Info(L"SysRecon starting...");
    
    ScanEngine& engine = ScanEngine::Instance();
    Logger::Instance().Info(L"Engine created");
    
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
