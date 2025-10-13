<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# SysRecon - Windows Audit Tool Development Instructions

This is a C++ Windows security auditing tool designed to run on Windows systems for reconnaissance, security assessment, and forensic analysis.

## Development Environment
- **Host Platform**: Arch Linux (development environment)
- **Target Platform**: Windows 10/11 (x64)
- **Language**: C++ with Windows API integration
- **Cross-compilation**: MinGW-w64 for Windows targets

## Architecture Guidelines
- Use modular design with plugin architecture
- Implement Windows API calls for system information gathering
- Focus on performance and minimal system footprint
- Support both CLI and optional GUI interfaces
- Ensure proper error handling and logging

## Key Components
1. **Core Engine**: Main scanning and coordination logic
2. **Data Collection Modules**: User accounts, services, processes, network
3. **Registry Analysis**: Persistence mechanisms, security policies
4. **Memory Analysis**: Process dumps, injection detection
5. **Reporting Engine**: JSON, CSV, HTML, PDF output
6. **Security Features**: Code signing, encryption, stealth mode

## Coding Standards
- Follow Windows API naming conventions
- Use RAII principles for resource management
- Implement proper Unicode support (UTF-16 for Windows APIs)
- Add comprehensive error checking for all Windows API calls
- Use modern C++ features (C++17/20) where appropriate
