#pragma once

#include "../sysrecon.h"

namespace SysRecon {
namespace Core {

enum class LogLevel {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4
};

class Logger {
public:
    static Logger& Instance();
    
    // Configuration
    void SetLogLevel(LogLevel level);
    void SetLogFile(const String& filename);
    void SetConsoleOutput(bool enable);
    void SetTimestampFormat(const String& format);
    
    // Logging methods
    void Debug(const String& message);
    void Info(const String& message);
    void Warning(const String& message);
    void Error(const String& message);
    void Critical(const String& message);
    
    void Log(LogLevel level, const String& message);
    void LogWithContext(LogLevel level, const String& module, const String& function, const String& message);
    
    // Utility methods
    void Flush();
    void Rotate();
    bool IsEnabled(LogLevel level) const;
    
    // Statistics
    size_t GetLogCount(LogLevel level) const;
    void ResetCounters();
    
private:
    Logger() = default;
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    void WriteLog(LogLevel level, const String& message);
    String FormatMessage(LogLevel level, const String& message);
    String GetTimestamp();
    String LogLevelToString(LogLevel level);
    
    LogLevel min_log_level_ = LogLevel::Info;
    String log_filename_;
    String timestamp_format_ = L"%Y-%m-%d %H:%M:%S";
    bool console_output_ = true;
    bool file_output_ = false;
    
    std::ofstream log_file_;
    std::mutex log_mutex_;
    
    // Statistics
    std::map<LogLevel, size_t> log_counts_;
};

} // namespace Core
} // namespace SysRecon

// Convenience macros
#define SYSRECON_LOG_DEBUG_CTX(module, func, msg) \
    SysRecon::Core::Logger::Instance().LogWithContext(SysRecon::Core::LogLevel::Debug, module, func, msg)

#define SYSRECON_LOG_INFO_CTX(module, func, msg) \
    SysRecon::Core::Logger::Instance().LogWithContext(SysRecon::Core::LogLevel::Info, module, func, msg)

#define SYSRECON_LOG_WARNING_CTX(module, func, msg) \
    SysRecon::Core::Logger::Instance().LogWithContext(SysRecon::Core::LogLevel::Warning, module, func, msg)

#define SYSRECON_LOG_ERROR_CTX(module, func, msg) \
    SysRecon::Core::Logger::Instance().LogWithContext(SysRecon::Core::LogLevel::Error, module, func, msg)
