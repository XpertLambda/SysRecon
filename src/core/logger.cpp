#include "../../include/core/logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <fstream>
#include <map>

namespace SysRecon {
namespace Core {

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void Logger::SetLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    min_log_level_ = level;
}

void Logger::SetLogFile(const String& filename) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_filename_ = filename;
    
    if (log_file_.is_open()) {
        log_file_.close();
    }
    
    std::string narrowFilename;
    for (wchar_t c : filename) {
        narrowFilename += static_cast<char>(c);
    }
    
    log_file_.open(narrowFilename, std::ios::app);
    file_output_ = log_file_.is_open();
}

void Logger::SetConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    console_output_ = enable;
}

void Logger::SetTimestampFormat(const String& format) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    timestamp_format_ = format;
}

void Logger::Debug(const String& message) {
    Log(LogLevel::Debug, message);
}

void Logger::Info(const String& message) {
    Log(LogLevel::Info, message);
}

void Logger::Warning(const String& message) {
    Log(LogLevel::Warning, message);
}

void Logger::Error(const String& message) {
    Log(LogLevel::Error, message);
}

void Logger::Critical(const String& message) {
    Log(LogLevel::Critical, message);
}

void Logger::Log(LogLevel level, const String& message) {
    if (!IsEnabled(level)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    WriteLog(level, message);
    log_counts_[level]++;
}

void Logger::LogWithContext(LogLevel level, const String& module, const String& function, const String& message) {
    String contextualMessage = L"[" + module + L"::" + function + L"] " + message;
    Log(level, contextualMessage);
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (console_output_) {
        std::wcout.flush();
    }
    if (file_output_ && log_file_.is_open()) {
        log_file_.flush();
    }
}

void Logger::Rotate() {
    // Simple rotation - close and reopen file
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
        
        std::string narrowFilename;
        for (wchar_t c : log_filename_) {
            narrowFilename += static_cast<char>(c);
        }
        
        log_file_.open(narrowFilename, std::ios::app);
    }
}

bool Logger::IsEnabled(LogLevel level) const {
    return level >= min_log_level_;
}

size_t Logger::GetLogCount(LogLevel level) const {
    // Note: We can't use mutex in const method, so we'll make a simple unsafe read
    auto it = log_counts_.find(level);
    return (it != log_counts_.end()) ? it->second : 0;
}

void Logger::ResetCounters() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_counts_.clear();
}

void Logger::WriteLog(LogLevel level, const String& message) {
    String formattedMessage = FormatMessage(level, message);
    
    if (console_output_) {
        std::wcout << formattedMessage << std::endl;
    }
    
    if (file_output_ && log_file_.is_open()) {
        // Convert wide string to narrow for file output
        std::string narrowMessage;
        for (wchar_t c : formattedMessage) {
            narrowMessage += static_cast<char>(c);
        }
        log_file_ << narrowMessage << std::endl;
    }
}

String Logger::FormatMessage(LogLevel level, const String& message) {
    std::wstringstream ss;
    ss << L"[" << GetTimestamp() << L"] ";
    ss << L"[" << LogLevelToString(level) << L"] ";
    ss << message;
    return ss.str();
}

String Logger::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::wstringstream ss;
    ss << std::put_time(std::localtime(&time_t), L"%Y-%m-%d %H:%M:%S");
    return ss.str();
}

String Logger::LogLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Debug:    return L"DEBUG";
        case LogLevel::Info:     return L"INFO";
        case LogLevel::Warning:  return L"WARN";
        case LogLevel::Error:    return L"ERROR";
        case LogLevel::Critical: return L"CRITICAL";
        default:                 return L"UNKNOWN";
    }
}

} // namespace Core
} // namespace SysRecon