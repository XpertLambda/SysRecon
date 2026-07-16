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
    
    // Open by wide path: truncating each wchar_t to char mangled any
    // non-ASCII path component.
    log_file_.open(std::filesystem::path(filename), std::ios::app);
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
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
        
        log_file_.open(std::filesystem::path(log_filename_), std::ios::app);
    }
}

bool Logger::IsEnabled(LogLevel level) const {
    return level >= min_log_level_;
}

size_t Logger::GetLogCount(LogLevel level) const {
    // log_counts_ is written by Log() under this mutex; reading it unlocked
    // was a data race.
    std::lock_guard<std::mutex> lock(log_mutex_);
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
        // static_cast<char> per character silently mangled every non-ASCII
        // registry path, username and service name written to the log.
        log_file_ << Utils::WideToUtf8(formattedMessage) << std::endl;
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
    
    std::tm tm_buf{};
    // std::localtime returns a pointer to a shared static tm.
    localtime_s(&tm_buf, &time_t);

    std::wstringstream ss;
    ss << std::put_time(&tm_buf, L"%Y-%m-%d %H:%M:%S");
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

}
}