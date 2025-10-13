#include <gtest/gtest.h>
#include "../include/core/utils.h"
#include "../include/core/logger.h"

using namespace SysRecon::Core;

class UtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup test environment
    }

    void TearDown() override {
        // Cleanup test environment
    }
};

// Test string utilities
TEST_F(UtilsTest, StringConversion) {
    std::string utf8_str = "Hello World";
    SysRecon::String wide_str = Utils::Utf8ToWide(utf8_str);
    std::string converted_back = Utils::WideToUtf8(wide_str);
    
    EXPECT_EQ(utf8_str, converted_back);
}

TEST_F(UtilsTest, StringManipulation) {
    SysRecon::String test_str = L"  Hello World  ";
    SysRecon::String trimmed = Utils::Trim(test_str);
    
    EXPECT_EQ(trimmed, L"Hello World");
    
    SysRecon::String lower = Utils::ToLower(L"HELLO");
    EXPECT_EQ(lower, L"hello");
    
    SysRecon::String upper = Utils::ToUpper(L"world");
    EXPECT_EQ(upper, L"WORLD");
}

TEST_F(UtilsTest, StringSplitJoin) {
    SysRecon::String input = L"one,two,three";
    auto parts = Utils::Split(input, L",");
    
    EXPECT_EQ(parts.size(), 3);
    EXPECT_EQ(parts[0], L"one");
    EXPECT_EQ(parts[1], L"two");
    EXPECT_EQ(parts[2], L"three");
    
    SysRecon::String rejoined = Utils::Join(parts, L"-");
    EXPECT_EQ(rejoined, L"one-two-three");
}

TEST_F(UtilsTest, StringPatterns) {
    SysRecon::String text = L"Hello World";
    
    EXPECT_TRUE(Utils::StartsWith(text, L"Hello"));
    EXPECT_FALSE(Utils::StartsWith(text, L"World"));
    
    EXPECT_TRUE(Utils::EndsWith(text, L"World"));
    EXPECT_FALSE(Utils::EndsWith(text, L"Hello"));
}

// Test timer functionality
TEST_F(UtilsTest, Timer) {
    Utils::Timer timer;
    
    timer.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    timer.Stop();
    
    double elapsed = timer.GetElapsedMilliseconds();
    EXPECT_GE(elapsed, 90.0);  // Allow some tolerance
    EXPECT_LE(elapsed, 200.0);
}

// Test logger functionality
class LoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        Logger::Instance().SetConsoleOutput(false);
        Logger::Instance().ResetCounters();
    }
};

TEST_F(LoggerTest, LogLevels) {
    Logger& logger = Logger::Instance();
    
    logger.SetLogLevel(LogLevel::Warning);
    
    // These should be logged
    logger.Warning(L"Warning message");
    logger.Error(L"Error message");
    logger.Critical(L"Critical message");
    
    // These should be filtered out
    logger.Debug(L"Debug message");
    logger.Info(L"Info message");
    
    EXPECT_EQ(logger.GetLogCount(LogLevel::Warning), 1);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Error), 1);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Critical), 1);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Debug), 0);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Info), 0);
}

TEST_F(LoggerTest, LogWithContext) {
    Logger& logger = Logger::Instance();
    logger.SetLogLevel(LogLevel::Debug);
    
    logger.LogWithContext(LogLevel::Info, L"TestModule", L"TestFunction", L"Test message");
    
    EXPECT_EQ(logger.GetLogCount(LogLevel::Info), 1);
}

// Main test runner
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
