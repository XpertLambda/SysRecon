#include <gtest/gtest.h>
#include "../include/core/utils.h"
#include "../include/core/logger.h"
#include <cstdio>
#include <thread>

using namespace SysRecon::Core;

class UtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
    }
};

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
    
    EXPECT_EQ(parts.size(), 3u);
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

TEST_F(UtilsTest, Timer) {
    Utils::Timer timer;
    
    timer.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    timer.Stop();
    
    double elapsed = timer.GetElapsedMilliseconds();
    EXPECT_GE(elapsed, 90.0);
    // Generous upper bound: shared CI runners can deschedule a sleeping
    // thread for a long time; this only guards against a broken clock.
    EXPECT_LE(elapsed, 5000.0);
}

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
    
    logger.Warning(L"Warning message");
    logger.Error(L"Error message");
    logger.Critical(L"Critical message");
    
    logger.Debug(L"Debug message");
    logger.Info(L"Info message");
    
    EXPECT_EQ(logger.GetLogCount(LogLevel::Warning), 1u);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Error), 1u);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Critical), 1u);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Debug), 0u);
    EXPECT_EQ(logger.GetLogCount(LogLevel::Info), 0u);
}

TEST_F(LoggerTest, LogWithContext) {
    Logger& logger = Logger::Instance();
    logger.SetLogLevel(LogLevel::Debug);
    
    logger.LogWithContext(LogLevel::Info, L"TestModule", L"TestFunction", L"Test message");
    
    EXPECT_EQ(logger.GetLogCount(LogLevel::Info), 1u);
}


// --- UTF-8 codec -----------------------------------------------------------
// Previously the non-Windows conversion copied bytes one-to-one, and the
// Windows one relied on MultiByteToWideChar. Both directions now share one
// portable implementation, tested here.

TEST(Utf8, RoundTripsNonAsciiText) {
    const std::string utf8 = "Benutzer M\xC3\xBCller \xE2\x82\xAC \xF0\x9F\x94\x92";  // ü € 🔒
    const SysRecon::String wide = Utils::Utf8ToWide(utf8);
    EXPECT_EQ(Utils::WideToUtf8(wide), utf8);
}

TEST(Utf8, DecodesCodePointsCorrectly) {
    const SysRecon::String wide = Utils::Utf8ToWide("\xC3\xBC\xE2\x82\xAC");
    ASSERT_EQ(wide.size(), 2u);
    EXPECT_EQ(static_cast<uint32_t>(wide[0]), 0xFCu);
    EXPECT_EQ(static_cast<uint32_t>(wide[1]), 0x20ACu);
}

TEST(Utf8, ReplacesInvalidSequencesInsteadOfTruncating) {
    // Stray continuation byte, truncated sequence, overlong '/' and an
    // encoded surrogate must each become U+FFFD; surrounding text survives.
    EXPECT_EQ(Utils::Utf8ToWide("a\x80" "b"), SysRecon::String(L"a\uFFFDb"));
    EXPECT_EQ(Utils::Utf8ToWide("a\xE2\x82"), SysRecon::String(L"a\uFFFD\uFFFD"));
    EXPECT_EQ(Utils::Utf8ToWide("\xC0\xAF"), SysRecon::String(L"\uFFFD\uFFFD"));
    EXPECT_EQ(Utils::Utf8ToWide("\xED\xA0\x80").substr(0, 1), SysRecon::String(L"\uFFFD"));
}

TEST(Utf8, PreservesEmbeddedNul) {
    const std::string with_nul("a\0b", 3);
    EXPECT_EQ(Utils::Utf8ToWide(with_nul).size(), 3u);
    EXPECT_EQ(Utils::WideToUtf8(SysRecon::String(L"a\0b", 3)).size(), 3u);
}

TEST(Utf8, EmptyStrings) {
    EXPECT_EQ(Utils::Utf8ToWide(""), SysRecon::String());
    EXPECT_EQ(Utils::WideToUtf8(L""), std::string());
}

// --- Misc utils -------------------------------------------------------------

TEST_F(UtilsTest, SplitWithEmptyDelimiterDoesNotHang) {
    auto parts = Utils::Split(L"abc", L"");
    ASSERT_EQ(parts.size(), 1u);
    EXPECT_EQ(parts[0], L"abc");
}

TEST_F(UtilsTest, ReplaceAllWithEmptyNeedleIsNoOp) {
    EXPECT_EQ(Utils::ReplaceAll(L"abc", L"", L"x"), L"abc");
    EXPECT_EQ(Utils::ReplaceAll(L"a.b.c", L".", L"::"), L"a::b::c");
}

TEST_F(UtilsTest, IpHelpersUseValidatedParser) {
    // The old regex accepted 999.999.999.999 and the old stream parser read
    // uninitialised octets on malformed input.
    EXPECT_FALSE(Utils::IsValidIpAddress(L"999.999.999.999"));
    EXPECT_EQ(Utils::StringToIpAddress(L"not an ip"), 0u);
    EXPECT_EQ(Utils::StringToIpAddress(L"10.1.2.3"), 0x0A010203u);
    EXPECT_EQ(Utils::IpAddressToString(0x0A010203u), L"10.1.2.3");
    EXPECT_TRUE(Utils::IsPrivateIpAddress(L"192.168.1.1"));
}

TEST_F(UtilsTest, FormatBytes) {
    EXPECT_EQ(Utils::FormatBytes(512), L"512.00 B");
    EXPECT_EQ(Utils::FormatBytes(1536), L"1.50 KB");
}

TEST_F(LoggerTest, WritesUtf8ToLogFile) {
    Logger& logger = Logger::Instance();
    logger.SetLogLevel(LogLevel::Info);
    const std::string path = ::testing::TempDir() + "sysrecon_logger_test.log";
    std::remove(path.c_str());

    logger.SetLogFile(Utils::Utf8ToWide(path));
    logger.Info(L"user M\u00FCller");
    logger.CloseLogFile();

    std::ifstream in(path, std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    // Must be real UTF-8, not one byte per wchar_t (the old static_cast<char>).
    EXPECT_NE(contents.find("user M\xC3\xBCller"), std::string::npos);
    std::remove(path.c_str());
}
