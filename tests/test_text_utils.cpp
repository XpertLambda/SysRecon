#include <gtest/gtest.h>
#include <core/text_utils.h>

using namespace SysRecon::Core::Text;

// --- IPv4 parsing -----------------------------------------------------------

TEST(Ipv4, ParsesValidDottedQuad) {
    uint32_t ip = 0;
    ASSERT_TRUE(TryParseIpv4(L"192.168.10.200", ip));
    EXPECT_EQ(ip, 0xC0A80AC8u);
    ASSERT_TRUE(TryParseIpv4(L"0.0.0.0", ip));
    EXPECT_EQ(ip, 0u);
    ASSERT_TRUE(TryParseIpv4(L"255.255.255.255", ip));
    EXPECT_EQ(ip, 0xFFFFFFFFu);
}

TEST(Ipv4, RejectsOutOfRangeAndMalformed) {
    uint32_t ip = 0x12345678;
    EXPECT_FALSE(TryParseIpv4(L"999.999.999.999", ip));
    EXPECT_FALSE(TryParseIpv4(L"256.0.0.1", ip));
    EXPECT_FALSE(TryParseIpv4(L"1.2.3", ip));
    EXPECT_FALSE(TryParseIpv4(L"1.2.3.4.5", ip));
    EXPECT_FALSE(TryParseIpv4(L"1.2.3.4 ", ip));
    EXPECT_FALSE(TryParseIpv4(L"1..3.4", ip));
    EXPECT_FALSE(TryParseIpv4(L"0001.2.3.4", ip));
    EXPECT_FALSE(TryParseIpv4(L"", ip));
    EXPECT_FALSE(TryParseIpv4(L"a.b.c.d", ip));
    // `out` is untouched on failure.
    EXPECT_EQ(ip, 0x12345678u);
}

TEST(Ipv4, ClassifiesPrivateRanges) {
    EXPECT_TRUE(IsPrivateIpv4(L"10.0.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"172.16.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"172.31.255.255"));
    EXPECT_FALSE(IsPrivateIpv4(L"172.32.0.1"));
    EXPECT_FALSE(IsPrivateIpv4(L"172.15.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"192.168.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"169.254.1.1"));
    EXPECT_FALSE(IsPrivateIpv4(L"8.8.8.8"));
    EXPECT_FALSE(IsPrivateIpv4(L"not-an-ip"));
}

TEST(Ipv4, DetectsLoopback) {
    EXPECT_TRUE(IsLoopbackIpv4(L"127.0.0.1"));
    EXPECT_TRUE(IsLoopbackIpv4(L"127.10.0.1"));
    EXPECT_FALSE(IsLoopbackIpv4(L"0.0.0.0"));
    EXPECT_FALSE(IsLoopbackIpv4(L"10.0.0.1"));
}

// --- Registry string decoding ----------------------------------------------
// Registry data is attacker-controlled. The policy reader used to cast the raw
// buffer to WCHAR* and read until a NUL that need not exist.

TEST(RegistryBuffer, StopsAtTerminator) {
    const wchar_t data[] = L"abc\0junk";
    EXPECT_EQ(RegistryBufferToString(data, sizeof(data)), L"abc");
}

TEST(RegistryBuffer, NeverReadsPastByteCountWhenUnterminated) {
    const wchar_t data[4] = {L'a', L'b', L'c', L'd'};  // No terminator at all.
    EXPECT_EQ(RegistryBufferToString(data, 3 * sizeof(wchar_t)), L"abc");
    EXPECT_EQ(RegistryBufferToString(data, sizeof(data)), L"abcd");
}

TEST(RegistryBuffer, IgnoresTrailingOddByte) {
    const wchar_t data[] = {L'x', L'y'};
    EXPECT_EQ(RegistryBufferToString(data, sizeof(wchar_t) + 1), L"x");
}

TEST(RegistryBuffer, HandlesEmptyAndNull) {
    const wchar_t data[] = {L'\0'};
    EXPECT_EQ(RegistryBufferToString(data, 0), L"");
    EXPECT_EQ(RegistryBufferToString(data, 1), L"");
    EXPECT_EQ(RegistryBufferToString(nullptr, 100), L"");
}

// --- File-name sanitising ---------------------------------------------------
// Dump files are named after the (attacker-chosen) process name.

TEST(SanitizeFileName, ReplacesPathAndReservedCharacters) {
    EXPECT_EQ(SanitizeFileName(L"..\\..\\Windows\\evil.exe"), L"___.._Windows_evil.exe");
    EXPECT_EQ(SanitizeFileName(L"a/b:c*d?e\"f<g>h|i"), L"a_b_c_d_e_f_g_h_i");
}

TEST(SanitizeFileName, NeutralisesDotNames) {
    EXPECT_EQ(SanitizeFileName(L".."), L"__");
    EXPECT_EQ(SanitizeFileName(L".hidden"), L"_hidden");
}

TEST(SanitizeFileName, KeepsOrdinaryNamesAndCapsLength) {
    EXPECT_EQ(SanitizeFileName(L"notepad.exe"), L"notepad.exe");
    EXPECT_EQ(SanitizeFileName(L""), L"unnamed");
    EXPECT_EQ(SanitizeFileName(WString(200, L'a')).size(), 64u);
}
