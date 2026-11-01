#include <gtest/gtest.h>
#include <core/utils.h>

#include <set>

using namespace SysRecon;
using namespace SysRecon::Core;

// --- SHA-256 (FIPS 180-4 test vectors) --------------------------------------

TEST(Sha256, NistVectors) {
    EXPECT_EQ(Utils::Sha256Hex(ByteVector{}),
              L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const std::string abc = "abc";
    EXPECT_EQ(Utils::Sha256Hex(ByteVector(abc.begin(), abc.end())),
              L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const std::string two_block =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    EXPECT_EQ(Utils::Sha256Hex(ByteVector(two_block.begin(), two_block.end())),
              L"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256, MillionA) {
    // One million 'a' characters -> the classic long-message vector. Exercises
    // multi-block buffering and the length encoding.
    ByteVector big(1000000, static_cast<uint8_t>('a'));
    EXPECT_EQ(Utils::Sha256Hex(big),
              L"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// --- ExtractExecutablePath --------------------------------------------------

TEST(ExtractExecutablePath, Quoted) {
    EXPECT_EQ(Utils::ExtractExecutablePath(L"\"C:\\Program Files\\App\\svc.exe\" -k netsvcs"),
              L"C:\\Program Files\\App\\svc.exe");
}

TEST(ExtractExecutablePath, UnquotedWithSpacesStopsAtExe) {
    EXPECT_EQ(Utils::ExtractExecutablePath(L"C:\\Program Files\\App\\svc.exe -arg"),
              L"C:\\Program Files\\App\\svc.exe");
}

TEST(ExtractExecutablePath, PlainPath) {
    EXPECT_EQ(Utils::ExtractExecutablePath(L"C:\\Windows\\system32\\svchost.exe"),
              L"C:\\Windows\\system32\\svchost.exe");
}

TEST(ExtractExecutablePath, NativePrefixStripped) {
    EXPECT_EQ(Utils::ExtractExecutablePath(L"\\??\\C:\\drivers\\x.exe"),
              L"C:\\drivers\\x.exe");
}

TEST(ExtractExecutablePath, Empty) {
    EXPECT_EQ(Utils::ExtractExecutablePath(L"   "), L"");
}

// --- MissingLpePatchHints ---------------------------------------------------

namespace {
bool Mentions(const StringVector& v, const wchar_t* needle) {
    for (const auto& s : v) {
        if (s.find(needle) != String::npos) return true;
    }
    return false;
}
}  // namespace

TEST(MissingLpePatchHints, FlagsWhenNoFixInstalled) {
    const auto hints = Utils::MissingLpePatchHints(19043, {});
    EXPECT_TRUE(Mentions(hints, L"CVE-2021-34527"));  // PrintNightmare
    EXPECT_TRUE(Mentions(hints, L"CVE-2021-36934"));  // HiveNightmare
}

TEST(MissingLpePatchHints, SuppressedWhenFixingKbPresent) {
    const std::set<String> installed = {L"KB5004945"};  // PrintNightmare fix
    const auto hints = Utils::MissingLpePatchHints(19043, installed);
    EXPECT_FALSE(Mentions(hints, L"CVE-2021-34527"));
    // An unrelated CVE is still reported.
    EXPECT_TRUE(Mentions(hints, L"CVE-2021-36934"));
}
