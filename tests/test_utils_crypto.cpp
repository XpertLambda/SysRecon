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
bool Mentions(const std::vector<Utils::LpePatchHint>& v, const wchar_t* cve) {
    for (const auto& h : v) {
        if (h.cve == cve) return true;
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

TEST(MissingLpePatchHints, HintCarriesTheCveAndAFullMessage) {
    const auto hints = Utils::MissingLpePatchHints(19043, {});
    for (const auto& h : hints) {
        EXPECT_FALSE(h.cve.empty());
        EXPECT_NE(h.message.find(h.cve), String::npos);
        EXPECT_NE(h.message.find(L"KB"), String::npos);
    }
}

// BUG-002: a current Windows 11 (build 26200) was given six findings about
// 2020-2022 vulnerabilities, because the table applied to every build.
TEST(MissingLpePatchHints, Bug002_ModernBuildsGetNoAncientCves) {
    const std::set<String> few_hotfixes = {L"KB5000001", L"KB5000002", L"KB5000003", L"KB5000004", L"KB5000005"};
    for (uint32_t build : {26200u, 26100u, 22631u, 22621u, 19045u}) {
        EXPECT_TRUE(Utils::MissingLpePatchHints(build, few_hotfixes).empty()) << "build " << build;
        EXPECT_TRUE(Utils::MissingLpePatchHints(build, few_hotfixes, true).empty()) << "build " << build;
    }
}

TEST(MissingLpePatchHints, OriginalWindows11StillGetsTheJanuary2022Win32kIssue) {
    const auto hints = Utils::MissingLpePatchHints(22000, {});
    EXPECT_TRUE(Mentions(hints, L"CVE-2022-21882"));
    EXPECT_FALSE(Mentions(hints, L"CVE-2021-34527"));   // Windows 11 shipped after July 2021.
}

TEST(MissingLpePatchHints, EachCveIsAffectedOnlyWhereItExisted) {
    // Windows 10 1803 (17134): Win32k Feb-2021 yes, HiveNightmare (1809+) no.
    auto h1803 = Utils::MissingLpePatchHints(17134, {});
    EXPECT_TRUE(Mentions(h1803, L"CVE-2021-1732"));
    EXPECT_FALSE(Mentions(h1803, L"CVE-2021-36934"));
    // Windows 10 21H1 (19043): HiveNightmare yes, the Feb-2021 Win32k fix already shipped in it.
    auto h21h1 = Utils::MissingLpePatchHints(19043, {});
    EXPECT_TRUE(Mentions(h21h1, L"CVE-2021-36934"));
    EXPECT_FALSE(Mentions(h21h1, L"CVE-2021-1732"));
}

// BUG-016: Zerologon is a domain-controller flaw, not a workstation LPE.
TEST(MissingLpePatchHints, Bug016_ZerologonOnlyOnDomainControllers) {
    EXPECT_FALSE(Mentions(Utils::MissingLpePatchHints(17763, {}, false), L"CVE-2020-1472"));
    EXPECT_TRUE(Mentions(Utils::MissingLpePatchHints(17763, {}, true), L"CVE-2020-1472"));
    // A DC on Server 2022 (20348) was never vulnerable.
    EXPECT_FALSE(Mentions(Utils::MissingLpePatchHints(20348, {}, true), L"CVE-2020-1472"));
}

// --- ClassifyWindows (BUG-005) ----------------------------------------------

TEST(ClassifyWindows, ServerAndClientShareBuildNumbers) {
    // Windows Server 2025 and Windows 11 24H2 are both build 26100.
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 26100, 3).name, L"Windows Server 2025");
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 26100, 3).family, Utils::OsFamily::Server);
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 26100, 1).name, L"Windows 11");
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 26100, 1).family, Utils::OsFamily::Client);
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 26200, 1).name, L"Windows 11");
}

TEST(ClassifyWindows, ServerReleases) {
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 20348, 3).name, L"Windows Server 2022");
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 17763, 3).name, L"Windows Server 2019");
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 14393, 3).name, L"Windows Server 2016");
    EXPECT_EQ(Utils::ClassifyWindows(6, 3, 9600, 3).name, L"Windows Server 2012 R2");
    EXPECT_EQ(Utils::ClassifyWindows(6, 1, 7601, 3).name, L"Windows Server 2008 R2");
}

TEST(ClassifyWindows, DomainControllerIsAServerWithItsOwnFamily) {
    const auto dc = Utils::ClassifyWindows(10, 0, 20348, 2);
    EXPECT_EQ(dc.family, Utils::OsFamily::DomainController);
    EXPECT_EQ(dc.name, L"Windows Server 2022");
}

TEST(ClassifyWindows, ClientReleases) {
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 19045, 1).name, L"Windows 10");
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 22000, 1).name, L"Windows 11");
    EXPECT_EQ(Utils::ClassifyWindows(6, 3, 9600, 1).name, L"Windows 8.1");
    EXPECT_EQ(Utils::ClassifyWindows(6, 1, 7601, 1).name, L"Windows 7");
}

TEST(ClassifyWindows, UnknownProductTypeIsTreatedAsClientAndNeverCrashes) {
    EXPECT_EQ(Utils::ClassifyWindows(10, 0, 19045, 0).family, Utils::OsFamily::Client);
    EXPECT_EQ(Utils::ClassifyWindows(0, 0, 0, 0).family, Utils::OsFamily::Unknown);
    EXPECT_FALSE(Utils::ClassifyWindows(11, 2, 1, 1).name.empty());
}

// --- ISO-8601 timestamps (BUG-015) ------------------------------------------

TEST(Timestamp, Iso8601UtcIsUnambiguous) {
    EXPECT_EQ(Utils::FormatIso8601Utc(std::chrono::system_clock::from_time_t(0)), L"1970-01-01T00:00:00Z");
    EXPECT_EQ(Utils::FormatIso8601Utc(std::chrono::system_clock::from_time_t(1794156877)),
              L"2026-11-08T16:54:37Z");
}

TEST(Timestamp, LocalOffsetIsWithinRealWorldRange) {
    const int off = Utils::LocalUtcOffsetMinutes(std::chrono::system_clock::now());
    EXPECT_GT(off, -12 * 60);
    EXPECT_LE(off, 14 * 60);
}
