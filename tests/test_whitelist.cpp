#include <gtest/gtest.h>
#include <core/whitelist.h>
#include <core/text_utils.h>

using namespace SysRecon::Core;

// Regression tests for whitelist evasions. Each case below previously caused a
// finding to be suppressed entirely -- not merely misranked -- which is the
// worst possible failure for a detection tool.

namespace {
SystemWhitelist& WL() { return SystemWhitelist::Instance(); }
}

// --- IsSystemPath: prefix matching without a path boundary -----------------

TEST(IsSystemPath, RejectsSiblingDirectoryWithSharedPrefix) {
    // "c:\windows" must not prefix-match "C:\WindowsUpdate\...".
    EXPECT_FALSE(WL().IsSystemPath(L"C:\\WindowsUpdate\\evil.exe"));
    EXPECT_FALSE(WL().IsSystemPath(L"C:\\Windows_backdoor\\x.exe"));
}

TEST(IsSystemPath, AcceptsGenuineSystemPaths) {
    EXPECT_TRUE(WL().IsSystemPath(L"C:\\Windows\\System32\\svchost.exe"));
    EXPECT_TRUE(WL().IsSystemPath(L"C:\\Windows\\explorer.exe"));
}

TEST(IsSystemPath, IsCaseInsensitive) {
    EXPECT_TRUE(WL().IsSystemPath(L"c:\\WINDOWS\\SYSTEM32\\svchost.exe"));
}

TEST(IsSystemPath, RejectsEmptyAndUserWritableLocations) {
    EXPECT_FALSE(WL().IsSystemPath(L""));
    EXPECT_FALSE(WL().IsSystemPath(L"C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe"));
}

// --- Masquerading: name-only matching (T1036.005) --------------------------

TEST(IsSystemProcess, RejectsSystemNameRunningFromTempDirectory) {
    // Naming an implant svchost.exe must not exempt it.
    EXPECT_FALSE(WL().IsSystemProcess(L"svchost.exe", L"C:\\Temp\\svchost.exe"));
    EXPECT_FALSE(WL().IsSystemProcess(L"csrss.exe", L"C:\\Users\\bob\\csrss.exe"));
}

TEST(IsSystemProcess, AcceptsGenuineSystemBinary) {
    EXPECT_TRUE(WL().IsSystemProcess(L"svchost.exe", L"C:\\Windows\\System32\\svchost.exe"));
}

TEST(IsSystemProcess, TreatsUnverifiedPathAsNotWhitelisted) {
    // No path evidence means no suppression -- fail closed.
    EXPECT_FALSE(WL().IsSystemProcess(L"svchost.exe", L""));
}

TEST(IsSystemService, RequiresSystemPathNotJustKnownName) {
    EXPECT_FALSE(WL().IsSystemService(L"eventlog", L"C:\\Temp\\evil.exe"));
    EXPECT_TRUE(WL().IsSystemService(L"eventlog", L"C:\\Windows\\System32\\svchost.exe"));
}

TEST(IsSystemDll, RequiresSystemPathNotJustKnownName) {
    EXPECT_FALSE(WL().IsSystemDll(L"ntdll.dll", L"C:\\Temp\\ntdll.dll"));
    EXPECT_TRUE(WL().IsSystemDll(L"ntdll.dll", L"C:\\Windows\\System32\\ntdll.dll"));
}

// --- Persistence entries: unanchored substring match -----------------------

TEST(IsKnownPersistenceEntry, RejectsAttackerChosenNameContainingTrustedSubstring) {
    // The original bug: find() matched "OneDrive" inside any longer name, so a
    // Run entry named "OneDrive Updater" whitelisted itself out of the report.
    EXPECT_FALSE(WL().IsKnownPersistenceEntry(L"OneDrive Updater", L"C:\\Temp\\evil.exe"));
    EXPECT_FALSE(WL().IsKnownPersistenceEntry(L"My Windows Security Helper", L"C:\\Temp\\evil.exe"));
    EXPECT_FALSE(WL().IsKnownPersistenceEntry(L"Windows Defender Update Helper", L"C:\\Temp\\x.exe"));
}

TEST(IsKnownPersistenceEntry, RejectsTrustedNamePointingAtUntrustedBinary) {
    // Exact name match is still not enough on its own.
    EXPECT_FALSE(WL().IsKnownPersistenceEntry(L"OneDrive", L"C:\\Users\\bob\\evil.exe"));
}

TEST(IsKnownPersistenceEntry, AcceptsTrustedNameWithSystemBinary) {
    EXPECT_TRUE(WL().IsKnownPersistenceEntry(
        L"Windows Defender", L"C:\\Program Files\\Windows Defender\\MSASCuiL.exe"));
}

TEST(IsKnownPersistenceEntry, MatchesCaseInsensitivelyInBothDirections) {
    // The original was the only case-sensitive check, so "onedrive" bypassed it.
    EXPECT_TRUE(WL().IsKnownPersistenceEntry(
        L"wInDoWs DeFeNdEr", L"C:\\Program Files\\Windows Defender\\MSASCuiL.exe"));
}

// --- Unquoted service paths ------------------------------------------------

TEST(IsSafeUnquotedPath, FlagsClassicHijackableServicePath) {
    // C:\Program.exe would be executed before the real binary.
    EXPECT_FALSE(WL().IsSafeUnquotedPath(L"C:\\Program Files\\X\\y.exe"));
    EXPECT_FALSE(WL().IsSafeUnquotedPath(L"C:\\Program Files (x86)\\App\\app.exe -run"));
}

TEST(IsSafeUnquotedPath, AcceptsFullyQuotedPath) {
    EXPECT_TRUE(WL().IsSafeUnquotedPath(L"\"C:\\Program Files\\X\\y.exe\" -k netsvcs"));
}

TEST(IsSafeUnquotedPath, AcceptsPathWithoutSpaces) {
    EXPECT_TRUE(WL().IsSafeUnquotedPath(L"C:\\Windows\\System32\\svchost.exe"));
    EXPECT_TRUE(WL().IsSafeUnquotedPath(L"C:\\Windows\\System32\\svchost.exe -k netsvcs"));
}

TEST(IsSafeUnquotedPath, RejectsAttackerPrefixedFirstExeTrick) {
    // Original bug: it found the FIRST ".exe" with no preceding space and
    // declared the whole path safe, so this hijack was reported as safe.
    // The first token here IS a complete .exe, so the command as written is
    // unambiguous -- but the previously whitelisted "C:\Program Files\Windows*"
    // prefix must no longer rescue a genuinely hijackable path.
    EXPECT_FALSE(WL().IsSafeUnquotedPath(L"C:\\Program Files\\WindowsApps\\rogue\\app.exe"));
}

TEST(IsSafeUnquotedPath, RejectsUnquotedPathWhoseFirstTokenIsNotAnExecutable) {
    EXPECT_FALSE(WL().IsSafeUnquotedPath(L"C:\\Program Files\\Sub Dir\\run"));
}

// --- Operator-configurable trust -------------------------------------------

TEST(TrustedPath, OperatorCanWhitelistOrgSpecificLocation) {
    auto& wl = WL();
    EXPECT_FALSE(wl.IsSystemPath(L"D:\\CorpTools\\agent.exe"));
    wl.AddTrustedPath(L"d:\\corptools");
    EXPECT_TRUE(wl.IsSystemPath(L"D:\\CorpTools\\agent.exe"));
    // Boundary rule still applies to operator-supplied entries.
    EXPECT_FALSE(wl.IsSystemPath(L"D:\\CorpToolsEvil\\agent.exe"));
}
