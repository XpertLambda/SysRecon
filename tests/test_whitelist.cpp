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

// --- Name-only lookups: used to RAISE findings, never to suppress ----------

TEST(SystemProcessName, MatchesKnownNameRegardlessOfPath) {
    // This is the masquerade signal: name matches, path is checked separately.
    EXPECT_TRUE(WL().IsSystemProcessName(L"svchost.exe"));
    EXPECT_TRUE(WL().IsSystemProcessName(L"SVCHOST.EXE"));
    EXPECT_FALSE(WL().IsSystemProcessName(L"totally-not-malware.exe"));
}

TEST(SystemDllName, MatchesKnownDllForSideloadingDetection) {
    EXPECT_TRUE(WL().IsSystemDllName(L"ntdll.dll"));
    EXPECT_FALSE(WL().IsSystemDllName(L"mygame.dll"));
}

TEST(MasqueradeSignal, KnownNameOutsideSystemPathIsDetectable) {
    // The exact condition the Processes module flags as T1036.005.
    const SysRecon::String name = L"svchost.exe";
    const SysRecon::String path = L"C:\\Temp\\svchost.exe";
    EXPECT_TRUE(WL().IsSystemProcessName(name));
    EXPECT_FALSE(WL().IsSystemPath(path));
    EXPECT_FALSE(WL().IsSystemProcess(name, path));
}

// --- Execution-path helpers ------------------------------------------------

TEST(UserWritableExecutionPath, FlagsCommonDropLocations) {
    using namespace SysRecon::Core::Text;
    EXPECT_TRUE(IsUserWritableExecutionPath(L"C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"));
    EXPECT_TRUE(IsUserWritableExecutionPath(L"C:\\Windows\\Temp\\x.exe"));
    EXPECT_TRUE(IsUserWritableExecutionPath(L"C:\\Users\\bob\\Downloads\\setup.exe"));
    EXPECT_TRUE(IsUserWritableExecutionPath(L"C:\\Users\\Public\\x.exe"));
    EXPECT_TRUE(IsUserWritableExecutionPath(L"C:\\$Recycle.Bin\\S-1-5-21\\x.exe"));
}

TEST(UserWritableExecutionPath, IgnoresNormalInstallLocations) {
    using namespace SysRecon::Core::Text;
    EXPECT_FALSE(IsUserWritableExecutionPath(L"C:\\Windows\\System32\\svchost.exe"));
    EXPECT_FALSE(IsUserWritableExecutionPath(L"C:\\Program Files\\App\\app.exe"));
    EXPECT_FALSE(IsUserWritableExecutionPath(L""));
}

TEST(ExtractExecutablePath, HandlesQuotedAndUnquotedCommands) {
    using namespace SysRecon::Core::Text;
    EXPECT_EQ(ExtractExecutablePath(L"\"C:\\Program Files\\X\\y.exe\" -k netsvcs"),
              L"C:\\Program Files\\X\\y.exe");
    EXPECT_EQ(ExtractExecutablePath(L"C:\\Windows\\System32\\svchost.exe -k netsvcs"),
              L"C:\\Windows\\System32\\svchost.exe");
    EXPECT_EQ(ExtractExecutablePath(L"  C:\\Windows\\x.exe"), L"C:\\Windows\\x.exe");
}

TEST(ExtractExecutablePath, ReturnsExeNotTrailingArgumentForRundll) {
    using namespace SysRecon::Core::Text;
    EXPECT_EQ(ExtractExecutablePath(L"C:\\Windows\\system32\\rundll32.exe foo.dll,Entry"),
              L"C:\\Windows\\system32\\rundll32.exe");
}

TEST(ExtractExecutablePath, ReturnsEmptyOnUnterminatedQuote) {
    using namespace SysRecon::Core::Text;
    EXPECT_EQ(ExtractExecutablePath(L"\"C:\\broken\\path.exe"), L"");
    EXPECT_EQ(ExtractExecutablePath(L"   "), L"");
}

TEST(GetFileNameComponent, ExtractsLeafName) {
    using namespace SysRecon::Core::Text;
    EXPECT_EQ(GetFileNameComponent(L"C:\\a\\b\\x.exe"), L"x.exe");
    EXPECT_EQ(GetFileNameComponent(L"x.exe"), L"x.exe");
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
