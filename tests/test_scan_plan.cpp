#include <gtest/gtest.h>
#include <core/scan_plan.h>

#include <set>

using namespace SysRecon;
using namespace SysRecon::Core;

namespace {

ScanConfig ShippedConfig() {
    // Mirrors config.json: everything on except memory.
    ScanConfig c;
    c.memory.enabled = false;
    return c;
}

CliModuleRequest Cli(std::initializer_list<ModuleType> modules) {
    CliModuleRequest req;
    req.explicit_selection = true;
    for (ModuleType m : modules) req.modules.Set(m, true);
    return req;
}

}  // namespace

// --- Module resolution ------------------------------------------------------

TEST(ResolveModules, CommandLineCanEnableModuleDisabledInConfig) {
    // Regression: `sysrecon.exe --memory` with the shipped config (memory
    // disabled) silently ran nothing, because modules were constructed from
    // the config selection before the CLI selection was applied.
    const ModuleSelection s = ResolveModules(ShippedConfig(), Cli({ModuleType::Memory}), false);
    EXPECT_TRUE(s.memory);
    EXPECT_EQ(s.Count(), 1u);
}

TEST(ResolveModules, CommandLineSelectionReplacesConfigSelection) {
    const ModuleSelection s = ResolveModules(ShippedConfig(),
                                             Cli({ModuleType::Accounts, ModuleType::Services}), false);
    EXPECT_TRUE(s.accounts);
    EXPECT_TRUE(s.services);
    EXPECT_FALSE(s.processes);
    EXPECT_FALSE(s.network);
    EXPECT_FALSE(s.registry);
    EXPECT_FALSE(s.memory);
}

TEST(ResolveModules, NoSelectionUsesConfig) {
    ScanConfig c = ShippedConfig();
    c.network.enabled = false;
    const ModuleSelection s = ResolveModules(c, CliModuleRequest{}, false);
    EXPECT_FALSE(s.network);
    EXPECT_FALSE(s.memory);
    EXPECT_TRUE(s.accounts);
    EXPECT_EQ(s.Count(), 5u);
}

TEST(ResolveModules, MissingConfigKeepsMemoryOff) {
    // Regression: with no config file found, every module defaulted to on --
    // including the memory module the README described as off by default.
    const ModuleSelection s = ResolveModules(ScanConfig{}, CliModuleRequest{}, false);
    EXPECT_FALSE(s.memory);
    EXPECT_EQ(s.Count(), 6u);
}

TEST(ResolveModules, StealthDropsMemoryEvenWhenRequested) {
    StringVector notes;
    const ModuleSelection s = ResolveModules(ShippedConfig(), Cli({ModuleType::Memory, ModuleType::Accounts}),
                                             true, &notes);
    EXPECT_FALSE(s.memory);
    EXPECT_TRUE(s.accounts);
    ASSERT_FALSE(notes.empty());
    EXPECT_NE(notes.back().find(L"stealth"), String::npos);
}

TEST(ResolveModules, AllSelectsEverything) {
    CliModuleRequest req;
    req.explicit_selection = true;
    req.modules = ModuleSelection::All();
    EXPECT_EQ(ResolveModules(ShippedConfig(), req, false).Count(), 8u);
}

TEST(ResolveModules, ExplainsCliOverrideOfConfig) {
    StringVector notes;
    ResolveModules(ShippedConfig(), Cli({ModuleType::Memory}), false, &notes);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find(L"Memory"), String::npos);
}

TEST(ModuleSelection, NamesFollowExecutionOrder) {
    ModuleSelection s;
    s.memory = true;
    s.accounts = true;
    const StringVector names = s.Names();
    ASSERT_EQ(names.size(), 2u);
    EXPECT_EQ(names[0], L"Accounts");
    EXPECT_EQ(names[1], L"Memory");
}

// --- Format resolution ------------------------------------------------------

TEST(ResolveFormats, ConfigFlagsApplyWithoutCliFormat) {
    // Regression: output.generate_* were parsed and then ignored.
    ScanConfig c;
    c.output.generate_csv = false;
    const StringVector f = ResolveFormats({}, c);
    ASSERT_EQ(f.size(), 2u);
    EXPECT_EQ(f[0], L"json");
    EXPECT_EQ(f[1], L"html");
}

TEST(ResolveFormats, CliWinsAndIsDeduplicated) {
    ScanConfig c;
    c.output.generate_html = false;
    const StringVector f = ResolveFormats({L"html", L"html", L"json"}, c);
    ASSERT_EQ(f.size(), 2u);
    EXPECT_EQ(f[0], L"html");
    EXPECT_EQ(f[1], L"json");
}

// --- Config discovery -------------------------------------------------------

TEST(ResolveConfigPath, ExplicitPathIsReturnedEvenIfMissing) {
    auto none = [](const String&) { return false; };
    EXPECT_EQ(ResolveConfigPath(L"custom.json", L"C:\\Tools", none), L"custom.json");
}

TEST(ResolveConfigPath, PrefersWorkingDirectoryThenExecutableDirectory) {
    std::set<String> files = {L"C:\\Program Files\\SysRecon\\config.json"};
    auto exists = [&](const String& p) { return files.count(p) > 0; };

    // Elevated shell in System32: no local config, falls back beside the exe.
    EXPECT_EQ(ResolveConfigPath(L"", L"C:\\Program Files\\SysRecon", exists),
              L"C:\\Program Files\\SysRecon\\config.json");

    files.insert(L"config.json");
    EXPECT_EQ(ResolveConfigPath(L"", L"C:\\Program Files\\SysRecon", exists), L"config.json");
}

TEST(ResolveConfigPath, NothingFound) {
    auto none = [](const String&) { return false; };
    EXPECT_EQ(ResolveConfigPath(L"", L"C:\\Tools", none), L"");
    EXPECT_EQ(ResolveConfigPath(L"", L"", none), L"");
}

// --- Severity parsing / exit codes ------------------------------------------

TEST(Severity, ParseAcceptsKnownLevelsAnyCase) {
    EXPECT_EQ(ParseSeverity(L"low"), SecurityLevel::Low);
    EXPECT_EQ(ParseSeverity(L"Medium"), SecurityLevel::Medium);
    EXPECT_EQ(ParseSeverity(L"HIGH"), SecurityLevel::High);
    EXPECT_EQ(ParseSeverity(L"critical"), SecurityLevel::Critical);
    EXPECT_FALSE(ParseSeverity(L"none").has_value());
    EXPECT_FALSE(ParseSeverity(L"").has_value());
}

TEST(Severity, ExitCodeMapping) {
    EXPECT_EQ(SeverityExitCode(SecurityLevel::Critical, false), 0);  // no findings -> 0
    EXPECT_EQ(SeverityExitCode(SecurityLevel::Low, true), 0);
    EXPECT_EQ(SeverityExitCode(SecurityLevel::Medium, true), 10);
    EXPECT_EQ(SeverityExitCode(SecurityLevel::High, true), 20);
    EXPECT_EQ(SeverityExitCode(SecurityLevel::Critical, true), 30);
}

// --- Path helpers -----------------------------------------------------------

TEST(PathHelpers, AbsoluteDetection) {
    EXPECT_TRUE(IsAbsolutePath(L"C:\\Windows"));
    EXPECT_TRUE(IsAbsolutePath(L"d:/data"));
    EXPECT_TRUE(IsAbsolutePath(L"\\\\server\\share"));
    EXPECT_TRUE(IsAbsolutePath(L"/tmp/x"));
    EXPECT_FALSE(IsAbsolutePath(L"reports"));
    EXPECT_FALSE(IsAbsolutePath(L".\\reports"));
    EXPECT_FALSE(IsAbsolutePath(L"C:reports"));  // Drive-relative.
    EXPECT_FALSE(IsAbsolutePath(L""));
}

TEST(PathHelpers, ResolveAgainstConfigDirectory) {
    // config.json's "./reports" lands next to the config, not in whatever
    // directory the elevated shell happened to start in.
    EXPECT_EQ(ResolveAgainst(L"C:\\Program Files\\SysRecon", L"./reports"),
              L"C:\\Program Files\\SysRecon\\reports");
    EXPECT_EQ(ResolveAgainst(L"C:\\Program Files\\SysRecon\\", L"reports"),
              L"C:\\Program Files\\SysRecon\\reports");
    EXPECT_EQ(ResolveAgainst(L"C:\\base", L"D:\\abs"), L"D:\\abs");
    EXPECT_EQ(ResolveAgainst(L"", L"./reports"), L"./reports");
    EXPECT_EQ(ResolveAgainst(L"/opt/sr", L"reports"), L"/opt/sr/reports");
    EXPECT_EQ(ResolveAgainst(L"C:\\base", L"."), L"C:\\base");
}

TEST(PathHelpers, ParentDirectory) {
    EXPECT_EQ(ParentDirectory(L"C:\\Program Files\\SysRecon\\config.json"), L"C:\\Program Files\\SysRecon");
    EXPECT_EQ(ParentDirectory(L"config.json"), L"");
    EXPECT_EQ(ParentDirectory(L"/config.json"), L"/");
}
