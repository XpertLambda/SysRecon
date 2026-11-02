#include <gtest/gtest.h>
#include <core/config.h>
#include <core/logger.h>
#include <core/utils.h>

#include <cstdio>
#include <fstream>

using namespace SysRecon;
using namespace SysRecon::Core;

namespace {

class ConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        Logger::Instance().SetConsoleOutput(false);
        path_ = ::testing::TempDir() + "sysrecon_config_test.json";
    }
    void TearDown() override {
        std::remove(path_.c_str());
        ConfigManager::Instance().LoadDefaults();
    }

    bool Load(const std::string& json_text) {
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out << json_text;
        out.close();
        return ConfigManager::Instance().LoadFromFile(Utils::Utf8ToWide(path_));
    }

    const ScanConfig& Cfg() { return ConfigManager::Instance().GetConfig(); }

    std::string path_;
};

}  // namespace

TEST_F(ConfigTest, LoadsShippedShape) {
    ASSERT_TRUE(Load(R"({
        "general": {"verbose_output": true, "stealth_mode": false, "require_admin": false},
        "modules": {
            "processes": {"enabled": true, "check_dlls": false},
            "network": {"enabled": true, "scan_listening_ports": false, "analyze_connections": true},
            "registry": {"enabled": true, "custom_keys": ["SOFTWARE\\Vendor"]},
            "memory": {"enabled": true, "create_dumps": true, "max_dump_size_mb": 50}
        },
        "output": {"output_directory": "./out", "generate_csv": false}
    })"));
    EXPECT_TRUE(Cfg().verbose_output);
    EXPECT_FALSE(Cfg().require_admin);
    EXPECT_FALSE(Cfg().processes.check_dlls);
    EXPECT_FALSE(Cfg().network.scan_listening_ports);
    ASSERT_EQ(Cfg().registry.custom_keys.size(), 1u);
    EXPECT_EQ(Cfg().registry.custom_keys[0], L"SOFTWARE\\Vendor");
    EXPECT_TRUE(Cfg().memory.enabled);
    EXPECT_TRUE(Cfg().memory.create_dumps);
    EXPECT_EQ(Cfg().memory.max_dump_size_mb, 50u);
    EXPECT_EQ(Cfg().output.output_directory, L"./out");
    EXPECT_FALSE(Cfg().output.generate_csv);
    EXPECT_TRUE(ConfigManager::Instance().GetWarnings().empty());
}

TEST_F(ConfigTest, WrongTypeFailsAndLeavesDefaultsNotHalfAppliedConfig) {
    // Regression: a type error threw mid-parse and returned false with every
    // value parsed before it still applied, while the engine logged "using
    // defaults".
    EXPECT_FALSE(Load(R"({
        "general": {"verbose_output": true},
        "modules": {"memory": {"enabled": "yes"}}
    })"));
    EXPECT_FALSE(Cfg().verbose_output);  // Not the half-applied `true`.
    EXPECT_FALSE(Cfg().memory.enabled);
    const auto errors = ConfigManager::Instance().GetValidationErrors();
    ASSERT_FALSE(errors.empty());
    EXPECT_NE(errors[0].find(L"modules.memory.enabled"), String::npos);
}

TEST_F(ConfigTest, SyntaxErrorFallsBackToDefaults) {
    EXPECT_FALSE(Load(R"({"general": {"verbose_output": true,)"));
    EXPECT_FALSE(Cfg().verbose_output);
}

TEST_F(ConfigTest, ValidationFailureRevertsToDefaults) {
    EXPECT_FALSE(Load(R"({
        "general": {"verbose_output": true},
        "output": {"generate_json": false, "generate_csv": false, "generate_html": false}
    })"));
    EXPECT_FALSE(Cfg().verbose_output);
    EXPECT_TRUE(Cfg().output.generate_json);
}

TEST_F(ConfigTest, RejectsNegativeAndOversizedDumpLimit) {
    EXPECT_FALSE(Load(R"({"modules": {"memory": {"max_dump_size_mb": -1}}})"));
    EXPECT_FALSE(Load(R"({"modules": {"memory": {"max_dump_size_mb": 4096}}})"));
    EXPECT_FALSE(Load(R"({"modules": {"memory": {"max_dump_size_mb": 0}}})"));
}

TEST_F(ConfigTest, WarnsAboutRemovedAndUnknownSettings) {
    // These keys exist in older config files and did nothing; an operator must
    // be told rather than left believing e.g. reports are encrypted.
    ASSERT_TRUE(Load(R"({
        "general": {"max_threads": 8},
        "security": {"encrypt_output": true},
        "modules": {"memory": {"analyze_heap": true}, "eventlogs": {"enabled": true}}
    })"));
    const auto& w = ConfigManager::Instance().GetWarnings();
    auto mentions = [&](const wchar_t* key) {
        for (const auto& msg : w) {
            if (msg.find(key) != String::npos) return true;
        }
        return false;
    };
    EXPECT_TRUE(mentions(L"general.max_threads"));
    EXPECT_TRUE(mentions(L"security"));
    EXPECT_TRUE(mentions(L"modules.memory.analyze_heap"));
    EXPECT_TRUE(mentions(L"modules.eventlogs"));
}

TEST_F(ConfigTest, MissingFileReportsErrorAndKeepsDefaults) {
    std::remove(path_.c_str());
    EXPECT_FALSE(ConfigManager::Instance().LoadFromFile(Utils::Utf8ToWide(path_)));
    EXPECT_FALSE(Cfg().memory.enabled);
}

TEST_F(ConfigTest, EventLogSettings) {
    ASSERT_TRUE(Load(R"({"modules": {"event_logs": {"enabled": false, "lookback_days": 30,
                                                    "failed_logon_threshold": 5}}})"));
    EXPECT_FALSE(Cfg().event_logs.enabled);
    EXPECT_EQ(Cfg().event_logs.lookback_days, 30u);
    EXPECT_EQ(Cfg().event_logs.failed_logon_threshold, 5u);
    EXPECT_TRUE(ConfigManager::Instance().GetWarnings().empty());

    EXPECT_FALSE(Load(R"({"modules": {"event_logs": {"lookback_days": 0}}})"));
    EXPECT_FALSE(Load(R"({"modules": {"event_logs": {"lookback_days": 366}}})"));
    EXPECT_FALSE(Load(R"({"modules": {"event_logs": {"failed_logon_threshold": 0}}})"));
    EXPECT_FALSE(Load(R"({"modules": {"event_logs": {"lookback_days": "7"}}})"));
}

TEST_F(ConfigTest, AcceptsCommentsAndUtf8Paths) {
    ASSERT_TRUE(Load("{\n  // operator note\n  \"output\": {\"output_directory\": \"C:/Berichte/M\xC3\xBCller\"}\n}"));
    EXPECT_EQ(Cfg().output.output_directory, L"C:/Berichte/M\u00FCller");
}

TEST_F(ConfigTest, ShippedConfigFileIsValid) {
    // The config.json shipped in the repo and the installer must load cleanly
    // and carry no unknown keys.
    std::ifstream shipped(SYSRECON_SOURCE_DIR "/config.json", std::ios::binary);
    ASSERT_TRUE(shipped.is_open());
    std::string text((std::istreambuf_iterator<char>(shipped)), std::istreambuf_iterator<char>());
    ASSERT_TRUE(Load(text));
    EXPECT_TRUE(ConfigManager::Instance().GetWarnings().empty());
    EXPECT_FALSE(Cfg().memory.enabled);
    EXPECT_TRUE(Cfg().event_logs.enabled);
    EXPECT_EQ(Cfg().event_logs.lookback_days, 7u);
}
