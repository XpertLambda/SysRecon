#include "../../include/core/config.h"
#include "../../include/core/utils.h"
#include <json/json.hpp>
#include <fstream>
#include <set>

using json = nlohmann::json;

namespace SysRecon {
namespace Core {

namespace {

// The accepted schema. Anything outside it is reported as a warning rather
// than silently ignored: several keys that older config files carry
// (security.encrypt_output, general.max_threads, memory.analyze_heap, ...)
// were removed because the binary never honoured them, and an operator must
// not be left believing they are in effect.
const std::map<std::string, std::set<std::string>>& ModuleSchema() {
    static const std::map<std::string, std::set<std::string>> schema = {
        {"accounts",  {"enabled", "enumerate_groups"}},
        {"services",  {"enabled"}},
        {"processes", {"enabled", "check_dlls"}},
        {"network",   {"enabled", "scan_listening_ports", "analyze_connections"}},
        {"registry",  {"enabled", "scan_startup_keys", "analyze_policies", "check_permissions", "custom_keys"}},
        {"memory",    {"enabled", "create_dumps", "scan_for_malware", "max_dump_size_mb"}},
        {"privesc",   {"enabled", "check_services", "check_registry", "check_filesystem", "check_credentials", "verify_signatures", "check_tokens", "check_scheduled_tasks", "check_patches"}},
    };
    return schema;
}

const std::set<std::string> kGeneralKeys = {"verbose_output", "stealth_mode", "require_admin"};
const std::set<std::string> kOutputKeys  = {"output_directory", "generate_json", "generate_csv", "generate_html"};
const std::set<std::string> kTopLevelKeys = {"general", "modules", "output"};

// Typed readers. A wrong type is a validation error naming the key, instead
// of a json::type_error escaping with nlohmann's generic message.
class Reader {
public:
    explicit Reader(StringVector& errors) : errors_(errors) {}

    void Bool(const json& obj, const char* section, const char* key, bool& target) {
        if (!obj.contains(key)) return;
        const json& v = obj.at(key);
        if (!v.is_boolean()) {
            Error(section, key, L"must be true or false");
            return;
        }
        target = v.get<bool>();
    }

    void SizeT(const json& obj, const char* section, const char* key, size_t& target) {
        if (!obj.contains(key)) return;
        const json& v = obj.at(key);
        if (!v.is_number_integer() || v.get<long long>() < 0) {
            Error(section, key, L"must be a non-negative integer");
            return;
        }
        target = static_cast<size_t>(v.get<long long>());
    }

    void Str(const json& obj, const char* section, const char* key, String& target) {
        if (!obj.contains(key)) return;
        const json& v = obj.at(key);
        if (!v.is_string()) {
            Error(section, key, L"must be a string");
            return;
        }
        target = Utils::Utf8ToWide(v.get<std::string>());
    }

    void StrList(const json& obj, const char* section, const char* key, StringVector& target) {
        if (!obj.contains(key)) return;
        const json& v = obj.at(key);
        if (!v.is_array()) {
            Error(section, key, L"must be an array of strings");
            return;
        }
        StringVector values;
        for (const auto& item : v) {
            if (!item.is_string()) {
                Error(section, key, L"must contain only strings");
                return;
            }
            values.push_back(Utils::Utf8ToWide(item.get<std::string>()));
        }
        target = std::move(values);
    }

private:
    void Error(const char* section, const char* key, const wchar_t* what) {
        errors_.push_back(Utils::Utf8ToWide(std::string(section) + "." + key) + L" " + what);
    }
    StringVector& errors_;
};

void WarnUnknownKeys(const json& obj, const std::string& section,
                     const std::set<std::string>& known, StringVector& warnings) {
    if (!obj.is_object()) return;
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (known.find(it.key()) == known.end()) {
            const std::string path = section.empty() ? it.key() : section + "." + it.key();
            warnings.push_back(L"Unknown or unsupported setting ignored: " + Utils::Utf8ToWide(path));
        }
    }
}

}  // namespace

ConfigManager& ConfigManager::Instance() {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::LoadFromFile(const String& filename) {
    validation_errors_.clear();
    warnings_.clear();
    LoadDefaults();

    if (!Utils::FileExists(filename)) {
        validation_errors_.push_back(L"Configuration file not found: " + filename);
        return false;
    }

    SYSRECON_LOG_INFO(L"Loading configuration from: " + filename);

    // Parse into a scratch copy. A failure at any point -- syntax error, wrong
    // type, failed validation -- leaves the defaults in place rather than a
    // half-applied mixture of file and default values.
    ScanConfig parsed{};
    StringVector errors;

    try {
        std::ifstream file{std::filesystem::path(filename)};
        if (!file.is_open()) {
            validation_errors_.push_back(L"Failed to open configuration file: " + filename);
            return false;
        }

        json j = json::parse(file, nullptr, true, /*ignore_comments=*/true);
        if (!j.is_object()) {
            validation_errors_.push_back(L"Configuration root must be a JSON object");
            return false;
        }

        Reader r(errors);
        WarnUnknownKeys(j, "", kTopLevelKeys, warnings_);

        if (j.contains("general")) {
            const json& gen = j.at("general");
            WarnUnknownKeys(gen, "general", kGeneralKeys, warnings_);
            r.Bool(gen, "general", "verbose_output", parsed.verbose_output);
            r.Bool(gen, "general", "stealth_mode", parsed.stealth_mode);
            r.Bool(gen, "general", "require_admin", parsed.require_admin);
        }

        if (j.contains("modules")) {
            const json& modules = j.at("modules");
            std::set<std::string> module_names;
            for (const auto& [name, keys] : ModuleSchema()) {
                module_names.insert(name);
                if (modules.contains(name)) {
                    WarnUnknownKeys(modules.at(name), "modules." + name, keys, warnings_);
                }
            }
            WarnUnknownKeys(modules, "modules", module_names, warnings_);

            auto section = [&](const char* name) -> const json* {
                return modules.contains(name) && modules.at(name).is_object() ? &modules.at(name) : nullptr;
            };

            if (const json* acc = section("accounts")) {
                r.Bool(*acc, "modules.accounts", "enabled", parsed.accounts.enabled);
                r.Bool(*acc, "modules.accounts", "enumerate_groups", parsed.accounts.enumerate_groups);
            }
            if (const json* svc = section("services")) {
                r.Bool(*svc, "modules.services", "enabled", parsed.services.enabled);
            }
            if (const json* proc = section("processes")) {
                r.Bool(*proc, "modules.processes", "enabled", parsed.processes.enabled);
                r.Bool(*proc, "modules.processes", "check_dlls", parsed.processes.check_dlls);
            }
            if (const json* net = section("network")) {
                r.Bool(*net, "modules.network", "enabled", parsed.network.enabled);
                r.Bool(*net, "modules.network", "scan_listening_ports", parsed.network.scan_listening_ports);
                r.Bool(*net, "modules.network", "analyze_connections", parsed.network.analyze_connections);
            }
            if (const json* reg = section("registry")) {
                r.Bool(*reg, "modules.registry", "enabled", parsed.registry.enabled);
                r.Bool(*reg, "modules.registry", "scan_startup_keys", parsed.registry.scan_startup_keys);
                r.Bool(*reg, "modules.registry", "analyze_policies", parsed.registry.analyze_policies);
                r.Bool(*reg, "modules.registry", "check_permissions", parsed.registry.check_permissions);
                r.StrList(*reg, "modules.registry", "custom_keys", parsed.registry.custom_keys);
            }
            if (const json* mem = section("memory")) {
                r.Bool(*mem, "modules.memory", "enabled", parsed.memory.enabled);
                r.Bool(*mem, "modules.memory", "create_dumps", parsed.memory.create_dumps);
                r.Bool(*mem, "modules.memory", "scan_for_malware", parsed.memory.scan_for_malware);
                r.SizeT(*mem, "modules.memory", "max_dump_size_mb", parsed.memory.max_dump_size_mb);
            }
            if (const json* pe = section("privesc")) {
                r.Bool(*pe, "modules.privesc", "enabled", parsed.privesc.enabled);
                r.Bool(*pe, "modules.privesc", "check_services", parsed.privesc.check_services);
                r.Bool(*pe, "modules.privesc", "check_registry", parsed.privesc.check_registry);
                r.Bool(*pe, "modules.privesc", "check_filesystem", parsed.privesc.check_filesystem);
                r.Bool(*pe, "modules.privesc", "check_credentials", parsed.privesc.check_credentials);
                r.Bool(*pe, "modules.privesc", "verify_signatures", parsed.privesc.verify_signatures);
                r.Bool(*pe, "modules.privesc", "check_tokens", parsed.privesc.check_tokens);
                r.Bool(*pe, "modules.privesc", "check_scheduled_tasks", parsed.privesc.check_scheduled_tasks);
                r.Bool(*pe, "modules.privesc", "check_patches", parsed.privesc.check_patches);
            }
        }

        if (j.contains("output")) {
            const json& out = j.at("output");
            WarnUnknownKeys(out, "output", kOutputKeys, warnings_);
            r.Str(out, "output", "output_directory", parsed.output.output_directory);
            r.Bool(out, "output", "generate_json", parsed.output.generate_json);
            r.Bool(out, "output", "generate_csv", parsed.output.generate_csv);
            r.Bool(out, "output", "generate_html", parsed.output.generate_html);
        }

    } catch (const json::exception& e) {
        validation_errors_.push_back(L"JSON parsing error: " + Utils::Utf8ToWide(e.what()));
        SYSRECON_LOG_ERROR(L"Failed to parse configuration: " + Utils::Utf8ToWide(e.what()));
        return false;
    } catch (const std::exception& e) {
        validation_errors_.push_back(L"Configuration loading error: " + Utils::Utf8ToWide(e.what()));
        SYSRECON_LOG_ERROR(L"Failed to load configuration: " + Utils::Utf8ToWide(e.what()));
        return false;
    }

    for (const auto& w : warnings_) {
        SYSRECON_LOG_WARNING(w);
    }

    config_ = parsed;
    if (!errors.empty() || !ValidateConfig()) {
        // ValidateConfig() clears validation_errors_, so merge type errors in after it.
        validation_errors_.insert(validation_errors_.begin(), errors.begin(), errors.end());
        for (const auto& err : validation_errors_) {
            SYSRECON_LOG_ERROR(L"Invalid configuration: " + err);
        }
        LoadDefaults();
        return false;
    }

    SYSRECON_LOG_INFO(L"Configuration loaded successfully");
    return true;
}

bool ConfigManager::SaveToFile(const String& filename) const {
    SYSRECON_LOG_INFO(L"Saving configuration to: " + filename);

    try {
        json j;

        j["general"]["verbose_output"] = config_.verbose_output;
        j["general"]["stealth_mode"] = config_.stealth_mode;
        j["general"]["require_admin"] = config_.require_admin;

        j["modules"]["accounts"]["enabled"] = config_.accounts.enabled;
        j["modules"]["accounts"]["enumerate_groups"] = config_.accounts.enumerate_groups;

        j["modules"]["services"]["enabled"] = config_.services.enabled;

        j["modules"]["processes"]["enabled"] = config_.processes.enabled;
        j["modules"]["processes"]["check_dlls"] = config_.processes.check_dlls;

        j["modules"]["network"]["enabled"] = config_.network.enabled;
        j["modules"]["network"]["scan_listening_ports"] = config_.network.scan_listening_ports;
        j["modules"]["network"]["analyze_connections"] = config_.network.analyze_connections;

        j["modules"]["registry"]["enabled"] = config_.registry.enabled;
        j["modules"]["registry"]["scan_startup_keys"] = config_.registry.scan_startup_keys;
        j["modules"]["registry"]["analyze_policies"] = config_.registry.analyze_policies;
        j["modules"]["registry"]["check_permissions"] = config_.registry.check_permissions;
        j["modules"]["registry"]["custom_keys"] = json::array();
        for (const auto& key : config_.registry.custom_keys) {
            j["modules"]["registry"]["custom_keys"].push_back(Utils::WideToUtf8(key));
        }

        j["modules"]["memory"]["enabled"] = config_.memory.enabled;
        j["modules"]["memory"]["create_dumps"] = config_.memory.create_dumps;
        j["modules"]["memory"]["scan_for_malware"] = config_.memory.scan_for_malware;
        j["modules"]["memory"]["max_dump_size_mb"] = config_.memory.max_dump_size_mb;

        j["modules"]["privesc"]["enabled"] = config_.privesc.enabled;
        j["modules"]["privesc"]["check_services"] = config_.privesc.check_services;
        j["modules"]["privesc"]["check_registry"] = config_.privesc.check_registry;
        j["modules"]["privesc"]["check_filesystem"] = config_.privesc.check_filesystem;
        j["modules"]["privesc"]["check_credentials"] = config_.privesc.check_credentials;
        j["modules"]["privesc"]["verify_signatures"] = config_.privesc.verify_signatures;
        j["modules"]["privesc"]["check_tokens"] = config_.privesc.check_tokens;
        j["modules"]["privesc"]["check_scheduled_tasks"] = config_.privesc.check_scheduled_tasks;
        j["modules"]["privesc"]["check_patches"] = config_.privesc.check_patches;

        j["output"]["output_directory"] = Utils::WideToUtf8(config_.output.output_directory);
        j["output"]["generate_json"] = config_.output.generate_json;
        j["output"]["generate_csv"] = config_.output.generate_csv;
        j["output"]["generate_html"] = config_.output.generate_html;

        std::ofstream file{std::filesystem::path(filename)};
        if (!file.is_open()) {
            SYSRECON_LOG_ERROR(L"Failed to open file for writing: " + filename);
            return false;
        }

        file << j.dump(4);
        file.close();

        SYSRECON_LOG_INFO(L"Configuration saved successfully");
        return true;

    } catch (const std::exception& e) {
        SYSRECON_LOG_ERROR(L"Failed to save configuration: " + Utils::Utf8ToWide(e.what()));
        return false;
    }
}

bool ConfigManager::LoadDefaults() {
    // ScanConfig carries its defaults as member initialisers; re-listing them
    // here only created a second place to forget to update.
    config_ = ScanConfig{};
    return true;
}

bool ConfigManager::IsModuleEnabled(ModuleType module) const {
    switch (module) {
        case ModuleType::Accounts:  return config_.accounts.enabled;
        case ModuleType::Services:  return config_.services.enabled;
        case ModuleType::Processes: return config_.processes.enabled;
        case ModuleType::Network:   return config_.network.enabled;
        case ModuleType::Registry:  return config_.registry.enabled;
        case ModuleType::Memory:    return config_.memory.enabled;
        case ModuleType::PrivEsc:   return config_.privesc.enabled;
        default:                    return false;
    }
}

bool ConfigManager::ValidateConfig() const {
    validation_errors_.clear();

    if (config_.output.output_directory.empty()) {
        validation_errors_.push_back(L"output_directory cannot be empty");
    }

    if (config_.memory.max_dump_size_mb == 0 || config_.memory.max_dump_size_mb > 1024) {
        validation_errors_.push_back(L"max_dump_size_mb must be between 1 and 1024");
    }

    const bool any_module_enabled = config_.accounts.enabled || config_.services.enabled ||
                                    config_.processes.enabled || config_.network.enabled ||
                                    config_.registry.enabled || config_.memory.enabled ||
                                    config_.privesc.enabled;
    if (!any_module_enabled) {
        validation_errors_.push_back(L"At least one module must be enabled");
    }

    const bool any_output_enabled = config_.output.generate_json || config_.output.generate_csv ||
                                    config_.output.generate_html;
    if (!any_output_enabled) {
        validation_errors_.push_back(L"At least one output format must be enabled");
    }

    return validation_errors_.empty();
}

StringVector ConfigManager::GetValidationErrors() const {
    return validation_errors_;
}

}
}
