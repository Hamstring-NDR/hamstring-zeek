#include "ZeekAnalysisHandler.hpp"
#include "ZeekConfigHandler.hpp"

#include <cxxopts.hpp>
#include <filesystem>
#include <iostream>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;

/// Back up or restore the default Zeek configuration file.
///
/// Due to how ZeekConfigurationHandler works, the configuration is *appended*
/// to local.zeek and node.cfg. If the Docker container is stopped and started
/// again (e.g., `docker restart`), the writable container layer is preserved.
/// Without this backup logic, appending to the same configuration files a second
/// time upon restart would result in duplicate configurations and cause Zeek to fail.
///
/// On first run (no backup exists), this copies the pristine config to a backup location.
/// On subsequent runs, it restores the backup to ensure a clean slate before configuring.
static void manageConfigBackup(const fs::path &config_path, const fs::path &backup_path) {
    bool initial_setup = !fs::exists(backup_path);
    spdlog::info("Initial setup: {}", initial_setup);

    if (initial_setup) {
        spdlog::info("Backing up default config");
        if (fs::exists(config_path)) {
            fs::copy_file(config_path, backup_path, fs::copy_options::overwrite_existing);
        }
    } else {
        spdlog::info("Restoring default config from backup");
        fs::copy_file(backup_path, config_path, fs::copy_options::overwrite_existing);
    }
}

int main(int argc, char **argv) {
    cxxopts::Options options("hamstring_zeek", "Configure and start Zeek analysis based on pipeline configuration.");

    // clang-format off
    options.add_options()
        ("c,config", "Path to the configuration file", cxxopts::value<std::string>())
        ("zeek-config-location", "Override the default Zeek config location", cxxopts::value<std::string>())
        ("i,interface", "Start Zeek in network analysis mode on this interface", cxxopts::value<std::string>())
        ("f,file", "Path to a PCAP file for static analysis", cxxopts::value<std::string>())
        ("h,help", "Print usage");
    // clang-format on

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    if (!result.count("config")) {
        spdlog::error("Option --config is required.");
        return 1;
    }

    if (result.count("interface") && result.count("file")) {
        spdlog::error("Options --interface and --file are mutually exclusive.");
        return 1;
    }

    const fs::path config_file          = result["config"].as<std::string>();
    const fs::path zeek_config_location = result.count("zeek-config-location")
                                              ? fs::path(result["zeek-config-location"].as<std::string>())
                                              : fs::path("/usr/local/zeek/share/zeek/site/local.zeek");

    const fs::path backup_path = "/opt/local.zeek_backup";

    // --- Back up / restore Zeek config ---
    try {
        manageConfigBackup(zeek_config_location, backup_path);
    } catch (const fs::filesystem_error &e) {
        spdlog::error("Filesystem error during backup/restore: {}", e.what());
        return 1;
    }

    // --- Load YAML config ---
    YAML::Node config_node;
    try {
        config_node = YAML::LoadFile(config_file.string());
    } catch (const YAML::Exception &e) {
        spdlog::error("Error parsing config file. Is this proper YAML? Error: {}", e.what());
        return 1;
    }

    // --- Configure and run ---
    try {
        // Resolve CLI overrides
        std::optional<std::string> interface_override =
            result.count("interface") ? std::optional(result["interface"].as<std::string>()) : std::nullopt;
        bool pcap_override = result.count("file") > 0;

        ZeekConfigurationHandler configHandler(config_node, zeek_config_location, interface_override, pcap_override);
        configHandler.configure();
        spdlog::info("Configured Zeek");

        fs::path pcap_file = result.count("file") ? fs::path(result["file"].as<std::string>()) : fs::path{};

        ZeekAnalysisHandler analysisHandler(zeek_config_location, configHandler.getZeekLogLocation(),
                                            std::make_shared<PosixCommandExecutor>(), pcap_file);

        spdlog::info("Starting analysis...");
        analysisHandler.startAnalysis(configHandler.getAnalysisMode());

    } catch (const std::exception &e) {
        spdlog::error("Error during execution: {}", e.what());
        return 1;
    }

    return 0;
}
