#include "ZeekAnalysisHandler.hpp"
#include "ZeekConfigHandler.hpp"

#include <cxxopts.hpp>
#include <filesystem>
#include <iostream>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;

int main(int argc, char **argv) {
    cxxopts::Options options("hamstring_zeek", "Configure and start Zeek analysis based on pipeline configuration.");

    options.add_options()("c,config", "Path to the configuration file location", cxxopts::value<std::string>())(
        "zeek-config-location", "Overrides the default configuration location of Zeek", cxxopts::value<std::string>())(
        "i,interface", "Starts Zeek in network analysis mode on the specified interface",
        cxxopts::value<std::string>())("f,file", "Absolute path to one pcap file",
                                       cxxopts::value<std::string>())("h,help", "Print usage");

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

    std::string config_file          = result["config"].as<std::string>();
    std::string zeek_config_location = "/usr/local/zeek/share/zeek/site/local.zeek";
    if (result.count("zeek-config-location")) {
        zeek_config_location = result["zeek-config-location"].as<std::string>();
    }

    std::string default_zeek_config_backup_location = "/opt/local.zeek_backup";
    bool        initial_zeek_setup                  = !fs::exists(default_zeek_config_backup_location);

    spdlog::info("initial setup: {}", initial_zeek_setup);

    try {
        if (initial_zeek_setup) {
            spdlog::info("Backup default config");
            if (fs::exists(zeek_config_location)) {
                fs::copy_file(zeek_config_location, default_zeek_config_backup_location,
                              fs::copy_options::overwrite_existing);
            }
        } else {
            spdlog::info("Restore default config");
            if (fs::exists(default_zeek_config_backup_location)) {
                fs::copy_file(default_zeek_config_backup_location, zeek_config_location,
                              fs::copy_options::overwrite_existing);
            }
        }
    } catch (const fs::filesystem_error &e) {
        spdlog::error("Filesystem error during backup/restore: {}", e.what());
        return 1;
    }

    YAML::Node config_node;
    try {
        config_node = YAML::LoadFile(config_file);
    } catch (const YAML::Exception &e) {
        spdlog::error("Error parsing the config file. Is this proper yaml? Error: {}", e.what());
        return 1;
    }

    try {
        ZeekConfigurationHandler configHandler(config_node, zeek_config_location);

        if (result.count("interface")) {
            configHandler.setAnalysisStatic(false);
            configHandler.setNetworkInterfaces({result["interface"].as<std::string>()});
        } else if (result.count("file")) {
            configHandler.setAnalysisStatic(true);
        }

        configHandler.configure();
        spdlog::info("configured zeek");

        std::string pcap_file = result.count("file") ? result["file"].as<std::string>() : "";

        ZeekAnalysisHandler analysisHandler(zeek_config_location, configHandler.getZeekLogLocation(), pcap_file);

        spdlog::info("starting analysis...");
        analysisHandler.startAnalysis(configHandler.isAnalysisStatic());

    } catch (const std::exception &e) {
        spdlog::error("Error during execution: {}", e.what());
        return 1;
    }

    return 0;
}
