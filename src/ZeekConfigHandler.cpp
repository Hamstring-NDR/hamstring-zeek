#include "ZeekConfigHandler.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

ZeekConfigurationHandler::ZeekConfigurationHandler(const YAML::Node  &config_node,
                                                   const std::string &zeek_config_location,
                                                   const std::string &zeek_node_config_template,
                                                   const std::string &zeek_log_location,
                                                   const std::string &additional_configurations)
    : base_config_location(zeek_config_location), additional_configurations(additional_configurations),
      zeek_node_config_template(zeek_node_config_template), zeek_node_config_path("/usr/local/zeek/etc/node.cfg"),
      zeek_log_location(zeek_log_location) {
    spdlog::info("Setting up Zeek configuration...");

    const char *container_env = std::getenv("CONTAINER_NAME");
    if (!container_env) {
        spdlog::error("CONTAINER_NAME ENV variable could not be found. Aborting "
                      "configuration...");
        throw std::runtime_error("CONTAINER_NAME env. variable not found.");
    }
    container_name = container_env;

    auto env_node = config_node["environment"];
    if (!env_node) {
        throw std::runtime_error("Missing 'environment' section in config.");
    }

    auto brokers_node = env_node["kafka_brokers"];
    for (const auto &broker : brokers_node) {
        std::string ip   = broker["node_ip"].as<std::string>();
        std::string port = broker["external_port"].as<std::string>();
        kafka_brokers.push_back(ip + ":" + port);
    }

    kafka_topic_prefix = env_node["kafka_topics_prefix"]["pipeline"]["logserver_in"].as<std::string>();

    auto pipeline_node = config_node["pipeline"];
    auto sensors_node  = pipeline_node["zeek"]["sensors"];
    auto sensor_config = sensors_node[container_name];

    if (!sensor_config) {
        throw std::runtime_error("No sensor configuration found for " + container_name);
    }

    if (sensor_config["static_analysis"] && sensor_config["static_analysis"].as<bool>()) {
        is_analysis_static = true;
    } else {
        is_analysis_static = false;
        try {
            for (const auto &iface : sensor_config["interfaces"]) {
                network_interfaces.push_back(iface.as<std::string>());
            }
        } catch (const std::exception &e) {
            spdlog::error("Could not parse configuration for zeek sensor, "
                          "'interfaces' parameter missing or invalid: {}",
                          e.what());
        }
    }

    for (const auto &proto : sensor_config["protocols"]) {
        configured_protocols.push_back(proto.as<std::string>());
    }

    spdlog::info("Successfully parsed config.yaml");
}

void ZeekConfigurationHandler::configure() {
    spdlog::info("configuring Zeek...");
    if (!is_analysis_static) {
        templateAndCopyNodeConfig();
    }
    appendAdditionalConfigurations();
    createPluginConfiguration();
}

void ZeekConfigurationHandler::appendAdditionalConfigurations() {
    std::ofstream base_config(base_config_location, std::ios_base::app);
    if (!base_config.is_open()) {
        spdlog::error("Could not open base_config_location for appending: {}", base_config_location);
        return;
    }

    base_config << "\n";

    if (fs::exists(additional_configurations) && fs::is_directory(additional_configurations)) {
        for (const auto &entry : fs::directory_iterator(additional_configurations)) {
            if (entry.path().extension() == ".zeek") {
                std::ifstream add_conf(entry.path());
                if (add_conf.is_open()) {
                    base_config << add_conf.rdbuf() << "\n";
                }
            }
        }
    }
}

void ZeekConfigurationHandler::createPluginConfiguration() {
    std::ofstream base_config(base_config_location, std::ios_base::app);
    if (!base_config.is_open()) {
        spdlog::error("Could not open base_config_location for kafka config: {}", base_config_location);
        return;
    }

    base_config << "@load packages/zeek-kafka\n"
                << "redef Kafka::topic_name = \"\";\n"
                << "redef Kafka::kafka_conf = table(\n"
                << "  [\"metadata.broker.list\"] = \"";

    for (size_t i = 0; i < kafka_brokers.size(); ++i) {
        base_config << kafka_brokers[i];
        if (i < kafka_brokers.size() - 1)
            base_config << ",";
    }
    base_config << "\");\n";
    base_config << "redef Kafka::tag_json = F;\n"
                << "event zeek_init() &priority=-10\n"
                << "{\n";

    for (const auto &protocol : configured_protocols) {
        std::string lower_protocol = protocol;
        std::transform(lower_protocol.begin(), lower_protocol.end(), lower_protocol.begin(), ::tolower);
        std::string upper_protocol = protocol;
        std::transform(upper_protocol.begin(), upper_protocol.end(), upper_protocol.begin(), ::toupper);

        std::string topic_name               = kafka_topic_prefix + "-" + lower_protocol;
        std::string zeek_protocol_log_format = "Custom" + upper_protocol;
        std::string kafka_writer_name        = lower_protocol + "_filter";

        base_config << "    local " << kafka_writer_name << ": Log::Filter = [\n"
                    << "        $name = \"kafka-" << kafka_writer_name << "\",\n"
                    << "        $writer = Log::WRITER_KAFKAWRITER,\n"
                    << "        $path = \"" << topic_name << "\"\n"
                    << "    ];\n"
                    << "    Log::add_filter(" << zeek_protocol_log_format << "::LOG, " << kafka_writer_name << ");\n\n";
    }

    base_config << "}\n";
    spdlog::info("Wrote kafka zeek plugin configuration to file");
}

std::vector<std::string> ZeekConfigurationHandler::createWorkerConfigurationsForInterfaces() {
    std::vector<std::string> lines;
    for (const auto &iface : network_interfaces) {
        lines.push_back("[zeek-" + iface + "]\n");
        lines.push_back("type=worker\n");
        lines.push_back("host=localhost\n");
    }
    return lines;
}

void ZeekConfigurationHandler::templateAndCopyNodeConfig() {
    try {
        if (fs::exists(zeek_node_config_template)) {
            fs::copy_file(zeek_node_config_template, zeek_node_config_path, fs::copy_options::overwrite_existing);
        } else {
            spdlog::warn("Node config template not found: {}", zeek_node_config_template);
        }
    } catch (const fs::filesystem_error &e) {
        spdlog::error("File copy error: {}", e.what());
    }

    std::ofstream node_cfg(zeek_node_config_path, std::ios_base::app);
    if (!node_cfg.is_open()) {
        spdlog::error("Could not append to node config path: {}", zeek_node_config_path);
        return;
    }

    auto lines = createWorkerConfigurationsForInterfaces();
    for (const auto &line : lines) {
        node_cfg << line;
    }
}
