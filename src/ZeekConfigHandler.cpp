#include "ZeekConfigHandler.hpp"
#include "string_utils.hpp"

#include <cstdlib>
#include <fstream>
#include <stdexcept>

ZeekConfigurationHandler::ZeekConfigurationHandler(const YAML::Node                 &config_node,
                                                   const fs::path                   &zeek_config_location,
                                                   const std::optional<std::string> &interface_override,
                                                   bool                              pcap_override,
                                                   const fs::path                   &zeek_node_config_template,
                                                   const fs::path                   &zeek_log_location,
                                                   const fs::path                   &additional_configurations)
    : base_config_location_(zeek_config_location),
      additional_configurations_(additional_configurations),
      zeek_node_config_template_(zeek_node_config_template),
      zeek_log_location_(zeek_log_location) {

    spdlog::info("Setting up Zeek configuration...");

    // --- Resolve container name from environment ---
    const char *container_env = std::getenv("CONTAINER_NAME");
    if (container_env == nullptr) {
        throw std::runtime_error("CONTAINER_NAME env variable not found. Aborting configuration.");
    }
    container_name_ = container_env;

    // --- Parse environment section ---
    auto env_node = config_node["environment"];
    if (!env_node) {
        throw std::runtime_error("Missing 'environment' section in config.");
    }

    for (const auto &broker : env_node["kafka_brokers"]) {
        auto ip   = broker["node_ip"].as<std::string>();
        auto port = broker["external_port"].as<std::string>();
        kafka_brokers_.push_back(ip + ":" + port);
    }

    kafka_topic_prefix_ = env_node["kafka_topics_prefix"]["pipeline"]["logserver_in"].as<std::string>();

    // --- Parse sensor-specific configuration ---
    auto sensor_config = config_node["pipeline"]["zeek"]["sensors"][container_name_];
    if (!sensor_config) {
        throw std::runtime_error("No sensor configuration found for container: " + container_name_);
    }

    for (const auto &proto : sensor_config["protocols"]) {
        configured_protocols_.push_back(proto.as<std::string>());
    }

    // --- Determine analysis mode (CLI overrides take precedence over YAML) ---
    if (interface_override.has_value()) {
        analysis_mode_      = AnalysisMode::Network;
        network_interfaces_ = {interface_override.value()};
    } else if (pcap_override) {
        analysis_mode_ = AnalysisMode::Static;
    } else if (sensor_config["static_analysis"] && sensor_config["static_analysis"].as<bool>()) {
        analysis_mode_ = AnalysisMode::Static;
    } else {
        analysis_mode_ = AnalysisMode::Network;
        if (!sensor_config["interfaces"] || sensor_config["interfaces"].size() == 0) {
            throw std::runtime_error(
                "Analysis mode is 'network' but no 'interfaces' specified for sensor: " + container_name_);
        }
        for (const auto &iface : sensor_config["interfaces"]) {
            network_interfaces_.push_back(iface.as<std::string>());
        }
    }

    spdlog::info("Successfully parsed config.yaml (mode={})",
                 analysis_mode_ == AnalysisMode::Static ? "static" : "network");
}

void ZeekConfigurationHandler::configure() const {
    spdlog::info("Configuring Zeek...");
    if (analysis_mode_ == AnalysisMode::Network) {
        templateAndCopyNodeConfig();
    }
    appendAdditionalConfigurations();
    createPluginConfiguration();
}

void ZeekConfigurationHandler::appendAdditionalConfigurations() const {
    std::ofstream base_config(base_config_location_, std::ios_base::app);
    if (!base_config.is_open()) {
        spdlog::error("Could not open for appending: {}", base_config_location_.string());
        return;
    }

    base_config << "\n";

    if (fs::exists(additional_configurations_) && fs::is_directory(additional_configurations_)) {
        for (const auto &entry : fs::directory_iterator(additional_configurations_)) {
            if (entry.path().extension() == ".zeek") {
                std::ifstream add_conf(entry.path());
                if (add_conf.is_open()) {
                    base_config << add_conf.rdbuf() << "\n";
                }
            }
        }
    }
}

void ZeekConfigurationHandler::createPluginConfiguration() const {
    std::ofstream base_config(base_config_location_, std::ios_base::app);
    if (!base_config.is_open()) {
        spdlog::error("Could not open for Kafka config: {}", base_config_location_.string());
        return;
    }

    base_config << "@load packages/zeek-kafka\n"
                << "redef Kafka::topic_name = \"\";\n"
                << "redef Kafka::kafka_conf = table(\n"
                << "  [\"metadata.broker.list\"] = \"" << utils::joinStrings(kafka_brokers_, ",") << "\");\n"
                << "redef Kafka::tag_json = F;\n"
                << "event zeek_init() &priority=-10\n"
                << "{\n";

    for (const auto &protocol : configured_protocols_) {
        auto lower = utils::toLower(protocol);
        auto upper = utils::toUpper(protocol);

        auto topic_name       = kafka_topic_prefix_ + "-" + lower;
        auto log_format       = "Custom" + upper;
        auto kafka_writer     = lower + "_filter";

        base_config << "    local " << kafka_writer << ": Log::Filter = [\n"
                    << "        $name = \"kafka-" << kafka_writer << "\",\n"
                    << "        $writer = Log::WRITER_KAFKAWRITER,\n"
                    << "        $path = \"" << topic_name << "\"\n"
                    << "    ];\n"
                    << "    Log::add_filter(" << log_format << "::LOG, " << kafka_writer << ");\n\n";
    }

    base_config << "}\n";
    spdlog::info("Wrote Kafka Zeek plugin configuration to file");
}

void ZeekConfigurationHandler::writeWorkerConfigurations(std::ostream &out) const {
    for (const auto &iface : network_interfaces_) {
        out << "[zeek-" << iface << "]\n"
            << "type=worker\n"
            << "host=localhost\n";
    }
}

void ZeekConfigurationHandler::templateAndCopyNodeConfig() const {
    try {
        if (fs::exists(zeek_node_config_template_)) {
            fs::copy_file(zeek_node_config_template_, zeek_node_config_path_, fs::copy_options::overwrite_existing);
        } else {
            spdlog::warn("Node config template not found: {}", zeek_node_config_template_.string());
        }
    } catch (const fs::filesystem_error &e) {
        spdlog::error("File copy error: {}", e.what());
        return;
    }

    std::ofstream node_cfg(zeek_node_config_path_, std::ios_base::app);
    if (!node_cfg.is_open()) {
        spdlog::error("Could not append to node config: {}", zeek_node_config_path_.string());
        return;
    }

    writeWorkerConfigurations(node_cfg);
}
