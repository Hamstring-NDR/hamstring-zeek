#pragma once

#include <filesystem>
#include <optional>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;

/// Represents the analysis mode for a Zeek sensor.
enum class AnalysisMode { Static, Network };

/// Handles the configuration of Zeek sensors based on the pipeline configuration.
///
/// This class is responsible for setting up Zeek to process network traffic according
/// to the specified configuration. It configures the Zeek Kafka plugin, sets up worker
/// nodes for network interfaces, and integrates additional custom configurations.
///
/// The handler is immutable after construction — the constructor resolves all config
/// values including CLI overrides. Call `configure()` to write the Zeek config files.
class ZeekConfigurationHandler {
  public:
    /// Construct a ZeekConfigurationHandler from a YAML config and optional CLI overrides.
    ///
    /// @param config_node                 Parsed YAML config root node.
    /// @param zeek_config_location        Path to the main Zeek config file (local.zeek).
    /// @param interface_override          CLI override: force network analysis on this interface.
    /// @param pcap_override               CLI override: force static analysis (presence implies static mode).
    /// @param zeek_node_config_template   Template for node.cfg.
    /// @param zeek_log_location           Path where Zeek writes logs.
    /// @param additional_configurations   Directory with extra .zeek config files.
    ///
    /// @throws std::runtime_error  If CONTAINER_NAME env var is missing, sensor config is
    ///                             not found, or required fields (interfaces) are absent.
    ZeekConfigurationHandler(const YAML::Node &config_node,
                             const fs::path   &zeek_config_location = "/usr/local/zeek/share/zeek/site/local.zeek",
                             const std::optional<std::string> &interface_override = std::nullopt,
                             bool                              pcap_override      = false,
                             const fs::path &zeek_node_config_template            = "/opt/src/zeek/base_node.cfg",
                             const fs::path &zeek_log_location                    = "/usr/local/zeek/log/zeek.log",
                             const fs::path &additional_configurations = "/opt/src/zeek/additional_configs/");

    /// Execute the complete Zeek configuration: node config, additional configs, and Kafka plugin.
    void configure() const;

    [[nodiscard]] AnalysisMode                    getAnalysisMode() const { return analysis_mode_; }
    [[nodiscard]] const fs::path                 &getZeekLogLocation() const { return zeek_log_location_; }
    [[nodiscard]] const std::vector<std::string> &getNetworkInterfaces() const { return network_interfaces_; }

  private:
    void appendAdditionalConfigurations() const;
    void createPluginConfiguration() const;
    void writeWorkerConfigurations(std::ostream &out) const;
    void templateAndCopyNodeConfig() const;

    fs::path    base_config_location_;
    fs::path    additional_configurations_;
    fs::path    zeek_node_config_template_;
    fs::path    zeek_node_config_path_{"/usr/local/zeek/etc/node.cfg"};
    fs::path    zeek_log_location_;
    std::string container_name_;

    AnalysisMode             analysis_mode_{AnalysisMode::Static};
    std::vector<std::string> network_interfaces_;
    std::string              kafka_topic_prefix_;
    std::vector<std::string> configured_protocols_;
    std::vector<std::string> kafka_brokers_;
};
