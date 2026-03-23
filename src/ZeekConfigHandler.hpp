#pragma once

#include <spdlog/spdlog.h>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

class ZeekConfigurationHandler {
  public:
    ZeekConfigurationHandler(const YAML::Node  &config_node,
                             const std::string &zeek_config_location = "/usr/local/zeek/share/zeek/site/local.zeek",
                             const std::string &zeek_node_config_template = "/opt/src/zeek/base_node.cfg",
                             const std::string &zeek_log_location         = "/usr/local/zeek/log/zeek.log",
                             const std::string &additional_configurations = "/opt/src/zeek/additional_configs/");

    void configure();

    bool isAnalysisStatic() const { return is_analysis_static; }
    void setAnalysisStatic(bool is_static) { is_analysis_static = is_static; }

    const std::vector<std::string> &getNetworkInterfaces() const { return network_interfaces; }
    void setNetworkInterfaces(const std::vector<std::string> &interfaces) { network_interfaces = interfaces; }

    std::string getZeekLogLocation() const { return zeek_log_location; }

  private:
    void                     appendAdditionalConfigurations();
    void                     createPluginConfiguration();
    std::vector<std::string> createWorkerConfigurationsForInterfaces();
    void                     templateAndCopyNodeConfig();

    std::string base_config_location;
    std::string additional_configurations;
    std::string zeek_node_config_template;
    std::string zeek_node_config_path;
    std::string zeek_log_location;
    std::string container_name;

    bool                     is_analysis_static;
    std::vector<std::string> network_interfaces;
    std::string              kafka_topic_prefix;
    std::vector<std::string> configured_protocols;
    std::vector<std::string> kafka_brokers;
};
