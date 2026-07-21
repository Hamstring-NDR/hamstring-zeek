#pragma once

#include "CommandExecutor.hpp"
#include "ZeekConfigHandler.hpp"

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;

/// Handles the execution of Zeek analysis in either static or network analysis mode.
///
/// Uses an injected ICommandExecutor for running system commands, enabling
/// unit testing without actual process execution.
class ZeekAnalysisHandler {
  public:
    /// @param zeek_config_location  Path to the Zeek configuration file.
    /// @param zeek_log_location     Path where Zeek writes its logs.
    /// @param executor              Command executor (defaults to PosixCommandExecutor).
    /// @param pcap_file             Optional path to a single PCAP file for static analysis.
    /// @param kafka_brokers         Kafka broker endpoints to wait for before starting Zeek.
    ZeekAnalysisHandler(const fs::path &zeek_config_location, const fs::path &zeek_log_location,
                        std::shared_ptr<ICommandExecutor> executor = std::make_shared<PosixCommandExecutor>(),
                        const fs::path &pcap_file = "", std::vector<std::string> kafka_brokers = {});

    /// Start analysis in the given mode.
    void startAnalysis(AnalysisMode mode);

  private:
    void startStaticAnalysis();
    void startNetworkAnalysis();
    bool areKafkaBrokersReachable() const;
    bool deployZeekctl() const;
    bool waitForKafkaBrokers(const std::atomic_bool *stop_requested = nullptr) const;
    bool waitForIntervalOrStop(const std::atomic_bool &stop_requested, int interval_seconds) const;

    fs::path                          zeek_config_location_;
    fs::path                          zeek_log_location_;
    fs::path                          pcap_file_;
    fs::path                          static_files_dir_;
    std::shared_ptr<ICommandExecutor> executor_;
    std::vector<std::string>          kafka_brokers_;
    int                               kafka_wait_interval_seconds_{5};
    int                               kafka_outage_threshold_seconds_{15};
    int                               kafka_recovery_stability_seconds_{30};
};
