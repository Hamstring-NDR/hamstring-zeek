#pragma once

#include "CommandExecutor.hpp"
#include "ZeekConfigHandler.hpp"

#include <filesystem>
#include <memory>
#include <string>

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
    ZeekAnalysisHandler(const fs::path              &zeek_config_location,
                        const fs::path              &zeek_log_location,
                        std::shared_ptr<ICommandExecutor> executor = std::make_shared<PosixCommandExecutor>(),
                        const fs::path              &pcap_file     = "");

    /// Start analysis in the given mode.
    void startAnalysis(AnalysisMode mode);

  private:
    void startStaticAnalysis();
    void startNetworkAnalysis();

    fs::path                         zeek_config_location_;
    fs::path                         zeek_log_location_;
    fs::path                         pcap_file_;
    fs::path                         static_files_dir_;
    std::shared_ptr<ICommandExecutor> executor_;
};
