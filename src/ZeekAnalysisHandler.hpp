#pragma once

#include <string>
#include <vector>

class ZeekAnalysisHandler {
public:
    ZeekAnalysisHandler(
        const std::string& zeek_config_location,
        const std::string& zeek_log_location,
        const std::string& pcap_file = ""
    );

    void startAnalysis(bool is_static_analysis);

private:
    void startStaticAnalysis();
    void startNetworkAnalysis();

    std::string zeek_config_location;
    std::string zeek_log_location;
    std::string pcap_file;
    std::string static_files_dir;
};
