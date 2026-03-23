#include "ZeekAnalysisHandler.hpp"
#include <spdlog/spdlog.h>
#include <thread>
#include <vector>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <cstdio>
#include <array>

namespace fs = std::filesystem;

ZeekAnalysisHandler::ZeekAnalysisHandler(
    const std::string& zeek_config_location,
    const std::string& zeek_log_location,
    const std::string& pcap_file)
    : zeek_config_location(zeek_config_location),
      zeek_log_location(zeek_log_location),
      pcap_file(pcap_file)
{
    const char* env_dir = std::getenv("STATIC_FILES_DIR");
    if (env_dir) {
        static_files_dir = env_dir;
    } else {
        static_files_dir = "/opt/static_files";
    }
}

void ZeekAnalysisHandler::startAnalysis(bool is_static_analysis) {
    if (is_static_analysis) {
        spdlog::info("static analysis mode selected");
        startStaticAnalysis();
    } else {
        spdlog::info("network analysis mode selected");
        startNetworkAnalysis();
    }
}

void ZeekAnalysisHandler::startStaticAnalysis() {
    std::vector<std::string> files;
    
    if (!pcap_file.empty()) {
        files.push_back(pcap_file);
    } else {
        if (fs::exists(static_files_dir) && fs::is_directory(static_files_dir)) {
            for (const auto& entry : fs::directory_iterator(static_files_dir)) {
                if (entry.path().extension() == ".pcap") {
                    files.push_back(entry.path().string());
                }
            }
        }
    }

    std::vector<std::thread> threads;
    for (const auto& file : files) {
        spdlog::info("Starting Analysis for file {}...", file);
        threads.emplace_back([file, this]() {
            std::string command = "zeek -C -r " + file + " " + zeek_config_location;
            int ret = std::system(command.c_str());
            if (ret != 0) {
                spdlog::error("Zeek static analysis failed for file: {}", file);
            }
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    spdlog::info("Finished static analyses");
}

void ZeekAnalysisHandler::startNetworkAnalysis() {
    std::string start_zeek = "zeekctl deploy";
    spdlog::info("Deploying zeekctl...");
    int ret = std::system(start_zeek.c_str());
    if (ret != 0) {
        spdlog::error("zeekctl deploy failed!");
        return;
    }

    spdlog::info("network analysis started");

    // Replicating Python behavior: run tail -f /dev/null to keep container running
    std::thread reader_thread([]() {
        FILE* pipe = popen("tail -f /dev/null", "r");
        if (!pipe) {
            spdlog::error("Failed to start tail process");
            return;
        }
        std::array<char, 1024> buffer;
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            std::cout << "[ZEEK LOG] " << buffer.data();
        }
        pclose(pipe);
    });

    spdlog::info("network analysis ongoing");
    if (reader_thread.joinable()) {
        reader_thread.join();
    }
    
    spdlog::info("network analysis stopped");
}
