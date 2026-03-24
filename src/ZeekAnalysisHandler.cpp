#include "ZeekAnalysisHandler.hpp"

#include <csignal>
#include <cstdlib>
#include <spdlog/spdlog.h>
#include <thread>
#include <vector>

ZeekAnalysisHandler::ZeekAnalysisHandler(const fs::path                   &zeek_config_location,
                                         const fs::path                   &zeek_log_location,
                                         std::shared_ptr<ICommandExecutor> executor,
                                         const fs::path                   &pcap_file)
    : zeek_config_location_(zeek_config_location),
      zeek_log_location_(zeek_log_location),
      pcap_file_(pcap_file),
      executor_(std::move(executor)) {

    const char *env_dir = std::getenv("STATIC_FILES_DIR");
    static_files_dir_   = env_dir ? fs::path(env_dir) : fs::path("/opt/static_files");
}

void ZeekAnalysisHandler::startAnalysis(AnalysisMode mode) {
    if (mode == AnalysisMode::Static) {
        spdlog::info("Static analysis mode selected");
        startStaticAnalysis();
    } else {
        spdlog::info("Network analysis mode selected");
        startNetworkAnalysis();
    }
}

void ZeekAnalysisHandler::startStaticAnalysis() {
    std::vector<fs::path> files;

    if (!pcap_file_.empty()) {
        files.push_back(pcap_file_);
    } else if (fs::exists(static_files_dir_) && fs::is_directory(static_files_dir_)) {
        for (const auto &entry : fs::directory_iterator(static_files_dir_)) {
            if (entry.path().extension() == ".pcap") {
                files.push_back(entry.path());
            }
        }
    }

    std::vector<std::thread> threads;
    threads.reserve(files.size());

    for (const auto &file : files) {
        spdlog::info("Starting analysis for file {}...", file.string());
        threads.emplace_back([this, file]() {
            std::vector<std::string> args = {"zeek", "-C", "-r", file.string(), zeek_config_location_.string()};
            int ret = executor_->execute(args);
            if (ret != 0) {
                spdlog::error("Zeek static analysis failed for file: {} (exit code {})", file.string(), ret);
            }
        });
    }

    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    spdlog::info("Finished static analyses");
}

void ZeekAnalysisHandler::startNetworkAnalysis() {
    spdlog::info("Deploying zeekctl...");
    int ret = executor_->execute({"zeekctl", "deploy"});
    if (ret != 0) {
        spdlog::error("zeekctl deploy failed (exit code {})", ret);
        return;
    }

    spdlog::info("Network analysis started");

    // Block until a shutdown signal is received (e.g. docker stop sending SIGTERM).
    // Uses sigwait() on a dedicated thread instead of std::signal() + global state,
    // which has undefined behavior when mixed with C++ threading primitives.
    sigset_t wait_set;
    sigemptyset(&wait_set);
    sigaddset(&wait_set, SIGINT);
    sigaddset(&wait_set, SIGTERM);

    // Block these signals in the current thread so sigwait can catch them
    pthread_sigmask(SIG_BLOCK, &wait_set, nullptr);

    spdlog::info("Network analysis ongoing — waiting for shutdown signal...");

    int sig = 0;
    sigwait(&wait_set, &sig);

    spdlog::info("Received signal {}. Stopping Zeek...", sig);
    executor_->execute({"zeekctl", "stop"});

    spdlog::info("Network analysis stopped");
}
