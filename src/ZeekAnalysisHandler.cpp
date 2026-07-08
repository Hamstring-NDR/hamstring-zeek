#include "ZeekAnalysisHandler.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <netdb.h>
#include <spdlog/fmt/ranges.h>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

struct BrokerEndpoint {
    std::string host;
    std::string port;
};

BrokerEndpoint parseBrokerEndpoint(const std::string &endpoint) {
    auto separator = endpoint.rfind(':');
    if (separator == std::string::npos || separator == 0 || separator == endpoint.size() - 1) {
        throw std::runtime_error("Invalid Kafka broker endpoint: " + endpoint);
    }
    return {endpoint.substr(0, separator), endpoint.substr(separator + 1)};
}

int parsePositiveEnvInt(const char *name, int default_value) {
    const char *value = std::getenv(name);
    if (value == nullptr || std::strlen(value) == 0) {
        return default_value;
    }

    try {
        int parsed = std::stoi(value);
        return std::max(1, parsed);
    } catch (const std::exception &) {
        spdlog::warn("Ignoring invalid integer value '{}' for {}", value, name);
        return default_value;
    }
}

bool connectWithTimeout(const addrinfo *addr, int timeout_seconds) {
    int fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (fd < 0) {
        return false;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return false;
    }

    int ret = connect(fd, addr->ai_addr, addr->ai_addrlen);
    if (ret == 0) {
        close(fd);
        return true;
    }

    if (errno != EINPROGRESS) {
        close(fd);
        return false;
    }

    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(fd, &write_set);

    timeval timeout{};
    timeout.tv_sec = timeout_seconds;

    ret = select(fd + 1, nullptr, &write_set, nullptr, &timeout);
    if (ret <= 0) {
        close(fd);
        return false;
    }

    int       socket_error = 0;
    socklen_t len          = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) != 0) {
        close(fd);
        return false;
    }

    close(fd);
    return socket_error == 0;
}

bool canConnectToBroker(const std::string &endpoint) {
    BrokerEndpoint broker = parseBrokerEndpoint(endpoint);

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    addrinfo *results = nullptr;
    int       ret     = getaddrinfo(broker.host.c_str(), broker.port.c_str(), &hints, &results);
    if (ret != 0) {
        spdlog::debug("Kafka broker {} is not resolvable yet: {}", endpoint, gai_strerror(ret));
        return false;
    }

    bool connected = false;
    for (auto *addr = results; addr != nullptr; addr = addr->ai_next) {
        if (connectWithTimeout(addr, 2)) {
            connected = true;
            break;
        }
    }

    freeaddrinfo(results);
    return connected;
}

} // namespace

ZeekAnalysisHandler::ZeekAnalysisHandler(const fs::path &zeek_config_location, const fs::path &zeek_log_location,
                                         std::shared_ptr<ICommandExecutor> executor, const fs::path &pcap_file,
                                         std::vector<std::string> kafka_brokers)
    : zeek_config_location_(zeek_config_location), zeek_log_location_(zeek_log_location), pcap_file_(pcap_file),
      executor_(std::move(executor)), kafka_brokers_(std::move(kafka_brokers)) {

    const char *env_dir = std::getenv("STATIC_FILES_DIR");
    static_files_dir_   = env_dir ? fs::path(env_dir) : fs::path("/opt/static_files");

    kafka_wait_interval_seconds_ = parsePositiveEnvInt("HAMSTRING_ZEEK_KAFKA_WAIT_INTERVAL_SECONDS", 5);
}

void ZeekAnalysisHandler::startAnalysis(AnalysisMode mode) {
    waitForKafkaBrokers();

    if (mode == AnalysisMode::Static) {
        spdlog::info("Static analysis mode selected");
        startStaticAnalysis();
    } else {
        spdlog::info("Network analysis mode selected");
        startNetworkAnalysis();
    }
}

bool ZeekAnalysisHandler::areKafkaBrokersReachable() const {
    if (kafka_brokers_.empty()) {
        return true;
    }

    for (const auto &broker : kafka_brokers_) {
        try {
            if (!canConnectToBroker(broker)) {
                return false;
            }
        } catch (const std::exception &e) {
            spdlog::warn("Kafka broker readiness check failed for {}: {}", broker, e.what());
            return false;
        }
    }

    return true;
}

bool ZeekAnalysisHandler::waitForKafkaBrokers(const std::atomic_bool *stop_requested) const {
    if (kafka_brokers_.empty()) {
        spdlog::warn("No Kafka brokers configured for readiness checks. Starting Zeek without waiting for Kafka.");
        return true;
    }

    spdlog::info("Waiting for Kafka brokers: {}", fmt::join(kafka_brokers_, ", "));

    while (true) {
        if (stop_requested != nullptr && stop_requested->load()) {
            spdlog::info("Kafka wait interrupted by shutdown request.");
            return false;
        }

        std::vector<std::string> unavailable;

        for (const auto &broker : kafka_brokers_) {
            try {
                if (!canConnectToBroker(broker)) {
                    unavailable.push_back(broker);
                }
            } catch (const std::exception &e) {
                spdlog::warn("Kafka broker readiness check failed for {}: {}", broker, e.what());
                unavailable.push_back(broker);
            }
        }

        if (unavailable.empty()) {
            spdlog::info("Kafka brokers are reachable.");
            return true;
        }

        spdlog::warn("Kafka brokers not reachable yet: {}. Retrying in {} seconds.", fmt::join(unavailable, ", "),
                     kafka_wait_interval_seconds_);
        for (int slept = 0; slept < kafka_wait_interval_seconds_; ++slept) {
            if (stop_requested != nullptr && stop_requested->load()) {
                spdlog::info("Kafka wait interrupted by shutdown request.");
                return false;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
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

    for (const auto &file : files) {
        while (true) {
            waitForKafkaBrokers();

            spdlog::info("Starting analysis for file {}...", file.string());
            std::vector<std::string> args = {"zeek", "-C", "-r", file.string(), zeek_config_location_.string()};
            int                      ret  = executor_->execute(args);
            if (ret == 0) {
                break;
            }

            if (areKafkaBrokersReachable()) {
                spdlog::error("Zeek static analysis failed for file: {} (exit code {})", file.string(), ret);
                break;
            }

            spdlog::warn("Zeek static analysis failed while Kafka was unreachable for file: {} (exit code {}). "
                         "Waiting for Kafka and retrying the same file.",
                         file.string(), ret);
        }
    }

    spdlog::info("Finished static analyses");
}

bool ZeekAnalysisHandler::deployZeekctl() const {
    spdlog::info("Deploying zeekctl...");
    int ret = executor_->execute({"zeekctl", "deploy"});
    if (ret != 0) {
        spdlog::error("zeekctl deploy failed (exit code {})", ret);
        return false;
    }

    spdlog::info("Network analysis started");
    return true;
}

void ZeekAnalysisHandler::startNetworkAnalysis() {
    if (!deployZeekctl()) {
        return;
    }

    // Block until a shutdown signal is received (e.g. docker stop sending SIGTERM).
    // Uses sigwait() on a dedicated thread instead of std::signal() + global state,
    // which has undefined behavior when mixed with C++ threading primitives.
    sigset_t wait_set;
    sigemptyset(&wait_set);
    sigaddset(&wait_set, SIGINT);
    sigaddset(&wait_set, SIGTERM);

    // Block these signals in the current thread so sigwait can catch them
    pthread_sigmask(SIG_BLOCK, &wait_set, nullptr);

    std::atomic_bool stop_monitor{false};
    std::thread      kafka_monitor([this, &stop_monitor]() {
        bool kafka_was_reachable = true;

        while (!stop_monitor.load()) {
            for (int slept = 0; slept < kafka_wait_interval_seconds_; ++slept) {
                if (stop_monitor.load()) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (areKafkaBrokersReachable()) {
                if (!kafka_was_reachable) {
                    spdlog::info("Kafka brokers are reachable again while Zeek network analysis is running.");
                    kafka_was_reachable = true;
                }
                continue;
            }

            if (kafka_was_reachable) {
                spdlog::warn("Kafka became unreachable while Zeek network analysis is running. Zeek will keep "
                             "capturing; Kafka delivery depends on the Zeek Kafka writer retrying successfully.");
                kafka_was_reachable = false;
            } else {
                spdlog::warn("Kafka is still unreachable while Zeek network analysis is running.");
            }
        }
    });

    spdlog::info("Network analysis ongoing — waiting for shutdown signal...");

    int sig = 0;
    sigwait(&wait_set, &sig);

    spdlog::info("Received signal {}. Stopping Zeek...", sig);
    stop_monitor.store(true);
    if (kafka_monitor.joinable()) {
        kafka_monitor.join();
    }
    executor_->execute({"zeekctl", "stop"});

    spdlog::info("Network analysis stopped");
}
