#include "ZeekLogTransport.hpp"

#include "string_utils.hpp"

#include <stdexcept>

namespace {

/// Configures https://github.com/SeisoLLC/zeek-kafka.
class KafkaZeekLogTransport final : public IZeekLogTransport {
  public:
    KafkaZeekLogTransport(std::vector<std::string> brokers, std::string topic_prefix)
        : brokers_(std::move(brokers)), topic_prefix_(std::move(topic_prefix)) {}

    void writePluginConfiguration(std::ostream &out, const std::vector<std::string> &protocols) const override {
        out << "@load packages/zeek-kafka\n"
            << "redef Kafka::topic_name = \"\";\n"
            << "redef Kafka::kafka_conf = table(\n"
            << "  [\"metadata.broker.list\"] = \"" << utils::joinStrings(brokers_, ",") << "\",\n"
            << "  [\"socket.keepalive.enable\"] = \"true\",\n"
            << "  [\"reconnect.backoff.ms\"] = \"1000\",\n"
            << "  [\"reconnect.backoff.max.ms\"] = \"10000\",\n"
            << "  [\"message.send.max.retries\"] = \"10000000\",\n"
            << "  [\"retry.backoff.ms\"] = \"1000\",\n"
            << "  [\"message.timeout.ms\"] = \"0\");\n"
            << "redef Kafka::tag_json = F;\n"
            << "event zeek_init() &priority=-10\n"
            << "{\n";

        for (const auto &protocol : protocols) {
            const auto lower = utils::toLower(protocol);
            const auto upper = utils::toUpper(protocol);

            const auto topic_name  = topic_prefix_ + "-" + lower;
            const auto log_id      = "Custom" + upper;
            const auto writer_name = lower + "_filter";

            out << "    local " << writer_name << ": Log::Filter = [\n"
                << "        $name = \"kafka-" << writer_name << "\",\n"
                << "        $writer = Log::WRITER_KAFKAWRITER,\n"
                << "        $path = \"" << topic_name << "\"\n"
                << "    ];\n"
                << "    Log::add_filter(" << log_id << "::LOG, " << writer_name << ");\n\n";
        }

        out << "}\n";
    }

    std::vector<std::string> endpoints() const override { return brokers_; }
    std::string              name() const override { return "kafka"; }

  private:
    std::vector<std::string> brokers_;
    std::string              topic_prefix_;
};

/// Configures https://github.com/ASTRAOS-de/zeek-fluvio.
class FluvioZeekLogTransport final : public IZeekLogTransport {
  public:
    FluvioZeekLogTransport(std::vector<std::string> endpoints, std::string default_topic_name)
        : endpoints_(std::move(endpoints)), default_topic_name_(std::move(default_topic_name)) {}

    void writePluginConfiguration(std::ostream &out, const std::vector<std::string> &protocols) const override {
        out << "@load zeek-fluvio\n"
            << "redef Fluvio::send_all_active_logs = F;\n";

        if (!default_topic_name_.empty()) {
            out << "redef Fluvio::default_topic_name = \"" << default_topic_name_ << "\";\n";
        }

        out << "redef Fluvio::logs_to_send = set(";
        for (std::size_t i = 0; i < protocols.size(); ++i) {
            if (i > 0) {
                out << ", ";
            }
            out << "Custom" << utils::toUpper(protocols[i]) << "::LOG";
        }
        out << ");\n";
    }

    std::vector<std::string> endpoints() const override { return endpoints_; }
    std::string              name() const override { return "fluvio"; }

  private:
    std::vector<std::string> endpoints_;
    std::string              default_topic_name_;
};

} // namespace

std::unique_ptr<IZeekLogTransport> makeZeekLogTransport(const ZeekLogTransportConfig &config) {
    const auto transport = utils::toLower(config.transport);

    if (transport.empty() || transport == "kafka") {
        return std::make_unique<KafkaZeekLogTransport>(config.endpoints, config.topic_prefix);
    }
    if (transport == "fluvio") {
        return std::make_unique<FluvioZeekLogTransport>(config.endpoints, config.fluvio_topic_name);
    }

    throw std::runtime_error("Unsupported ingestion_transport: " + config.transport);
}
