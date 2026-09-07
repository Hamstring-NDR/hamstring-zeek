#pragma once

#include <memory>
#include <ostream>
#include <string>
#include <vector>

/// Abstract interface for wiring up Zeek's log-shipping plugin.
class IZeekLogTransport {
  public:
    virtual ~IZeekLogTransport() = default;

    /// Write the `@load` + `zeek_init()` (or equivalent) boilerplate needed
    /// to ship the given protocols' custom logs (e.g. CustomDNS::LOG,
    /// CustomHTTP::LOG) through this transport's Zeek writer plugin.
    virtual void writePluginConfiguration(std::ostream &out, const std::vector<std::string> &protocols) const = 0;

    /// Endpoints ("host:port") that should be reachable before Zeek is
    /// started. May be empty for a transport that has no meaningful
    /// pre-flight reachability check.
    virtual std::vector<std::string> endpoints() const = 0;

    /// Transport name, for logging ("kafka", "fluvio").
    virtual std::string name() const = 0;
};

/// Inputs needed to construct any of the supported Zeek log transports.
struct ZeekLogTransportConfig {
    std::string              transport;          ///< "kafka" (default) or "fluvio"
    std::vector<std::string> endpoints;           ///< broker / SPU endpoints, "host:port"
    std::string              topic_prefix;        ///< kafka: per-protocol topics are "<prefix>-<protocol>"
    std::string              fluvio_topic_name;   ///< fluvio: optional Fluvio::default_topic_name override
};

/// Build the configured transport.
/// @throws std::runtime_error if `config.transport` names something unsupported.
std::unique_ptr<IZeekLogTransport> makeZeekLogTransport(const ZeekLogTransportConfig &config);
