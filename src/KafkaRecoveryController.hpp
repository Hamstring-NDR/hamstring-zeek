#pragma once

#include <chrono>
#include <optional>

/// Tracks Kafka availability during live analysis and decides when Zeek
/// Kafka writer must be recreated. It does not perform I/O, making the
/// recovery policy independently testable.
class KafkaRecoveryController {
  public:
    enum class Event {
        None,
        OutageStarted,
        RecoveryArmed,
        TransientOutageResolved,
        StableRecoveryStarted,
        RestartDue,
    };

    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    KafkaRecoveryController(std::chrono::seconds outage_threshold, std::chrono::seconds recovery_stability)
        : outage_threshold_(outage_threshold), recovery_stability_(recovery_stability) {}

    Event update(bool kafka_reachable, TimePoint now) {
        if (!kafka_reachable) {
            recovery_started_.reset();
            restart_due_ = false;

            if (!outage_started_) {
                outage_started_ = now;
                return Event::OutageStarted;
            }

            if (!recovery_armed_ && now - *outage_started_ >= outage_threshold_) {
                recovery_armed_ = true;
                return Event::RecoveryArmed;
            }

            return Event::None;
        }

        if (!outage_started_) {
            return Event::None;
        }

        if (!recovery_armed_) {
            reset();
            return Event::TransientOutageResolved;
        }

        if (!recovery_started_) {
            recovery_started_ = now;
            return Event::StableRecoveryStarted;
        }

        if (!restart_due_ && now - *recovery_started_ >= recovery_stability_) {
            restart_due_ = true;
            return Event::RestartDue;
        }

        return Event::None;
    }

    /// Call after an attempted Zeek recycle. A failed attempt is retried only
    /// after another complete stable-recovery window.
    void recordRestartResult(bool successful, TimePoint now) {
        if (successful) {
            reset();
            return;
        }

        restart_due_      = false;
        recovery_started_ = now;
    }

  private:
    void reset() {
        outage_started_.reset();
        recovery_started_.reset();
        recovery_armed_ = false;
        restart_due_    = false;
    }

    std::chrono::seconds     outage_threshold_;
    std::chrono::seconds     recovery_stability_;
    std::optional<TimePoint> outage_started_;
    std::optional<TimePoint> recovery_started_;
    bool                     recovery_armed_{false};
    bool                     restart_due_{false};
};
