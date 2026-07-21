#include "KafkaRecoveryController.hpp"

#include <gtest/gtest.h>

using namespace std::chrono_literals;

class KafkaRecoveryControllerTest : public ::testing::Test {
  protected:
    KafkaRecoveryController::TimePoint now_{KafkaRecoveryController::Clock::now()};
};

TEST_F(KafkaRecoveryControllerTest, IgnoresBriefOutages) {
    KafkaRecoveryController controller(15s, 30s);

    EXPECT_EQ(controller.update(false, now_), KafkaRecoveryController::Event::OutageStarted);
    EXPECT_EQ(controller.update(true, now_ + 14s), KafkaRecoveryController::Event::TransientOutageResolved);
    EXPECT_EQ(controller.update(true, now_ + 60s), KafkaRecoveryController::Event::None);
}

TEST_F(KafkaRecoveryControllerTest, RestartsOnlyAfterStableRecovery) {
    KafkaRecoveryController controller(15s, 30s);

    EXPECT_EQ(controller.update(false, now_), KafkaRecoveryController::Event::OutageStarted);
    EXPECT_EQ(controller.update(false, now_ + 15s), KafkaRecoveryController::Event::RecoveryArmed);
    EXPECT_EQ(controller.update(true, now_ + 16s), KafkaRecoveryController::Event::StableRecoveryStarted);
    EXPECT_EQ(controller.update(true, now_ + 45s), KafkaRecoveryController::Event::None);
    EXPECT_EQ(controller.update(true, now_ + 46s), KafkaRecoveryController::Event::RestartDue);
}

TEST_F(KafkaRecoveryControllerTest, RequiresAnotherStableWindowAfterFailedRestart) {
    KafkaRecoveryController controller(15s, 30s);

    controller.update(false, now_);
    controller.update(false, now_ + 15s);
    controller.update(true, now_ + 16s);
    EXPECT_EQ(controller.update(true, now_ + 46s), KafkaRecoveryController::Event::RestartDue);

    controller.recordRestartResult(false, now_ + 46s);
    EXPECT_EQ(controller.update(true, now_ + 75s), KafkaRecoveryController::Event::None);
    EXPECT_EQ(controller.update(true, now_ + 76s), KafkaRecoveryController::Event::RestartDue);
}

TEST_F(KafkaRecoveryControllerTest, ResetsAfterSuccessfulRestartForLaterOutages) {
    KafkaRecoveryController controller(15s, 30s);

    controller.update(false, now_);
    controller.update(false, now_ + 15s);
    controller.update(true, now_ + 16s);
    controller.update(true, now_ + 46s);
    controller.recordRestartResult(true, now_ + 46s);

    EXPECT_EQ(controller.update(false, now_ + 47s), KafkaRecoveryController::Event::OutageStarted);
}
