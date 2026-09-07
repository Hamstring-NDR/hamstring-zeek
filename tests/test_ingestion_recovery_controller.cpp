#include "IngestionRecoveryController.hpp"

#include <gtest/gtest.h>

using namespace std::chrono_literals;

class IngestionRecoveryControllerTest : public ::testing::Test {
  protected:
    IngestionRecoveryController::TimePoint now_{IngestionRecoveryController::Clock::now()};
};

TEST_F(IngestionRecoveryControllerTest, IgnoresBriefOutages) {
    IngestionRecoveryController controller(15s, 30s);

    EXPECT_EQ(controller.update(false, now_), IngestionRecoveryController::Event::OutageStarted);
    EXPECT_EQ(controller.update(true, now_ + 14s), IngestionRecoveryController::Event::TransientOutageResolved);
    EXPECT_EQ(controller.update(true, now_ + 60s), IngestionRecoveryController::Event::None);
}

TEST_F(IngestionRecoveryControllerTest, RestartsOnlyAfterStableRecovery) {
    IngestionRecoveryController controller(15s, 30s);

    EXPECT_EQ(controller.update(false, now_), IngestionRecoveryController::Event::OutageStarted);
    EXPECT_EQ(controller.update(false, now_ + 15s), IngestionRecoveryController::Event::RecoveryArmed);
    EXPECT_EQ(controller.update(true, now_ + 16s), IngestionRecoveryController::Event::StableRecoveryStarted);
    EXPECT_EQ(controller.update(true, now_ + 45s), IngestionRecoveryController::Event::None);
    EXPECT_EQ(controller.update(true, now_ + 46s), IngestionRecoveryController::Event::RestartDue);
}

TEST_F(IngestionRecoveryControllerTest, RequiresAnotherStableWindowAfterFailedRestart) {
    IngestionRecoveryController controller(15s, 30s);

    controller.update(false, now_);
    controller.update(false, now_ + 15s);
    controller.update(true, now_ + 16s);
    EXPECT_EQ(controller.update(true, now_ + 46s), IngestionRecoveryController::Event::RestartDue);

    controller.recordRestartResult(false, now_ + 46s);
    EXPECT_EQ(controller.update(true, now_ + 75s), IngestionRecoveryController::Event::None);
    EXPECT_EQ(controller.update(true, now_ + 76s), IngestionRecoveryController::Event::RestartDue);
}

TEST_F(IngestionRecoveryControllerTest, ResetsAfterSuccessfulRestartForLaterOutages) {
    IngestionRecoveryController controller(15s, 30s);

    controller.update(false, now_);
    controller.update(false, now_ + 15s);
    controller.update(true, now_ + 16s);
    controller.update(true, now_ + 46s);
    controller.recordRestartResult(true, now_ + 46s);

    EXPECT_EQ(controller.update(false, now_ + 47s), IngestionRecoveryController::Event::OutageStarted);
}