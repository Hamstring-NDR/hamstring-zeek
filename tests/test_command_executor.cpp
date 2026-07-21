#include "CommandExecutor.hpp"

#include <csignal>
#include <gtest/gtest.h>

TEST(PosixCommandExecutorTest, UnblocksShutdownSignalsBeforeExec) {
    sigset_t shutdown_signals;
    sigemptyset(&shutdown_signals);
    sigaddset(&shutdown_signals, SIGINT);
    sigaddset(&shutdown_signals, SIGTERM);

    sigset_t original_mask;
    ASSERT_EQ(pthread_sigmask(SIG_BLOCK, &shutdown_signals, &original_mask), 0);

    PosixCommandExecutor executor;
    const int result =
        executor.execute({"sh", "-c", "grep -q '^SigBlk:[[:space:]]*0000000000000000$' /proc/self/status"});

    ASSERT_EQ(pthread_sigmask(SIG_SETMASK, &original_mask, nullptr), 0);
    EXPECT_EQ(result, 0);
}
