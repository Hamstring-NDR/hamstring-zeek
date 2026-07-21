#include "CommandExecutor.hpp"

#include <csignal>
#include <gtest/gtest.h>

namespace {

class SignalMaskRestorer {
  public:
    explicit SignalMaskRestorer(const sigset_t &mask) : mask_(mask) {}
    ~SignalMaskRestorer() { pthread_sigmask(SIG_SETMASK, &mask_, nullptr); }

  private:
    sigset_t mask_;
};

} // namespace

TEST(PosixCommandExecutorTest, UnblocksShutdownSignalsBeforeExec) {
    sigset_t shutdown_signals;
    sigemptyset(&shutdown_signals);
    sigaddset(&shutdown_signals, SIGINT);
    sigaddset(&shutdown_signals, SIGTERM);

    sigset_t original_mask;
    ASSERT_EQ(pthread_sigmask(SIG_BLOCK, &shutdown_signals, &original_mask), 0);
    SignalMaskRestorer restorer(original_mask);

    PosixCommandExecutor executor;
    EXPECT_EQ(executor.execute({COMMAND_EXECUTOR_SIGNAL_HELPER}), 0);
}
