#include <csignal>

int main() {
    sigset_t current_mask;
    if (pthread_sigmask(SIG_BLOCK, nullptr, &current_mask) != 0) {
        return 2;
    }

    return sigismember(&current_mask, SIGINT) == 1 || sigismember(&current_mask, SIGTERM) == 1 ? 1 : 0;
}
