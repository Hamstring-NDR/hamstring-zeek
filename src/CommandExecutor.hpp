#pragma once

#include <cerrno>
#include <cstring>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

/// Abstract interface for executing system commands.
/// Enables dependency injection for unit testing.
class ICommandExecutor {
  public:
    virtual ~ICommandExecutor() = default;

    /// Execute a command with the given arguments.
    /// @param args  The command and its arguments (args[0] is the executable).
    /// @return The exit code of the process (0 on success).
    virtual int execute(const std::vector<std::string> &args) const = 0;
};

/// Default implementation that uses POSIX fork/execvp/waitpid.
/// This replaces all std::system() calls, avoiding shell injection
/// and providing proper process management.
class PosixCommandExecutor : public ICommandExecutor {
  public:
    int execute(const std::vector<std::string> &args) const override {
        if (args.empty()) {
            throw std::invalid_argument("Cannot execute empty command");
        }

        // Build the C-style argv array required by execvp
        std::vector<char *> argv;
        argv.reserve(args.size() + 1);
        for (const auto &arg : args) {
            argv.push_back(const_cast<char *>(arg.c_str()));
        }
        argv.push_back(nullptr);

        pid_t pid = fork();
        if (pid < 0) {
            throw std::runtime_error(std::string("fork() failed: ") + std::strerror(errno));
        }

        if (pid == 0) {
            // Child process — replace with the target command
            execvp(argv[0], argv.data());
            // execvp only returns on failure
            spdlog::error("execvp failed for '{}': {}", args[0], std::strerror(errno));
            _exit(127);
        }

        // Parent process — wait for child
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            throw std::runtime_error(std::string("waitpid() failed: ") + std::strerror(errno));
        }

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            spdlog::warn("Command '{}' killed by signal {}", args[0], WTERMSIG(status));
            return 128 + WTERMSIG(status);
        }

        return -1;
    }
};
