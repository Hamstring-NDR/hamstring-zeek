#include "CommandExecutor.hpp"
#include "ZeekAnalysisHandler.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <mutex>

namespace fs = std::filesystem;

/// Mock command executor that records all executed commands without running them.
class MockCommandExecutor : public ICommandExecutor {
  public:
    int execute(const std::vector<std::string> &args) const override {
        std::lock_guard<std::mutex> lock(mutex_);
        recorded_calls_.push_back(args);
        return exit_code_;
    }

    /// Set the exit code that execute() will return.
    void setExitCode(int code) { exit_code_ = code; }

    /// Get all recorded command calls (thread-safe snapshot).
    std::vector<std::vector<std::string>> getRecordedCalls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return recorded_calls_;
    }

  private:
    mutable std::mutex                              mutex_;
    mutable std::vector<std::vector<std::string>>   recorded_calls_;
    int                                             exit_code_{0};
};

class ZeekAnalysisHandlerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_executor_ = std::make_shared<MockCommandExecutor>();

        test_dir_ = fs::temp_directory_path() / "zeek_analysis_test_XXXXXX";
        std::string tpath = test_dir_.string();
        char       *dt    = mkdtemp(tpath.data());
        test_dir_         = fs::path(dt);
    }

    void TearDown() override { fs::remove_all(test_dir_); }

    std::shared_ptr<MockCommandExecutor> mock_executor_;
    fs::path                             test_dir_;
};

TEST_F(ZeekAnalysisHandlerTest, Initialization) {
    ZeekAnalysisHandler handler("/mock/config.zeek", "/mock/logs", mock_executor_, "/tmp/test.pcap");
    SUCCEED();
}

TEST_F(ZeekAnalysisHandlerTest, StaticAnalysisWithPcapFile) {
    // Create a test pcap file
    fs::path pcap = test_dir_ / "capture.pcap";
    std::ofstream(pcap) << "dummy";

    ZeekAnalysisHandler handler("/mock/config.zeek", "/mock/logs", mock_executor_, pcap);
    handler.startAnalysis(AnalysisMode::Static);

    auto calls = mock_executor_->getRecordedCalls();
    ASSERT_EQ(calls.size(), 1);
    EXPECT_EQ(calls[0][0], "zeek");
    EXPECT_EQ(calls[0][1], "-C");
    EXPECT_EQ(calls[0][2], "-r");
    EXPECT_EQ(calls[0][3], pcap.string());
    EXPECT_EQ(calls[0][4], "/mock/config.zeek");
}

TEST_F(ZeekAnalysisHandlerTest, StaticAnalysisDiscoversPcapFiles) {
    // Create multiple pcap files in the static files dir
    setenv("STATIC_FILES_DIR", test_dir_.c_str(), 1);
    std::ofstream(test_dir_ / "a.pcap") << "dummy";
    std::ofstream(test_dir_ / "b.pcap") << "dummy";
    std::ofstream(test_dir_ / "c.txt") << "not a pcap";

    ZeekAnalysisHandler handler("/mock/config.zeek", "/mock/logs", mock_executor_);
    handler.startAnalysis(AnalysisMode::Static);

    auto calls = mock_executor_->getRecordedCalls();
    EXPECT_EQ(calls.size(), 2); // a.pcap and b.pcap, not c.txt

    unsetenv("STATIC_FILES_DIR");
}

TEST_F(ZeekAnalysisHandlerTest, StaticAnalysisHandlesFailedCommand) {
    mock_executor_->setExitCode(1);

    fs::path pcap = test_dir_ / "fail.pcap";
    std::ofstream(pcap) << "dummy";

    ZeekAnalysisHandler handler("/mock/config.zeek", "/mock/logs", mock_executor_, pcap);
    // Should not throw — errors are logged
    EXPECT_NO_THROW(handler.startAnalysis(AnalysisMode::Static));

    auto calls = mock_executor_->getRecordedCalls();
    EXPECT_EQ(calls.size(), 1);
}
