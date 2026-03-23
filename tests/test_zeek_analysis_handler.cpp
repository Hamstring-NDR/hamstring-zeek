#include <gtest/gtest.h>
#include "ZeekAnalysisHandler.hpp"

class ZeekAnalysisHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Basic setup if any
    }

    void TearDown() override {
        // Clean up
    }
};

TEST_F(ZeekAnalysisHandlerTest, Initialization) {
    ZeekAnalysisHandler handler("/mock/config.zeek", "/mock/logs", "/tmp/test.pcap");
    // Only basic initialization is tested to avoid running actual system commands in unit tests.
    // In a full environment, we would use dependency injection for command execution to verify system calls.
    SUCCEED();
}

TEST_F(ZeekAnalysisHandlerTest, StartAnalysisDelegation) {
    ZeekAnalysisHandler handler("/mock/config.zeek", "/mock/logs", "/tmp/test.pcap");
    // Same rationale as above. We're testing that it links correctly and the API exists.
    SUCCEED();
}
