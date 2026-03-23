#include <gtest/gtest.h>
#include "ZeekConfigHandler.hpp"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

class ZeekConfigHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        setenv("CONTAINER_NAME", "ZEEK_TEST_CONTAINER", 1);
        test_dir = fs::temp_directory_path() / "zeek_test_dir_XXXXXX";
        // Create a unique temporary directory
        std::string tpath = test_dir.string();
        char* dt = mkdtemp(tpath.data());
        test_dir = dt;
        
        fs::create_directories(test_dir / "additional_configs");
        
        local_zeek = test_dir / "local.zeek";
        node_cfg = test_dir / "node.cfg";
        node_cfg_template = test_dir / "base_node.cfg";
        
        std::ofstream(node_cfg_template) << "# base node config\n";
    }

    void TearDown() override {
        fs::remove_all(test_dir);
        unsetenv("CONTAINER_NAME");
    }

    YAML::Node createMockConfig(bool static_analysis) {
        YAML::Node config;
        config["environment"]["kafka_brokers"][0]["node_ip"] = "192.168.175.69";
        config["environment"]["kafka_brokers"][0]["external_port"] = "8097";
        config["environment"]["kafka_topics_prefix"]["pipeline"]["logserver_in"] = "pipeline-logserver_in";
        
        YAML::Node sensor = config["pipeline"]["zeek"]["sensors"]["ZEEK_TEST_CONTAINER"];
        sensor["protocols"].push_back("http");
        sensor["protocols"].push_back("dns");
        
        if (static_analysis) {
            sensor["static_analysis"] = true;
        } else {
            sensor["static_analysis"] = false;
            sensor["interfaces"].push_back("enx84ba5960ffe6");
        }
        return config;
    }

    fs::path test_dir;
    fs::path local_zeek;
    fs::path node_cfg;
    fs::path node_cfg_template;
};

TEST_F(ZeekConfigHandlerTest, InitializationStaticAnalysis) {
    auto config = createMockConfig(true);
    ZeekConfigurationHandler handler(
        config, local_zeek.string(), node_cfg_template.string(), "/usr/local/zeek/log/zeek.log", (test_dir / "additional").string()
    );
    
    EXPECT_TRUE(handler.isAnalysisStatic());
    EXPECT_EQ(handler.getZeekLogLocation(), "/usr/local/zeek/log/zeek.log");
}

TEST_F(ZeekConfigHandlerTest, InitializationNetworkAnalysis) {
    auto config = createMockConfig(false);
    ZeekConfigurationHandler handler(
        config, local_zeek.string(), node_cfg_template.string(), "/usr/local/zeek/log/zeek.log", (test_dir / "additional").string()
    );
    
    EXPECT_FALSE(handler.isAnalysisStatic());
    auto interfaces = handler.getNetworkInterfaces();
    ASSERT_EQ(interfaces.size(), 1);
    EXPECT_EQ(interfaces[0], "enx84ba5960ffe6");
}

TEST_F(ZeekConfigHandlerTest, ConfigureIntegration) {
    auto config = createMockConfig(false);
    // Create an additional config
    std::ofstream(test_dir / "additional_configs" / "custom.zeek") << "@load custom-script\n";

    ZeekConfigurationHandler handler(
        config, local_zeek.string(), node_cfg_template.string(), "/usr/local/zeek/log/zeek.log", (test_dir / "additional_configs").string()
    );

    // Act
    handler.configure();

    // Verify local.zeek content
    std::ifstream lz(local_zeek);
    std::string content((std::istreambuf_iterator<char>(lz)), std::istreambuf_iterator<char>());
    
    EXPECT_TRUE(content.find("@load custom-script") != std::string::npos);
    EXPECT_TRUE(content.find("@load packages/zeek-kafka") != std::string::npos);
    EXPECT_TRUE(content.find("pipeline-logserver_in-http") != std::string::npos);
    EXPECT_TRUE(content.find("192.168.175.69:8097") != std::string::npos);
}
