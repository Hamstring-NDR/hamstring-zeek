#include "ZeekConfigHandler.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;

class ZeekConfigHandlerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        setenv("CONTAINER_NAME", "ZEEK_TEST_CONTAINER", 1);

        // Create a unique temporary directory
        auto        base  = fs::temp_directory_path() / "zeek_test_XXXXXX";
        std::string tpath = base.string();
        char       *dt    = mkdtemp(tpath.data());
        test_dir          = fs::path(dt);

        fs::create_directories(test_dir / "additional_configs");

        local_zeek        = test_dir / "local.zeek";
        node_cfg          = test_dir / "node.cfg";
        node_cfg_template = test_dir / "base_node.cfg";

        std::ofstream(node_cfg_template) << "# base node config\n";
    }

    void TearDown() override {
        fs::remove_all(test_dir);
        unsetenv("CONTAINER_NAME");
    }

    YAML::Node createMockConfig(bool static_analysis) {
        YAML::Node config;
        config["environment"]["kafka_brokers"][0]["node_ip"]                     = "127.0.0.1";
        config["environment"]["kafka_brokers"][0]["external_port"]               = "9092";
        config["environment"]["kafka_topics_prefix"]["pipeline"]["logserver_in"] = "pipeline-logserver_in";

        YAML::Node sensor = config["pipeline"]["zeek"]["sensors"]["ZEEK_TEST_CONTAINER"];
        sensor["protocols"].push_back("http");
        sensor["protocols"].push_back("dns");

        if (static_analysis) {
            sensor["static_analysis"] = true;
        } else {
            sensor["static_analysis"] = false;
            sensor["interfaces"].push_back("eth0");
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
    ZeekConfigurationHandler handler(config, local_zeek, std::nullopt, false, node_cfg_template,
                                     "/usr/local/zeek/log/zeek.log", test_dir / "additional");

    EXPECT_EQ(handler.getAnalysisMode(), AnalysisMode::Static);
    EXPECT_EQ(handler.getZeekLogLocation(), "/usr/local/zeek/log/zeek.log");
}

TEST_F(ZeekConfigHandlerTest, InitializationNetworkAnalysis) {
    auto config = createMockConfig(false);
    ZeekConfigurationHandler handler(config, local_zeek, std::nullopt, false, node_cfg_template,
                                     "/usr/local/zeek/log/zeek.log", test_dir / "additional");

    EXPECT_EQ(handler.getAnalysisMode(), AnalysisMode::Network);
    auto interfaces = handler.getNetworkInterfaces();
    ASSERT_EQ(interfaces.size(), 1);
    EXPECT_EQ(interfaces[0], "eth0");
}

TEST_F(ZeekConfigHandlerTest, CLIInterfaceOverrideForcesNetworkMode) {
    // Even with static_analysis=true in YAML, CLI --interface should override
    auto config = createMockConfig(true);
    ZeekConfigurationHandler handler(config, local_zeek, std::optional<std::string>("ens192"), false,
                                     node_cfg_template, "/usr/local/zeek/log/zeek.log", test_dir / "additional");

    EXPECT_EQ(handler.getAnalysisMode(), AnalysisMode::Network);
    auto interfaces = handler.getNetworkInterfaces();
    ASSERT_EQ(interfaces.size(), 1);
    EXPECT_EQ(interfaces[0], "ens192");
}

TEST_F(ZeekConfigHandlerTest, CLIPcapOverrideForcesStaticMode) {
    // Even with static_analysis=false in YAML, CLI --file should override to static
    auto config = createMockConfig(false);
    ZeekConfigurationHandler handler(config, local_zeek, std::nullopt, true, node_cfg_template,
                                     "/usr/local/zeek/log/zeek.log", test_dir / "additional");

    EXPECT_EQ(handler.getAnalysisMode(), AnalysisMode::Static);
}

TEST_F(ZeekConfigHandlerTest, MissingContainerNameThrows) {
    unsetenv("CONTAINER_NAME");
    auto config = createMockConfig(true);
    EXPECT_THROW(ZeekConfigurationHandler(config, local_zeek), std::runtime_error);
}

TEST_F(ZeekConfigHandlerTest, MissingInterfacesInNetworkModeThrows) {
    auto config = createMockConfig(false);
    // Remove the interfaces node
    config["pipeline"]["zeek"]["sensors"]["ZEEK_TEST_CONTAINER"].remove("interfaces");
    EXPECT_THROW(ZeekConfigurationHandler(config, local_zeek, std::nullopt, false, node_cfg_template,
                                          "/usr/local/zeek/log/zeek.log", test_dir / "additional"),
                 std::runtime_error);
}

TEST_F(ZeekConfigHandlerTest, ConfigureIntegration) {
    auto config = createMockConfig(false);
    // Create an additional config
    std::ofstream(test_dir / "additional_configs" / "custom.zeek") << "@load custom-script\n";

    ZeekConfigurationHandler handler(config, local_zeek, std::nullopt, false, node_cfg_template,
                                     "/usr/local/zeek/log/zeek.log", test_dir / "additional_configs");

    handler.configure();

    // Verify local.zeek content
    std::ifstream lz(local_zeek);
    std::string   content((std::istreambuf_iterator<char>(lz)), std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("@load custom-script"), std::string::npos);
    EXPECT_NE(content.find("@load packages/zeek-kafka"), std::string::npos);
    EXPECT_NE(content.find("pipeline-logserver_in-http"), std::string::npos);
    EXPECT_NE(content.find("127.0.0.1:9092"), std::string::npos);
}
