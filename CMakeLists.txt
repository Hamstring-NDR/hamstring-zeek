cmake_minimum_required(VERSION 3.15)
project(hamstring_zeek DESCRIPTION "Zeek orchestration module" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find packages provided by vcpkg
find_package(yaml-cpp CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

# Threads
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Executable
add_executable(hamstring_zeek
    src/main.cpp
    src/ZeekConfigHandler.cpp
    src/ZeekAnalysisHandler.cpp
)

target_include_directories(hamstring_zeek PRIVATE src)

# Link Libraries
target_link_libraries(hamstring_zeek PRIVATE
    yaml-cpp::yaml-cpp
    spdlog::spdlog
    cxxopts::cxxopts
    Threads::Threads
)

# Testing
enable_testing()

add_executable(hamstring_zeek_tests
    tests/test_zeek_config_handler.cpp
    tests/test_zeek_analysis_handler.cpp
    tests/test_kafka_recovery_controller.cpp
    tests/test_command_executor.cpp
    src/ZeekConfigHandler.cpp
    src/ZeekAnalysisHandler.cpp
)

add_executable(command_executor_signal_helper tests/command_executor_signal_helper.cpp)
target_link_libraries(command_executor_signal_helper PRIVATE Threads::Threads)
add_dependencies(hamstring_zeek_tests command_executor_signal_helper)
target_compile_definitions(hamstring_zeek_tests PRIVATE
    COMMAND_EXECUTOR_SIGNAL_HELPER="$<TARGET_FILE:command_executor_signal_helper>"
)

target_include_directories(hamstring_zeek_tests PRIVATE src)

target_link_libraries(hamstring_zeek_tests PRIVATE
    yaml-cpp::yaml-cpp
    spdlog::spdlog
    GTest::gtest_main
    Threads::Threads
)

include(GoogleTest)
gtest_discover_tests(hamstring_zeek_tests)
