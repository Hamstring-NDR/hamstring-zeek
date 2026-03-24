#pragma once

#include <algorithm>
#include <numeric>
#include <string>
#include <string_view>
#include <vector>

namespace utils {

    /// Convert a string to lowercase (returns a copy).
    inline std::string toLower(std::string_view input) {
        std::string result(input);
        std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) { return std::tolower(ch); });
        return result;
    }

    /// Convert a string to uppercase (returns a copy).
    inline std::string toUpper(std::string_view input) {
        std::string result(input);
        std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) { return std::toupper(ch); });
        return result;
    }

    /// Join a vector of strings with a delimiter (equivalent of Python's `",".join(list)`).
    inline std::string joinStrings(const std::vector<std::string> &parts, std::string_view delimiter) {
        if (parts.empty()) {
            return {};
        }
        return std::accumulate(std::next(parts.begin()), parts.end(), parts.front(),
                               [&delimiter](const std::string &acc, const std::string &piece) {
                                   return acc + std::string(delimiter) + piece;
                               });
    }

} // namespace utils
