#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>

#include "StringParser.h"

// Fuzzer entry point that treats the incoming buffer as newline-delimited tokens:
// line1 -> source string, line2 -> start token, line3 -> end token, line4 (optional) -> end-token optional flag.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    if (!data || size == 0) {
        return 0;
    }

    std::string input(reinterpret_cast<const char *>(data), size);

    auto nextLine = [&input](std::size_t &offset) -> std::string {
        if (offset >= input.size()) {
            return {};
        }

        std::size_t newlinePos = input.find('\n', offset);
        std::string line;
        if (newlinePos == std::string::npos) {
            line = input.substr(offset);
            offset = input.size();
        } else {
            line = input.substr(offset, newlinePos - offset);
            offset = newlinePos + 1;
        }
        return line;
    };

    std::size_t cursor = 0;
    std::string source = nextLine(cursor);
    std::string startToken = nextLine(cursor);
    std::string endToken = nextLine(cursor);
    std::string flagLine = nextLine(cursor);

    bool endOptional = true;
    if (!flagLine.empty()) {
        std::string normalized = flagLine;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (normalized == "0" || normalized == "false" || normalized == "no" || normalized == "off") {
            endOptional = false;
        } else if (normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on") {
            endOptional = true;
        }
    }

    (void)tmx::utils::StringParser::Substring(source, startToken, endToken, endOptional);
    return 0;
}
