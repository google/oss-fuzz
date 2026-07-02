#include "systemd_target_parser.hpp"
#include <fstream>
#include <unistd.h>
#include <vector>
#include <string>
#include <iostream>

// Define the global variable required by systemd_target_parser
bool gVerbose = false;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Write data to a temporary file
    char temp_filename[] = "/tmp/target_parser_fuzzer_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd < 0) {
        return 0;
    }
    
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        unlink(temp_filename);
        return 0;
    }
    close(fd);

    // Call the function under test
    try {
        std::vector<std::string> filePaths = {temp_filename};
        parseFiles(filePaths);
    } catch (const std::exception& e) {
        // We expect exceptions for invalid JSON or validation errors,
        // which is fine. We want to catch them so the fuzzer doesn't
        // treat them as crashes.
    }

    // Clean up
    unlink(temp_filename);
    return 0;
}
