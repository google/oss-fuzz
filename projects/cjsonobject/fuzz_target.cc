#include <iostream>
#include "../CJsonObject.hpp"  // Adjust the include path if necessary

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Convert the input data to a string for JSON parsing
    std::string jsonContent(reinterpret_cast<const char*>(data), size);

    // Parse the JSON content
    neb::CJsonObject jsonObj;
    if (!jsonObj.Parse(jsonContent)) {
        // Parsing failed, but this is expected with random inputs
        return 0;
    }

    // Display parsed JSON (optional, can be removed for performance)
    std::cout << "Parsed JSON content:\n" << jsonObj.ToString() << std::endl;

    return 0;
}
