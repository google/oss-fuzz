#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "flatbuffers/flatbuffers.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) {
        return 0;
    }

    size_t malicious_size;
    memcpy(&malicious_size, data, sizeof(size_t));

    flatbuffers::FlatBufferBuilder builder;
    int64_t* my_buffer = nullptr;

    builder.CreateUninitializedVector<int64_t>(malicious_size, &my_buffer);

    if (my_buffer != nullptr) {
        my_buffer[100] = 0xDEADBEEF; 
    }

    return 0;
}
