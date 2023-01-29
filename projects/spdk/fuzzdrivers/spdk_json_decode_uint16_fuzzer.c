#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/json.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    struct spdk_json_val val;
    uint16_t out;
    if (Size < 2) {
        return 0;
    }
    val.len = Size;
    val.start = Data;
    spdk_json_decode_uint16(&val, &out);
    return 0;
}
