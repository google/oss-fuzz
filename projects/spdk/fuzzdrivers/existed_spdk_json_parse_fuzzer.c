#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/json.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    struct spdk_json_val values[1];
    void *end;
    spdk_json_parse((void *)Data, Size, values, 1, &end, 0);
    return 0;
}
