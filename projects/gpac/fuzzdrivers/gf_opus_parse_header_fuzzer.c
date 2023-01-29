#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/avparse.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8)
        return 0;
    GF_OpusConfig cfg;
    gf_opus_parse_header(&cfg, (u8 *)Data, Size);
    return 0;
}
