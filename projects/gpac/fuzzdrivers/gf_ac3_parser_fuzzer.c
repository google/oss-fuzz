#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/avparse.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2)
        return 0;
    if (Data[0] != 0x0b || Data[1] != 0x77)
        return 0;
    GF_AC3Config hdr;
    u32 pos = 0;
    gf_ac3_parser((u8 *)Data, Size, &pos, &hdr, 1);
    return 0;
}
