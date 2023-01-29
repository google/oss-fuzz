#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/avparse.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_M4ADecSpecInfo cfg;
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    gf_m4a_parse_program_config_element(bs, &cfg);
    gf_bs_del(bs);
    return 0;
}
