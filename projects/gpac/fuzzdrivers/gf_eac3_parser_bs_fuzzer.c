#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/avparse.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    GF_AC3Config hdr;
    gf_eac3_parser_bs(bs, &hdr, 0);
    gf_bs_del(bs);
    return 0;
}
