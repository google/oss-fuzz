#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/media_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    GF_ProResFrameInfo prores_frame;
    gf_media_prores_parse_bs(bs, &prores_frame);
    gf_bs_del(bs);
    return 0;
}
