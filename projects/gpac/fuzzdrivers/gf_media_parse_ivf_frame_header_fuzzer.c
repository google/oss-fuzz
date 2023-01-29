#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/media_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    u64 frame_size, pts;
    gf_media_parse_ivf_frame_header(bs, &frame_size, &pts);
    gf_bs_del(bs);
    return 0;
}
