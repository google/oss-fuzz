#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/media_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream * bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    GF_VPConfig vp9_cfg;
    Bool key_frame;
    u32 FrameWidth, FrameHeight, renderWidth, renderHeight;
    gf_vp9_parse_sample(bs, &vp9_cfg, &key_frame, &FrameWidth, &FrameHeight, &renderWidth, &renderHeight);
    gf_bs_del(bs);
    return 0;
}
