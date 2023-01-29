#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/media_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream * bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    u64 ivf_frame_size = gf_bs_read_u64(bs);
    u32 num_frames_in_superframe;
    u32 frame_sizes[16];
    u32 superframe_index_size;
    gf_vp9_parse_superframe(bs, ivf_frame_size, &num_frames_in_superframe, frame_sizes, &superframe_index_size);
    gf_bs_del(bs);
    return 0;
}
