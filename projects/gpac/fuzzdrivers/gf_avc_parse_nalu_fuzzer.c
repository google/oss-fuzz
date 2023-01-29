#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/media_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream *bs = gf_bs_new((char*)Data, Size, GF_BITSTREAM_READ);
    AVCState *avc = gf_malloc(sizeof(AVCState));
    gf_avc_parse_nalu(bs, avc);
    gf_free(avc);
    gf_bs_del(bs);
    return 0;
}
