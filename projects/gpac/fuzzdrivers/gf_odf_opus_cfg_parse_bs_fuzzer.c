#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/mpeg4_odf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    GF_OpusConfig cfg;
    gf_odf_opus_cfg_parse_bs(bs, &cfg);
    gf_bs_del(bs);
    return 0;
}
