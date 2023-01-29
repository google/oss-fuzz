#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/odf_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    GF_Descriptor *desc = NULL;
    u32 size = 0;
    gf_odf_parse_descriptor(bs, &desc, &size);
    gf_odf_desc_del(desc);
    gf_bs_del(bs);
    return 0;
}
