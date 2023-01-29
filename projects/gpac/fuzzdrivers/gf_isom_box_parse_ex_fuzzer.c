#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/isomedia_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_Err err;
    GF_Box *box = NULL;
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    err = gf_isom_box_parse_ex(&box, bs, 0, GF_TRUE, Size);
    gf_bs_del(bs);
    if (err == GF_OK) gf_isom_box_del(box);
    return 0;
}
