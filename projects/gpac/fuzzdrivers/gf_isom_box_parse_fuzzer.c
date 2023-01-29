#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/isomedia_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream *bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    GF_Box *box = NULL;
    gf_isom_box_parse(&box, bs);
    gf_bs_del(bs);
    if (box) gf_isom_box_del(box);
    return 0;
}
