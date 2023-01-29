#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/avparse.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream * bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    u32 codecid, width, height, dsi_len;
    u8 * dsi;
    gf_img_parse(bs,&codecid,&width,&height,&dsi,&dsi_len);
    if (dsi) gf_free(dsi);
    gf_bs_del(bs);
    return 0;
}
