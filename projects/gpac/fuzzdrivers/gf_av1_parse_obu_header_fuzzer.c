#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/media_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_BitStream * bs = gf_bs_new(Data, Size, GF_BITSTREAM_READ);
    ObuType obu_type;
    Bool obu_extension_flag;
    Bool obu_has_size_field;
    u8 temporal_id;
    u8 spatial_id;
    gf_av1_parse_obu_header(bs,&obu_type,&obu_extension_flag,&obu_has_size_field,&temporal_id,&spatial_id);
    gf_bs_del(bs);
    return 0;
}
