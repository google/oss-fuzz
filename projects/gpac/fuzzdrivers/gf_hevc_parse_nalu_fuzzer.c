#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/media_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // fuzzing code goes here
    HEVCState * hevc = NULL;
    u8 * nal_unit_type = NULL;
    u8 * temporal_id = NULL;
    u8 * layer_id = NULL;
    gf_hevc_parse_nalu(Data, Size, hevc, nal_unit_type, temporal_id, layer_id);
    return 0;
}
