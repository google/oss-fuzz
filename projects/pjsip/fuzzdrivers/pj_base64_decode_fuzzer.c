#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "pjlib-util.h"
#include "pjlib.h"
#include "pjmedia-codec.h"
#include "pjmedia.h"
#include "pjmedia_audiodev.h"
#include "pjmedia_videodev.h"
#include "pjnath.h"
#include "pjsip.h"
#include "pjsip_simple.h"
#include "pjsip_ua.h"
#include "pjsua.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    pj_str_t input;
    pj_uint8_t out[2048];
    int out_len = 2048;

    input.ptr = (char *)Data;
    input.slen = Size;

    pj_base64_decode(&input, out, &out_len);

    return 0;
}
