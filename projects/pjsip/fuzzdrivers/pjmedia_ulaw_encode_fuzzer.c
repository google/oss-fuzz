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
    size_t count = Size / 2;
    uint8_t *dst = malloc(count);
    pj_int16_t *src = malloc(count * sizeof(pj_int16_t));
    memcpy(src, Data, count * sizeof(pj_int16_t));
    pjmedia_ulaw_encode(dst, src, count);
    free(dst);
    free(src);
    return 0;
}
