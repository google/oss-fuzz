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
    pj_caching_pool cp;
    pj_init();
    pj_caching_pool_init(&cp, &pj_pool_factory_default_policy, 0);
    pj_pool_t *pool = pj_pool_create(&cp.factory, "pool", 1024, 1024, NULL);
    pjsip_rx_data *rdata = pj_pool_zalloc(pool, sizeof(pjsip_rx_data));
    rdata->msg_info.msg = pj_pool_zalloc(pool, sizeof(pjsip_msg));
    rdata->msg_info.msg->body = pj_pool_zalloc(pool, sizeof(pjsip_msg_body));
    rdata->msg_info.msg->body->data = pj_pool_alloc(pool, Size);
    pj_memcpy(rdata->msg_info.msg->body->data, Data, Size);
    pjsip_pres_status *status = pj_pool_zalloc(pool, sizeof(pjsip_pres_status));
    pjsip_pres_parse_xpidf(rdata, pool, status);
    pj_pool_release(pool);
    pj_caching_pool_destroy(&cp);
    return 0;
}
