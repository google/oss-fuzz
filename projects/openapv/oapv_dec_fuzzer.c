// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Fuzzer for the OpenAPV (OAPV) decoder.
// OpenAPV is the Advanced Professional Video codec used in Android 16+.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "inc/oapv.h"
#include "app/oapv_app_util.h"

// Limit allocation to prevent OOM in fuzzing (oss-fuzz has 2GB limit)
#define MAX_FRAME_PIXELS (4096 * 2160)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0;  // Too small to be a valid APV access unit
    }

    oapvd_t did = NULL;
    oapvm_t mid = NULL;
    oapvd_cdesc_t cdesc;
    oapv_bitb_t bitb;
    oapv_frms_t ofrms;
    oapv_au_info_t aui;
    oapvd_stat_t stat;
    int ret = 0;

    memset(&cdesc, 0, sizeof(cdesc));
    memset(&ofrms, 0, sizeof(ofrms));
    memset(&aui, 0, sizeof(oapv_au_info_t));

    // Create decoder
    did = oapvd_create(&cdesc, &ret);
    if (did == NULL) {
        return 0;
    }

    // Create metadata handler
    mid = oapvm_create(&ret);
    if (OAPV_FAILED(ret)) {
        goto cleanup;
    }

    // Parse access unit info from the bitstream
    if (OAPV_FAILED(oapvd_info((void *)data, size, &aui))) {
        goto cleanup;
    }

    // Allocate frame buffers with size limit
    ofrms.num_frms = aui.num_frms;
    for (int i = 0; i < ofrms.num_frms; i++) {
        oapv_frm_t *frm = &ofrms.frm[i];
        oapv_frm_info_t *finfo = &aui.frm_info[i];

        // Reject extreme dimensions to prevent OOM
        if ((int64_t)finfo->w * finfo->h > MAX_FRAME_PIXELS) {
            goto cleanup;
        }

        if (frm->imgb != NULL &&
            (frm->imgb->w[0] != finfo->w || frm->imgb->h[0] != finfo->h)) {
            frm->imgb->release(frm->imgb);
            frm->imgb = NULL;
        }

        if (frm->imgb == NULL) {
            frm->imgb = imgb_create(finfo->w, finfo->h, finfo->cs);
            if (frm->imgb == NULL) {
                goto cleanup;
            }
        }
    }

    // Decode
    bitb.addr = (void *)data;
    bitb.ssize = size;
    oapvd_decode(did, &bitb, &ofrms, mid, &stat);

cleanup:
    if (did) oapvd_delete(did);
    if (mid) oapvm_delete(mid);
    for (int i = 0; i < ofrms.num_frms; i++) {
        if (ofrms.frm[i].imgb != NULL) {
            ofrms.frm[i].imgb->release(ofrms.frm[i].imgb);
        }
    }
    return 0;
}
