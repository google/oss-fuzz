// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stddef.h>
#include "ldacBT.h"

#define TESTFUNC_TYPE extern "C" int

TESTFUNC_TYPE
LLVMFuzzerTestOneInput(const uint8_t *buf, size_t size)
{
    if (size == 0) {
    	return 0;
    }
    HANDLE_LDAC_BT hLdacBt;
    int pcm_used, stream_sz, frame_num;
    unsigned char p_stream[1024];

    hLdacBt = ldacBT_get_handle();

    ldacBT_init_handle_encode(
        hLdacBt,
        679,
        LDACBT_EQMID_SQ,
        LDACBT_CHANNEL_MODE_DUAL_CHANNEL,
        LDACBT_SMPL_FMT_S16,
        48000);

    ldacBT_encode(
        hLdacBt,
        (void *)(&buf + 44),
        &pcm_used,
        p_stream,
        &stream_sz,
        &frame_num);

    ldacBT_get_sampling_freq(hLdacBt);
    ldacBT_get_bitrate(hLdacBt);
    ldacBT_get_version();

    ldacBT_close_handle(hLdacBt);
    ldacBT_free_handle(hLdacBt);

    return 0;
}
