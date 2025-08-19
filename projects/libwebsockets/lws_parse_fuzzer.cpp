/* Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
##############################################################################*/


extern "C" {
#include "private-lib-core.h"
#include <libwebsockets.h>
}
#include <fuzzer/FuzzedDataProvider.h>
#include <cstring>
#include <cstdlib>
#include <vector>

static struct lws_protocols protocols[] = {
    { "http", &lws_callback_http_dummy, 0, 0 },
    { NULL, NULL, 0, 0 }
};

static struct lws_vhost mock_vhost = {
    .timeout_secs_ah_idle = 10,
};

static int initialize_context(struct lws *wsi) {
    struct lws_context_creation_info info = {};
    struct lws_context *cx = NULL;

    lws_context_info_defaults(&info, NULL);
    if (!(cx = lws_create_context(&info))) {
        return (-1);
    }
    lws_role_transition(wsi, (enum lwsi_role)LWSIFR_SERVER, LRS_HEADERS, &role_ops_h1);

    wsi->a.context = cx;
    wsi->a.protocol = protocols;
    wsi->a.vhost = &mock_vhost;
    if (lws_header_table_attach(wsi, 0) < 0) {
        lws_context_destroy(cx);
        return (-1);
    }

    return (0);
}

static int parse_http_header(struct lws *wsi, const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);
    size_t recved_size = 0;
    std::vector<uint8_t> recved;
    std::vector<uint8_t> fragment;
    int mutable_len = 0;
    unsigned char *mutable_fragment;

    wsi->http.ah->parser_state = WSI_TOKEN_NAME_PART;
    while (provider.remaining_bytes() > 0) {
        recved_size = provider.ConsumeIntegralInRange<size_t>(1, provider.remaining_bytes());
        recved = provider.ConsumeBytes<uint8_t>(recved_size);
        fragment.insert(fragment.end(), recved.begin(), recved.end());
        mutable_fragment = fragment.data();
        mutable_len = fragment.size();
        if (lws_parse(wsi, mutable_fragment, &mutable_len) < 0)
		return (-1);
        assert(mutable_len <= fragment.size() && mutable_len >= 0);
        fragment.erase(fragment.begin(), fragment.end() - mutable_len);
        if (wsi->http.ah->parser_state == WSI_PARSING_COMPLETE)
		break ;
    }

    return (0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct lws_context mock_context = {};
    struct lws wsi = {};

    if (size == 0) {
        return 0;
    }

    if (initialize_context(&wsi) < 0)
        return (0);
    parse_http_header(&wsi, data, size);

    lws_header_table_detach(&wsi, 0);
    lws_context_destroy(wsi.a.context);

    return 0;
}
