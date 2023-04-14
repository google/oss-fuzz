/* Copyright 2023 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <nc_hashkit.h>
#include <nc_conf.h>
#include <nc_util.h>
#include <proto/nc_proto.h>
#include <stdio.h>

#define kMinInputLength 5
#define kMaxInputLength 1024

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{

    if (Size < kMinInputLength || Size > kMaxInputLength) {
        return 1;
    }

    char *data = calloc((Size+1), sizeof(char));  
    memcpy(data, Data, Size);

    struct instance nci = {0};
    nci.mbuf_chunk_size = MBUF_SIZE;
    mbuf_init(&nci);
    msg_init();
    log_init(0, NULL);

    {
        struct conn fake_client = {0};
        struct mbuf *m = mbuf_get();

        struct msg *req = msg_get(&fake_client, 1, 1);
        req->state = 0;
        req->token = NULL;

        mbuf_copy(m, (const uint8_t*)Data, Size);

        STAILQ_INIT(&req->mhdr);
        mbuf_insert(&req->mhdr, m);
        req->pos = m->start;

        redis_parse_req(req);

        msg_put(req);
    }
    {
        
        struct conn fake_client = {0};
        struct mbuf *m = mbuf_get();

        struct msg *rsp = msg_get(&fake_client, 0, 1);
        rsp->state = 0;
        rsp->token = NULL;

        mbuf_copy(m, (const uint8_t*)data, Size);

        STAILQ_INIT(&rsp->mhdr);
        mbuf_insert(&rsp->mhdr, m);
        rsp->pos = m->start;

        redis_parse_rsp(rsp);

        msg_put(rsp);
    }
    {
        struct conn fake_client = {0};
        struct mbuf *m = mbuf_get();

        struct msg *rsp = msg_get(&fake_client, 0, 0);
        rsp->state = 0;
        rsp->token = NULL;

        mbuf_copy(m, (const uint8_t*)data, Size);

        STAILQ_INIT(&rsp->mhdr);
        mbuf_insert(&rsp->mhdr, m);
        rsp->pos = m->start;

        memcache_parse_rsp(rsp);
        msg_put(rsp);
    }
    {
        struct conn fake_client = {0};
        struct mbuf *m = mbuf_get();

        struct msg *req = msg_get(&fake_client, 1, 0);
        req->state = 0;
        req->token = NULL;

        mbuf_copy(m, (const uint8_t*)data, Size);

        STAILQ_INIT(&req->mhdr);
        mbuf_insert(&req->mhdr, m);
        req->pos = m->start;

        memcache_parse_req(req);
        msg_put(req);   
    }

    msg_deinit();
    mbuf_deinit();
    log_deinit();

    free(data);

    return 0;
}
