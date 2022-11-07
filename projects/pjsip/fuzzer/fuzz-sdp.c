/* Copyright 2022 Google LLC
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <pjmedia.h>
#include <pjlib.h>

#include <pjmedia/sdp.h>
#include <pjmedia/sdp_neg.h>

#define kMinInputLength 10
#define kMaxInputLength 5120

pj_pool_factory *mem;

int sdp_parser(char *DataFx,size_t Size){

    int ret = 0;
	pj_pool_t *pool;
    pjmedia_sdp_session *sdp;
    pj_status_t status;

    pool = pj_pool_create(mem, "sdp_neg_test", 4000, 4000, NULL);

    status = pjmedia_sdp_parse(pool, DataFx, Size,&sdp);

    if (status != PJ_SUCCESS){
        ret = 1;
        goto end;
    }

    status = pjmedia_sdp_validate(sdp);

end:
    pj_pool_release(pool);

    return ret;
}

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*pjproject/pjmedia/src/test/sdp_neg_test.c*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 1;
    }

/*Add Extra byte */
    char *DataFx;
    DataFx = (char *)calloc((Size+1),sizeof(char));
    memcpy((void *)DataFx,(void *)Data,Size);

/*init*/
    int ret = 0;
    pj_caching_pool caching_pool;
    pj_pool_t *pool;

    pj_init();
    pj_caching_pool_init(&caching_pool, &pj_pool_factory_default_policy, 0);
    pool = pj_pool_create(&caching_pool.factory, "test", 1000, 512, NULL);

    pj_log_set_level(0);

    mem = &caching_pool.factory;

    pjmedia_event_mgr_create(pool, 0, NULL);

/*Call*/
    ret = sdp_parser(DataFx,Size);

/*Free*/
    pjmedia_event_mgr_destroy(pjmedia_event_mgr_instance());
    pj_pool_release(pool);
    pj_caching_pool_destroy(&caching_pool);

    free(DataFx);
    return ret;
}
