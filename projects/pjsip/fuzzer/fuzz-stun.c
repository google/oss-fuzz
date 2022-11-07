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

#include <pjlib.h>
#include <pj/compat/socket.h>

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>

#define kMinInputLength 10
#define kMaxInputLength 5120

pj_pool_factory *mem;

int stun_parse(char *DataFx,size_t Size){
    int ret = 0;
    pj_pool_t *pool;
    pj_stun_msg *msg;
    pj_status_t status;

    pool = pj_pool_create(mem, "decode_test", 1024, 1024, NULL);

    status = pj_stun_msg_decode(pool, (pj_uint8_t*)DataFx,Size,
                            PJ_STUN_IS_DATAGRAM | PJ_STUN_CHECK_PACKET, 
                        &msg, NULL, NULL);

    if(status)
        ret = 1;

    pj_pool_release(pool);

    return ret;
}

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*pjproject/pjnath/src/pjnath-test/stun.c*/

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

    mem = &caching_pool.factory;

    pj_log_set_level(0);

    pj_init();

    pj_dump_config();
    pj_caching_pool_init( &caching_pool, &pj_pool_factory_default_policy, 0 );

    pjlib_util_init();
    pjnath_init();

/*call*/
    ret = stun_parse(DataFx,Size); 

    free(DataFx);
    return ret;
}
