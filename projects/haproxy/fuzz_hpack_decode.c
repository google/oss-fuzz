/*
 * # Copyright 2020 Google Inc.
 * #
 * # Licensed under the Apache License, Version 2.0 (the "License");
 * # you may not use this file except in compliance with the License.
 * # You may obtain a copy of the License at
 * #
 * #      http://www.apache.org/licenses/LICENSE-2.0
 * #
 * # Unless required by applicable law or agreed to in writing, software
 * # distributed under the License is distributed on an "AS IS" BASIS,
 * # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * # See the License for the specific language governing permissions and
 * # limitations under the License.
 * #
 * ################################################################################
 * */
#define HPACK_STANDALONE

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <haproxy/chunk.h>
#include <haproxy/hpack-dec.h>

#define MAX_RQ_SIZE 65536
#define MAX_HDR_NUM 1000

char hex[MAX_RQ_SIZE*3+3]; // enough for "[ XX]* <CR> <LF> \0"
uint8_t buf[MAX_RQ_SIZE];

char trash_buf[MAX_RQ_SIZE];
char tmp_buf[MAX_RQ_SIZE];

struct buffer tmp   = { .area = tmp_buf,   .data = 0, .size = sizeof(tmp_buf)   };

/* Empty function we dont need - we just need a callback */
void debug_hexdump(FILE *out, const char *pfx, const char *buf,
                   unsigned int baseaddr, int len)
{ }

// These must be included here
#include "../src/hpack-huff.c"
#include "../src/hpack-tbl.c"
#include "../src/hpack-dec.c"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
        char *new_str = (char *)malloc(size+1);
        struct hpack_dht *dht;
        struct pool_head pool;
        int dht_size = 4096;
        if (new_str == NULL){
                return 0;
        }
        memcpy(new_str, data, size);
        new_str[size] = '\0';
        struct http_hdr list[MAX_HDR_NUM];

        pool.size = dht_size;
        pool_head_hpack_tbl = &pool;
        dht = hpack_dht_alloc();

        if (dht != NULL)
        {
            hpack_decode_frame(dht, new_str, size, list,sizeof(list)/sizeof(list[0]), &tmp);
            if (dht != NULL)
            {
                free(dht);
            }
        }
        free(new_str);
        return 0;
}
