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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "memcached.h"
#include "proto_proxy.h"
#include "cache.h"
#include <sys/eventfd.h>

static struct event_base *main_base;
static conn *fconn;

#define PROXY 1
#define READ_BUFFER_SIZE 16384 // memcached.h

extern int LLVMFuzzerInitialize(int *argc, char **argv)
{
    // allocate cons
    conns = calloc(10, sizeof(conn *));

    // init eventfd
    int dfd = eventfd(0, EFD_NONBLOCK);
    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    main_base = event_base_new_with_config(ev_config);

    memcached_thread_init(1, NULL);
    // get the first, and only, worker thread, and manually attach to the conn
    LIBEVENT_THREAD *mthread = get_worker_thread(0); 

    // init proxy config
    settings.proxy_ctx = proxy_init(false);
    settings.proxy_enabled = true;
    settings.binding_protocol = proxy_prot;

    // generate connection
    fconn = conn_new(dfd, conn_parse_cmd,
                EV_READ|EV_PERSIST,
                4096, local_transport,
                main_base, NULL, 0,
                settings.binding_protocol);

    // assign worker thread
    fconn->thread = mthread;

    // initialize proxy thread
    proxy_thread_init(settings.proxy_ctx, fconn->thread);
    
    // setup hashing
    assoc_init(HASHPOWER_DEFAULT);
    hash_init(MURMUR3_HASH);

    return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    if(len < 4) return -1;
    if(len > READ_BUFFER_SIZE) return -1;

    int rval = 0;

    fconn->rbuf = do_cache_alloc(fconn->thread->rbuf_cache);
    fconn->rcurr = fconn->rbuf;
    fconn->rsize = READ_BUFFER_SIZE;

    fconn->rbytes = len;
    memcpy(fconn->rbuf, buf, len);

    rval = try_read_command_proxy(fconn);
    do_cache_free(fconn->thread->rbuf_cache, fconn->rbuf);
    fconn->rbuf = NULL;
    fconn->rcurr = NULL;
    
    return rval;
}
