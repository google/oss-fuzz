/* Copyright 2026 Google LLC
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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "libevent/include/event2/buffer.h"
#include "libevent/include/event2/bufferevent.h"
#include "libevent/include/event2/event.h"
}

static void read_cb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *input = bufferevent_get_input(bev);
    evbuffer_drain(input, evbuffer_get_length(input));
}

static void event_cb(struct bufferevent *bev, short what, void *ctx) {
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 16) return 0;

  FuzzedDataProvider data_provider(data, size);

  std::string s1 = data_provider.ConsumeRandomLengthString();
  std::string s2 = data_provider.ConsumeRandomLengthString();
  uint32_t val1 = data_provider.ConsumeIntegral<uint32_t>();
  uint32_t val2 = data_provider.ConsumeIntegral<uint32_t>();
  uint32_t val3 = data_provider.ConsumeIntegral<uint32_t>();
  uint32_t val4 = data_provider.ConsumeIntegral<uint32_t>();

  int use_pair = val1 % 2;
  int read_write = val2 % 2;
  int use_filter = val4 % 2;

  int options1 = val2 % 16;
  int options2 = val3 % 16;

  struct bufferevent *bev1 = NULL, *bev2 = NULL, *bev3 = NULL, *bev4 = NULL,
                     *pair[2];
  struct event_base *base = NULL;
  struct evbuffer *evbuf = NULL;
  struct ev_token_bucket_cfg *conn_bucket_cfg = NULL;
  struct bufferevent_rate_limit_group *bev_rate_group = NULL;
  char buf[128];

  /*create a buffer event*/
  struct event_config *cfg = event_config_new();
  if (val1 % 3 == 1) {
    event_config_avoid_method(cfg, "epoll");
  } else if (val1 % 3 == 2) {
    event_config_avoid_method(cfg, "epoll");
    event_config_avoid_method(cfg, "poll");
  }
  base = event_base_new_with_config(cfg);
  event_config_free(cfg);
  if (!base) return 0;

  if (use_pair == 0) {
    if (bufferevent_pair_new(base, options1, pair) == -1) {
      event_base_free(base);
      return 0;
    }
    bev1 = pair[0];
    bev2 = pair[1];
  } else {
    bev1 = bufferevent_socket_new(base, -1, options1);
    bev2 = bufferevent_socket_new(base, -1, options2);
  }

  /*bufferevent_filter_new*/
  if (use_filter == 0 && bev1 && bev2) {
    /*we cannot use BEV_OPT_CLOSE_ON_FREE when freeing bufferevents*/
    bev3 = bufferevent_filter_new(
        bev1, NULL, NULL, options1 & (~BEV_OPT_CLOSE_ON_FREE), NULL, NULL);
    bev4 = bufferevent_filter_new(
        bev2, NULL, NULL, options2 & (~BEV_OPT_CLOSE_ON_FREE), NULL, NULL);

    if (bev3) {
      // bev1 is now "under" bev3
    } else {
      bufferevent_free(bev1);
      bev1 = NULL;
    }
    if (bev4) {
      // bev2 is now "under" bev4
    } else {
      bufferevent_free(bev2);
      bev2 = NULL;
    }
  } else {
    bev3 = bev1;
    bev4 = bev2;
  }

  if (!bev3 || !bev4) {
    goto cleanup;
  }

  if (bufferevent_priority_set(bev3, val2 % 8) == 0) {
    bufferevent_get_priority(bev3);
  }

  /*set rate limits*/
  bufferevent_set_rate_limit(bev3, NULL);
  struct timeval cfg_tick;
  cfg_tick.tv_sec = val1 % 10;
  cfg_tick.tv_usec = val2 % 1000000;
  conn_bucket_cfg = ev_token_bucket_cfg_new(val1 % 1024 + 1, val2 % 2048 + 1, 
                                           val3 % 1024 + 1, val4 % 2048 + 1, &cfg_tick);
  if (conn_bucket_cfg) {
    bev_rate_group = bufferevent_rate_limit_group_new(base, conn_bucket_cfg);
    if (bev_rate_group) {
        bufferevent_add_to_rate_limit_group(bev4, bev_rate_group);
    }
  }

  /*write and read from buffer events*/
  bufferevent_setcb(bev3, read_cb, NULL, event_cb, NULL);
  bufferevent_setcb(bev4, read_cb, NULL, event_cb, NULL);
  bufferevent_enable(bev3, EV_READ | EV_WRITE);
  bufferevent_enable(bev4, EV_READ | EV_WRITE);

  bufferevent_write(bev3, s1.c_str(), s1.size());
  bufferevent_write(bev4, s2.c_str(), s2.size());
  
  /* Run loop briefly */
  event_base_loop(base, EVLOOP_NONBLOCK);

  bufferevent_write_buffer(bev3, bufferevent_get_input(bev4));

  evbuf = evbuffer_new();
  if (evbuf) {
    bufferevent_read_buffer(bev3, evbuf);
    evbuffer_free(evbuf);
  }
  bufferevent_read(bev3, buf, sizeof(buf));

  if (bev_rate_group) {
    bufferevent_remove_from_rate_limit_group(bev4);
  }

  /*watermarks*/
  if (read_write == 0) {
    bufferevent_setwatermark(bev4, EV_READ, val1 % 1024, val2 % 2048);
  } else {
    bufferevent_setwatermark(bev4, EV_WRITE, val1 % 1024, val2 % 2048);
  }

  /*clean up*/
cleanup:
  if (bev3) bufferevent_free(bev3);
  if (bev4) bufferevent_free(bev4);
  if (conn_bucket_cfg) ev_token_bucket_cfg_free(conn_bucket_cfg);
  if (bev_rate_group) bufferevent_rate_limit_group_free(bev_rate_group);
  if (base) event_base_free(base);

  return 0;
}
