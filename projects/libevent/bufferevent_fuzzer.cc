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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider data_provider(data, size);

  std::string s1 = data_provider.ConsumeRandomLengthString();
  std::string s2 = data_provider.ConsumeRandomLengthString();
  size_t int1 = data_provider.ConsumeIntegral<size_t>();
  size_t int2 = data_provider.ConsumeIntegral<size_t>();
  size_t int3 = data_provider.ConsumeIntegral<size_t>();
  size_t int4 = data_provider.ConsumeIntegral<size_t>();

  int use_pair = int1 % 2;
  int read_write = int2 % 2;
  int use_filter = int4 % 2;

  int options1 = int2 % 16;
  int options2 = int3 % 16;

  struct bufferevent *bev1 = NULL, *bev2 = NULL, *bev3 = NULL, *bev4 = NULL,
                     *pair[2];
  struct event_base *base = NULL;
  struct evbuffer *evbuf = NULL;
  static struct ev_token_bucket_cfg *conn_bucket_cfg = NULL;
  struct bufferevent_rate_limit_group *bev_rate_group = NULL;
  char buf[128];

  /*create a buffer event*/
  base = event_base_new();
  if (use_pair == 0) {
    if (bufferevent_pair_new(base, options1, pair) == -1) {
      event_base_free(base);
      return 0;
    }
    bev1 = pair[0];
    bev2 = pair[1];
    assert(bufferevent_pair_get_partner(bev1) != NULL);
  } else {
    bev1 = bufferevent_socket_new(base, -1, options1);
    bev2 = bufferevent_socket_new(base, -1, options2);
  }

  /*bufferevent_filter_new*/
  if (use_filter == 0) {

    /*we cannot use BEV_OPT_CLOSE_ON_FREE when freeing bufferevents*/
    bev3 = bufferevent_filter_new(
        bev1, NULL, NULL, options1 & (~BEV_OPT_CLOSE_ON_FREE), NULL, NULL);
    bev4 = bufferevent_filter_new(
        bev2, NULL, NULL, options2 & (~BEV_OPT_CLOSE_ON_FREE), NULL, NULL);

    if (bev1) {
      bufferevent_free(bev1);
    }
    if (bev2) {
      bufferevent_free(bev2);
    }
  } else {
    bev3 = bev1;
    bev4 = bev2;
  }

  if (!bev3 || !bev4) {
    goto cleanup;
  }

  if (bufferevent_priority_set(bev3, options2) == 0) {
    assert(bufferevent_get_priority(bev3) == options2);
  }

  /*set rate limits*/
  assert(bufferevent_set_rate_limit(bev3, NULL) != -1);
  static struct timeval cfg_tick = {static_cast<__time_t>(int1),
                                    static_cast<__suseconds_t>(int2)};
  conn_bucket_cfg = ev_token_bucket_cfg_new(int1, int2, int3, int4, &cfg_tick);
  if (!conn_bucket_cfg) {
    goto cleanup;
  }

  bev_rate_group = bufferevent_rate_limit_group_new(base, conn_bucket_cfg);
  assert(bufferevent_add_to_rate_limit_group(bev4, bev_rate_group) != -1);

  /*write and read from buffer events*/
  bufferevent_write(bev3, s1.c_str(), s1.size());
  bufferevent_write(bev4, s2.c_str(), s2.size());
  bufferevent_write_buffer(bev3, bufferevent_get_input(bev4));

  evbuf = evbuffer_new();
  bufferevent_read_buffer(bev3, evbuf);
  evbuffer_free(evbuf);
  bufferevent_read(bev3, buf, sizeof(buf) - 1);
  bufferevent_remove_from_rate_limit_group(bev4);

  /*watermarks*/
  if (read_write == 0) {
    bufferevent_setwatermark(bev4, EV_READ, int1, int2);
    bufferevent_getwatermark(bev4, EV_READ, &int3, NULL);
    bufferevent_getwatermark(bev4, EV_READ, NULL, &int4);
  } else {
    bufferevent_setwatermark(bev4, EV_WRITE, int1, int2);
    bufferevent_getwatermark(bev4, EV_WRITE, &int3, NULL);
    bufferevent_getwatermark(bev4, EV_WRITE, NULL, &int4);
  }

  assert(int1 == int3);
  assert(int2 == int4);

  /*clean up*/
cleanup:
  if (bev3) {
    bufferevent_free(bev3);
  }
  if (bev4) {
    bufferevent_free(bev4);
  }
  if (conn_bucket_cfg) {
    ev_token_bucket_cfg_free(conn_bucket_cfg);
    conn_bucket_cfg = NULL;
  }

  if (bev_rate_group) {
    bufferevent_rate_limit_group_free(bev_rate_group);
  }

  event_base_free(base);

  return 0;
}
