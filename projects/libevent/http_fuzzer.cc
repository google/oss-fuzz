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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "libevent/include/event2/event.h"
#include "libevent/include/event2/buffer.h"
#include "libevent/include/event2/buffer_compat.h"
#include "libevent/include/event2/util.h"
#include "libevent/include/event2/event.h"
#include "libevent/include/event2/http.h"
#include "libevent/include/event2/http_struct.h"
#include "libevent/include/event2/buffer.h"
#include "libevent/include/event2/bufferevent.h"
#include "libevent/http-internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }
  // Prepare in case it's used.
  struct evhttp_connection evcon;
  evcon.ext_method_cmp = NULL;

  struct evhttp *http_val = NULL;
  http_val = evhttp_new(NULL);
  if (http_val == NULL) {
    return 0;
  }
  evcon.http_server = http_val;

  // Decider to determine which request type to parse.
  uint8_t decider = data[0];
  data++;
  size--;

  FuzzedDataProvider data_provider(data, size);
  std::string s1 = data_provider.ConsumeRandomLengthString();

  struct evbuffer *buf = evbuffer_new();
  evbuffer_add(buf, s1.c_str(), s1.size());

  struct evhttp_request *req = evhttp_request_new(NULL, NULL);

  // Use either the defailt request type or EVHTTP_REQUEST
  if (decider % 2 == 1) {
    req->kind=EVHTTP_REQUEST;
    req->evcon = &evcon;
  }

  enum message_read_status data_read;

  data_read = evhttp_parse_firstline_(req, buf);
  if (data_read != ALL_DATA_READ) {
    data_read = evhttp_parse_headers_(req, buf);
    if (data_read != ALL_DATA_READ) {
      data_read = evhttp_parse_headers_(req, buf);
      if (data_read != ALL_DATA_READ) {
        evhttp_request_get_input_headers(req);
      }
    }
  }
  evhttp_request_get_host(req);

  char *encoded = evhttp_encode_uri(s1.c_str());
  if (encoded != NULL) {
    free(encoded);
  }

  // Cleanup
  evhttp_request_free(req);
  evbuffer_free(buf);
  evhttp_free(http_val);
  return 0;
}
