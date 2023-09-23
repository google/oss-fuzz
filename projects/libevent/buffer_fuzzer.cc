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
#include "util-internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider data_provider(data, size);

  std::string s1 = data_provider.ConsumeRandomLengthString();
  std::string s2 = data_provider.ConsumeRandomLengthString();
  std::string s3 = data_provider.ConsumeRandomLengthString();
  std::string s4 = data_provider.ConsumeRandomLengthString();

  struct evbuffer *buf = evbuffer_new();
  size_t sz;
  evbuffer_add(buf, s1.c_str(), s1.size());
  char *cp = NULL;
  cp = evbuffer_readln(buf, &sz, EVBUFFER_EOL_ANY);
  if (cp != NULL) {
    free(cp);
    cp = NULL;
  }
  struct evbuffer *buf2 = evbuffer_new();
  evbuffer_add(buf2, s1.c_str(), s1.size());
  evbuffer_add_reference(buf2, s2.c_str(), s2.size(), NULL, NULL);
  evbuffer_add_buffer(buf, buf2);
  evbuffer_expand(buf, 2000);
  evbuffer_pullup(buf, 2);
  evbuffer_prepend(buf, s3.c_str(), s3.size());
  evbuffer_prepend_buffer(buf, buf2);
  evbuffer_find(buf2, (const unsigned char *)s4.c_str(), s4.size());

  evbuffer_free(buf);
  evbuffer_free(buf2);

  return 0;
}
