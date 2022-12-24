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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>

#include "libevent/include/event2/event.h"
#include "libevent/include/event2/util.h"
#include "util-internal.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int r;
  int len;
  char out_buf[128];
  struct sockaddr_storage ss;
  std::string fuzz_string(reinterpret_cast<const char *>(data), size);

  r = evutil_parse_sockaddr_port(
        fuzz_string.c_str(), (struct sockaddr*)&ss, &len);
  if (r == 0) {
    evutil_format_sockaddr_port_((struct sockaddr*)&ss,
                                 out_buf,
                                 sizeof(out_buf));
  }

  return 0;
}
