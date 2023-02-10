// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>

#include "libevent/include/event2/http.h"
#include "libevent/include/event2/keyvalq_struct.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string fuzz_string(reinterpret_cast<const char *>(data), size);
  struct evkeyvalq headers;
  if (evhttp_parse_query(fuzz_string.c_str(), &headers) == 0) {
    evhttp_clear_headers(&headers);
  }

  if (size > 4) {
    uint32_t flags = *(uint32_t *)data;
    data += 4;
    size -= 4;
    std::string fuzz_string2(reinterpret_cast<const char *>(data), size);

    if (evhttp_parse_query_str_flags(fuzz_string2.c_str(), &headers, flags) == 0) {
      evhttp_clear_headers(&headers);
    }
  }

  return 0;
}
