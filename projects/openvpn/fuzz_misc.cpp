/* Copyright 2021 Google LLC
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
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "config.h"
#include "syshead.h"
#include "misc.h"
#include "buffer.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  struct gc_arena gc;
  struct env_set *es;
  gc = gc_new();
  es = env_set_create(&gc);

  int total_to_fuzz = provider.ConsumeIntegralInRange(1, 10);
  for (int i = 0; i < total_to_fuzz; i++) {
    int type = provider.ConsumeIntegralInRange(1, 7);
    std::string inp1 = provider.ConsumeRandomLengthString();
    std::string inp2 = provider.ConsumeRandomLengthString();

    switch (type) {
    case 0:
      env_set_del(es, inp1.c_str());
      break;
    case 1:
      env_set_add(es, inp2.c_str());
      break;
    case 2:
      env_set_get(es, inp1.c_str());
      break;
    case 3:
      if (strlen(inp1.c_str()) > 1 && strlen(inp2.c_str()) > 1) {
        setenv_str(es, inp2.c_str(), inp1.c_str());
      }
      break;
    case 4:
      hostname_randomize(inp1.c_str(), &gc);
      break;
    case 5:
      if (strlen(inp1.c_str()) > 0) {
        get_auth_challenge(inp1.c_str(), &gc);
      }
      break;
    default:
      sanitize_control_message(inp1.c_str(), &gc);
    }
  }

  env_set_destroy(es);
  gc_free(&gc);

  return 0;
}
