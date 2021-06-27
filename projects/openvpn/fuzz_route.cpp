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
//#include <fuzzer/FuzzedDataProvider.h>

#include "fuzz.h"

extern "C" {
#include <sys/time.h>
#include "config.h"
#include "syshead.h"
#include "proxy.h"
#include "interval.h"
#include "route.h"
#include "buffer.h"
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  struct env_set* es = NULL;
  struct route_option_list opt, *dest;
  struct route_list rl;
  struct gc_arena gc;

  // Initialisation
  memset(&opt, 0, sizeof(opt));
  es = env_set_create(&gc);

  add_route_to_option_list(&opt, "a", "b", "d", "c");

  // list init
  in_addr_t remote_host;
  ssize_t default_metric;
  //init_route_list(&rl, &opt, remote_endpoint,default_metric, remote_host, es); 

  gc_free(&rl.gc);
  gc_free(&gc);

  return 0;
}

