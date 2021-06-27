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

//#include "fuzz.h"

//extern "C" {
//#include <sys/time.h>
#include "config.h"
#include "syshead.h"
#include "init.h"
#include "proxy.h"
#include "interval.h"
#include "route.h"
#include "buffer.h"
//}

ssize_t fuzz_get_random_data(void *buf, size_t len) {
	return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  //FuzzedDataProvider provider(data, size);

  //struct env_set* es = NULL;
  struct route_option_list opt, *dest;
  struct route_list rl;
  //struct gc_arena gc;

  // Initialisation
  memset(&opt, 0, sizeof(opt));
/*
  gc = gc_new();
  es = env_set_create(&gc);

  opt.gc = &gc;
  add_route_to_option_list(&opt, "a", "b", "d", "c");

  // list init
  //remote_endpoint = provider.ConsumeRandomLengthString().c_str();
  */
  struct context c;
  memset(&c, 0, sizeof(struct context));
  gc_init(&c.gc);
  c.es = env_set_create(&c.gc);
  init_options(&c.options, true);
  net_ctx_init(&c, &c.net_ctx);
  init_verb_mute(&c, IVM_LEVEL_1);

  init_options_dev(&c.options);
  
  //options_postprocess(&c.options);
  pre_setup(&c.options);

  setenv_settings(c.es, &c.options);

  ALLOC_OBJ_CLEAR_GC(c.options.connection_list, struct connection_list, &c.options.gc);
  context_init_1(&c);

  in_addr_t remote_host;
  ssize_t default_metric;
  const char* remote_endpoint = "adsgas";

  // init
  memset(&rl, 0, sizeof(struct route_list));
  init_route_list(&rl, &opt, remote_endpoint,default_metric, remote_host, &c.es, &c); 

  // call 1  
  in_addr_t addr;
  route_list_add_vpn_gateway(&rl, &c.es, addr);

  // call 2
  struct route_ipv4 r;
  struct route_option ro;
  ro.network = "aasdf";
  ro.netmask = "234234";
  ro.gateway = "2341243";
  ro.metric = ";sdkf;sldkf";
  ro.next = NULL;

  memset(&r, 0, sizeof(struct route_ipv4));
  r.option = &ro;

  add_route(&r, NULL, 0, NULL, &c.es, &c);
  


  gc_free(&rl.gc);
  //gc_free(&gc);
  //gc_free(&rl);
  env_set_destroy(c.es);
  context_gc_free(&c);

  return 0;
}

