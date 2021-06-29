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

#include "config.h"
#include "syshead.h"
#include "init.h"
#include "proxy.h"
#include "interval.h"
#include "route.h"
#include "buffer.h"

#include "fuzz_randomizer.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  fuzz_random_init(data, size);

  struct route_option_list opt;
  struct route_list rl;

  // Initialisation
  memset(&opt, 0, sizeof(opt));

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
  char *tmp0 =  get_random_string();
  const char* remote_endpoint = tmp0;

  // init
  memset(&rl, 0, sizeof(struct route_list));
  init_route_list(&rl, &opt, remote_endpoint,default_metric, remote_host, c.es, &c); 

  // call 1  
  in_addr_t addr;
  route_list_add_vpn_gateway(&rl, c.es, addr);

  // call 2
  struct route_ipv4 r;
  struct route_option ro;
  char *tmp1 =  get_random_string();
  char *tmp2 =  get_random_string();
  char *tmp3 =  get_random_string();
  char *tmp4 =  get_random_string();
  ro.network = tmp1;
  ro.netmask = tmp2;
  ro.gateway = tmp3;
  ro.metric = tmp4;
  ro.next = NULL;

  memset(&r, 0, sizeof(struct route_ipv4));
  r.option = &ro;
  r.flags = RT_DEFINED;
  add_route(&r, NULL, 0, NULL, c.es, &c);
  


  gc_free(&rl.gc);
  env_set_destroy(c.es);
  context_gc_free(&c);

  free(tmp0);
  free(tmp1);
  free(tmp2);
  free(tmp3);
  free(tmp4);

  fuzz_random_destroy();

  return 0;
}

