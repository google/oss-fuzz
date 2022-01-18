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

/*
 * unbound-fuzzme.c - parse a packet provided on stdin (for fuzzing).
 *
 */
#include "config.h"
#include "util/regional.h"
#include "util/module.h"
#include "util/config_file.h"
#include "iterator/iterator.h"
#include "iterator/iter_priv.h"
#include "iterator/iter_scrub.h"
#include "util/log.h"
#include "util/netevent.h"
#include "util/alloc.h"
#include "sldns/sbuffer.h"
#include "services/cache/rrset.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t nr) {
  log_init("/tmp/foo", 0, NULL);
  struct regional* reg;

  struct sldns_buffer *pkt = sldns_buffer_new(1);
  sldns_buffer_new_frm_data(pkt, buf, nr);

  reg = regional_create();

  struct msg_parse msg;
  struct edns_data edns;
  memset(&msg, 0, sizeof(struct msg_parse));
  memset(&edns, 0, sizeof(edns));

  struct query_info qinfo_out;
  memset(&qinfo_out, 0, sizeof(struct query_info));
  qinfo_out.qname = (unsigned char *) "\03nic\02de";
  uint8_t *peter = (unsigned char *) "\02de";   // zonename  
  struct module_env env;
  memset(&env, 0, sizeof(struct module_env));
  struct config_file cfg;
  memset(&cfg, 0, sizeof(struct config_file));

  cfg.harden_glue = 0;    // crashes now, want to remove that later
  env.cfg = &cfg;
  cfg.rrset_cache_slabs = HASH_DEFAULT_SLABS;
  cfg.rrset_cache_size = HASH_DEFAULT_MAXMEM;

  struct comm_base* base = comm_base_create(0);
  comm_base_timept(base, &env.now, &env.now_tv);

  env.alloc = malloc(sizeof(struct alloc_cache));
  alloc_init(env.alloc, NULL, 0);

  env.rrset_cache = rrset_cache_create(env.cfg, env.alloc);
  

  struct iter_env ie;
  memset(&ie, 0, sizeof(struct iter_env));

  struct iter_priv priv;
  memset(&priv, 0, sizeof(struct iter_priv));
  ie.priv = &priv;


  if (parse_packet(pkt, &msg, reg) != LDNS_RCODE_NOERROR) {    
    goto out;
  }
  if (parse_extract_edns_from_response_msg(&msg, &edns, reg) != LDNS_RCODE_NOERROR) {
    goto out;
  }


  scrub_message(pkt, &msg, &qinfo_out, peter, reg, &env, &ie);   

out:
  rrset_cache_delete(env.rrset_cache);
  alloc_clear(env.alloc);
  free(env.alloc);
  comm_base_delete(base);
  regional_destroy(reg);
  sldns_buffer_free(pkt);
  return 0;
}
