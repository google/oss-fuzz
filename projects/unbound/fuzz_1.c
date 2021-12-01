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
#include "sldns/sbuffer.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  log_init("/tmp/foo", 0, NULL);
  char *bin = buf;
  struct regional* reg;

  struct sldns_buffer *pkt = sldns_buffer_new(1);
  sldns_buffer_new_frm_data(pkt, bin, len);

  reg = regional_create();

  struct msg_parse msg;
  struct edns_data edns;
  memset(&msg, 0, sizeof(struct msg_parse));
  memset(&edns, 0, sizeof(edns));
  if (parse_packet(pkt, &msg, reg) != LDNS_RCODE_NOERROR) {    
    goto out;
  }
  if (parse_extract_edns_from_response_msg(&msg, &edns, reg) != LDNS_RCODE_NOERROR) {
    goto out;
  }


  struct query_info qinfo_out;
  memset(&qinfo_out, 0, sizeof(struct query_info));
  qinfo_out.qname = (unsigned char *) "\03nic\02de";
  uint8_t *peter = (unsigned char *) "\02de";   // zonename  
  struct module_env env;
  memset(&env, 0, sizeof(struct module_env));
  struct config_file cfg;
  memset(&cfg, 0, sizeof(struct config_file));
  cfg.harden_glue = 1;    // crashes now, want to remove that later
  env.cfg = &cfg;

  struct iter_env ie;
  memset(&ie, 0, sizeof(struct iter_env));

  struct iter_priv priv;
  memset(&priv, 0, sizeof(struct iter_priv));
  ie.priv = &priv;
  scrub_message(pkt, &msg, &qinfo_out, peter, reg, &env, &ie);   
out:
  regional_destroy(reg);
  sldns_buffer_free(pkt);
  return 0;
}
