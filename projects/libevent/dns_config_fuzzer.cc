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

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "libevent/include/event2/buffer.h"
#include "libevent/include/event2/bufferevent.h"
#include "libevent/include/event2/dns.h"
#include "libevent/include/event2/event.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider data_provider(data, size);

  uint32_t flags = data_provider.ConsumeIntegral<uint32_t>();
  std::string s1 = data_provider.ConsumeRandomLengthString();
  std::string s2 = data_provider.ConsumeRandomLengthString();

  struct event_base *base = NULL;
  struct evdns_base *dns = NULL;

  base = event_base_new();
  dns = evdns_base_new(base, flags % 65537);

  /* Create resolv.conf file*/
  char resolvFilename[50];
  sprintf(resolvFilename, "/tmp/resolv.%d", getpid());
  FILE *fp = fopen(resolvFilename, "wb");
  if (!fp) {
    goto cleanup;
  }
  fwrite(s1.c_str(), s1.size(), 1, fp);
  fclose(fp);

  evdns_base_resolv_conf_parse(dns, flags % 17, resolvFilename);

  /* Create /etc/hosts file*/
  char hostsFilename[50];
  sprintf(hostsFilename, "/tmp/hosts.%d", getpid());
  fp = fopen(hostsFilename, "wb");
  if (!fp) {
    unlink(resolvFilename);
    goto cleanup;
  }
  fwrite(s2.c_str(), s2.size(), 1, fp);
  fclose(fp);

  evdns_base_load_hosts(dns, hostsFilename);
  evdns_base_search_ndots_set(dns, flags);

  unlink(resolvFilename);
  unlink(hostsFilename);
  evdns_base_search_clear(dns);
  evdns_base_clear_host_addresses(dns);

  /*clean up*/
cleanup:
  evdns_base_free(dns, 0);
  event_base_free(base);
  return 0;
}
