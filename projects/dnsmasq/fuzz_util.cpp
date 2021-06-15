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

extern "C" {
#include "dnsmasq.h"
}

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  std::string inp1 = provider.ConsumeRandomLengthString();
  std::string inp2 = provider.ConsumeRandomLengthString();

  // Util logic
  hostname_isequal(inp1.c_str(), inp2.c_str());

  legal_hostname((char *)inp1.c_str());
  char *tmp = canonicalise((char *)inp1.c_str(), NULL);
  if (tmp != NULL) {
    free(tmp);
  }

  char *tmp_out = (char *)malloc(30);
  int mac_type;
  parse_hex((char *)inp1.c_str(), (unsigned char *)tmp_out, 30, NULL, NULL);
  parse_hex((char *)inp1.c_str(), (unsigned char *)tmp_out, 30, NULL,
            &mac_type);
  free(tmp_out);

  wildcard_match((char *)inp1.c_str(), (char *)inp2.c_str());
  if (inp1.size() < inp2.size()) {
    wildcard_matchn(inp1.c_str(), inp2.c_str(), inp1.size());
  } else {
    wildcard_matchn(inp1.c_str(), inp2.c_str(), inp2.size());
  }
  hostname_issubdomain((char *)inp1.c_str(), (char *)inp2.c_str());

  // rfc1035-related logic
  size_t plen = sizeof(struct dns_header) + size;
  char *tmp_dns_packet = (char *)malloc(plen);
  char *tmp3 = tmp_dns_packet + sizeof(struct dns_header);
  memcpy(tmp3, data, size);

  extract_name((struct dns_header *)tmp_dns_packet, plen,
               (unsigned char **)&tmp3, (char *)inp1.c_str(), 0, 0);
  free(tmp_dns_packet);

  union all_addr addr;
  in_arpa_name_2_addr((char *)inp1.c_str(), &addr);

  return 0;
}
