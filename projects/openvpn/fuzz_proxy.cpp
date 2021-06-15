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
#include "proxy.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  struct gc_arena gc = gc_new();
  struct http_proxy_info pi;
  ssize_t generic_ssizet;
  int signal_received = 0;
  struct buffer lookahead = alloc_buf(1024);

  memset(&pi, 0, sizeof(pi));
  pi.proxy_authenticate = NULL;

  generic_ssizet = 0;
  std::string username = provider.ConsumeBytesAsString(
      (provider.ConsumeIntegralInRange<uint32_t>(1, 100)));
  strcpy(pi.up.username, username.c_str());
  if (strlen(pi.up.username) == 0) {
    gc_free(&gc);
    free_buf(&lookahead);
    return 0;
  }

  std::string pass = provider.ConsumeBytesAsString(
      (provider.ConsumeIntegralInRange<uint32_t>(1, 100)));
  strcpy(pi.up.password, pass.c_str());
  if (strlen(pi.up.password) == 0) {
    gc_free(&gc);
    free_buf(&lookahead);
    return 0;
  }

  generic_ssizet = provider.ConsumeIntegralInRange(0, 4);
  switch (generic_ssizet) {
  case 0:
    pi.auth_method = HTTP_AUTH_NONE;
    break;
  case 1:
    pi.auth_method = HTTP_AUTH_NONE;
    // pi.auth_method = HTTP_AUTH_BASIC;
    break;
  case 2:
    // pi.auth_method = HTTP_AUTH_DIGEST;
    pi.auth_method = HTTP_AUTH_NONE;
    break;
  case 3:
    // pi.auth_method = HTTP_AUTH_NTLM;
    pi.auth_method = HTTP_AUTH_NONE;
    break;
  case 4:
    pi.auth_method = HTTP_AUTH_NTLM2;
    break;
  }
  pi.options.http_version = "1.1";

  generic_ssizet = provider.ConsumeIntegralInRange(0, 4);
  switch (generic_ssizet) {
  case 0:
    pi.options.auth_retry = PAR_NO;
    break;
  case 1:
    pi.options.auth_retry = PAR_ALL;
    break;
  case 2:
    pi.options.auth_retry = PAR_NCT;
    break;
  }

  std::string proxy_authenticate = provider.ConsumeBytesAsString(
      (provider.ConsumeIntegralInRange<uint32_t>(1, 100)));
  char *tmp_authenticate = (char *)malloc(proxy_authenticate.size());
  memcpy(tmp_authenticate, proxy_authenticate.c_str(),
         proxy_authenticate.size());
  pi.proxy_authenticate = tmp_authenticate;
  establish_http_proxy_passthru(&pi, 0, "1.2.3.4", "777", NULL, &lookahead,
                                &signal_received);
  free(pi.proxy_authenticate);
  gc_free(&gc);
  free_buf(&lookahead);
  return 0;
}
