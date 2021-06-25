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

#include "fuzz.h"

extern "C" {
#include <sys/time.h>
#include "config.h"
#include "syshead.h"
#include "proxy.h"
#include "interval.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
}


extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    CRYPTO_malloc_init();
    SSL_library_init();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_digests();

    SSL_load_error_strings();
    return 1;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char *tmp = NULL;
  char *tmp2 = NULL;

  if (size < 500) {
    return 0;
  }
  FuzzedDataProvider provider(data, size);
  prov = &provider;

  struct gc_arena gc = gc_new();
  struct http_proxy_info pi;
  ssize_t generic_ssizet;
  int signal_received = 0;
  struct buffer lookahead = alloc_buf(1024);
  struct event_timeout evt;

  memset(&evt, 0, sizeof(struct event_timeout));
  memset(&pi, 0, sizeof(struct http_proxy_info));
  memset(&pi, 0, sizeof(pi));

  generic_ssizet = 0;
  std::string username = provider.ConsumeBytesAsString(
      (provider.ConsumeIntegralInRange<uint32_t>(1, USER_PASS_LEN)));
  strcpy(pi.up.username, username.c_str());
  if (strlen(pi.up.username) == 0) {
    gc_free(&gc);
    free_buf(&lookahead);
    return 0;
  }

  std::string pass = provider.ConsumeBytesAsString(
      (provider.ConsumeIntegralInRange<uint32_t>(1, USER_PASS_LEN)));
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
     pi.auth_method = HTTP_AUTH_BASIC;
    break;
  case 2:
    pi.auth_method = HTTP_AUTH_DIGEST;
    break;
  case 3:
    pi.auth_method = HTTP_AUTH_NTLM;
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

  char *tmp_authenticate = get_modifiable_string(provider);
  pi.proxy_authenticate = tmp_authenticate;

  if (provider.ConsumeProbability<double>() < 0.5) {

    tmp = get_modifiable_string(provider);
    pi.options.custom_headers[0].name = tmp;
    if (provider.ConsumeProbability<double>() < 0.5) {
      tmp2 = get_modifiable_string(provider);
      pi.options.custom_headers[0].content = tmp2;
    }
  }

  establish_http_proxy_passthru(&pi, 0, "1.2.3.4", "777", &evt, &lookahead,
                                &signal_received);
  free(pi.proxy_authenticate);
  gc_free(&gc);
  free_buf(&lookahead);

  if (tmp != NULL)  free(tmp);
  if (tmp2 != NULL) free(tmp2);
  return 0;
}
