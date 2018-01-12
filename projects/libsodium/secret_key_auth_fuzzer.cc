#include <sodium.h>

#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  setup_sodium_w_deterministic_random();

  unsigned char key[crypto_auth_KEYBYTES];
  unsigned char mac[crypto_auth_BYTES];

  crypto_auth(mac, data, size, key);
  crypto_auth_verify(mac, data, size, key);
  return 0;
}
