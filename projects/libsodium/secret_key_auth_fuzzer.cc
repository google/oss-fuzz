#include <assert.h>
#include <stdlib.h>
#include <sodium.h>

#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  int initialized = sodium_init();
  assert(initialized >= 0);

  setup_fake_random(data, size);

  unsigned char key[crypto_auth_KEYBYTES];
  unsigned char mac[crypto_auth_BYTES];

  // this uses a deterministic generator
  crypto_auth_keygen(key);

  crypto_auth(mac, data, size, key);
  int err = crypto_auth_verify(mac, data, size, key);
  assert(err == 0);

  return 0;
}
