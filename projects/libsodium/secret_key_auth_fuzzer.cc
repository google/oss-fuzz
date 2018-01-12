#include <assert.h>
#include <sodium.h>

#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  assert(randombytes_set_implementation(&fake_random) == 0);
  assert(randombytes_implementation_name() == "fake_random");
  assert(sodium_init() >= 0);

  unsigned char key[crypto_auth_KEYBYTES];
  unsigned char mac[crypto_auth_BYTES];

  crypto_auth(mac, data, size, key);
  crypto_auth_verify(mac, data, size, key);
  return 0;
}
