#include <assert.h>
#include <sodium.h>

const unsigned char key[crypto_auth_KEYBYTES] = {
  'k', 'e', 'y', 'k', 'e', 'y', 'k', 'e', 'y', 'k',
  'k', 'e', 'y', 'k', 'e', 'y', 'k', 'e', 'y', 'k',
  'k', 'e', 'y', 'k', 'e', 'y', 'k', 'e', 'y', 'k',
  'k', 'e'
};

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  int initialized = sodium_init();
  assert(initialized >= 0);

  unsigned char mac[crypto_auth_BYTES];

  crypto_auth(mac, data, size, key);
  crypto_auth_verify(mac, data, size, key);
  return 0;
}
