#include <assert.h>
#include <sodium.h>

class SodiumState {
public:
  SodiumState() {
    assert(sodium_init() == 0);
  }
};

SodiumState state;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  unsigned char key[crypto_auth_KEYBYTES];
  unsigned char mac[crypto_auth_BYTES];

  randombytes_buf_deterministic(key, crypto_auth_KEYBYTES, data);

  crypto_auth(mac, data, size, key);
  crypto_auth_verify(mac, data, size, key);

  return 0;
}
