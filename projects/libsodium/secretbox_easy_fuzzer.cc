#include <string>
extern "C" {
  #include <sodium.h>
}

using std::string;

class SodiumState {
public:
  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  SodiumState() {
    sodium_init(); // this can fail with a non-zero return code
    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof nonce);
  }
};

SodiumState state;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  size_t ciphertext_len = crypto_secretbox_MACBYTES + size;
  unsigned char ciphertext[ciphertext_len];

  crypto_secretbox_easy(ciphertext, data, size, state.nonce, state.key);

  unsigned char decrypted[size];
  crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, state.nonce, state.key);

  return 0;
}
