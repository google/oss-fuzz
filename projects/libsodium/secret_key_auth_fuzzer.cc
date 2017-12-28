// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

#include <string>
extern "C" {
#include <sodium.h>
}

using std::string;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  if (sodium_init() == -1) {
    return 1;
  }

  unsigned char key[crypto_auth_KEYBYTES];
  unsigned char mac[crypto_auth_BYTES];

  crypto_auth_keygen(key);

  crypto_auth(mac, data, size, key);
  crypto_auth_verify(mac, data, size, key);

  return 0;
}
