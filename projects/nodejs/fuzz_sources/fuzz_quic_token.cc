// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * A fuzzer focused on node::quic::RegularToken validation.
 */

#include <stdlib.h>
#include <quic/cid.h>
#include <quic/tokens.h>
#include "env-inl.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 17) {
    return 0;
  }
  uint8_t *sec_token_data = (uint8_t *)malloc(16);
  memcpy(sec_token_data, data, 16);

  node::quic::TokenSecret secret(sec_token_data);
  data+=16;
  size-=16;

  uint8_t *regular_token_data = (uint8_t *)malloc(size);
  memcpy(regular_token_data, data, size);

  node::quic::RegularToken token(regular_token_data, size);
  node::SocketAddress address;
  CHECK(node::SocketAddress::New(AF_INET, "123.123.123.123", 1234, &address));
  token.Validate(NGTCP2_PROTO_VER_MAX,
                       address,
                       secret,
                       // Set a large expiration just to be safe
                       10000000000);
  free(sec_token_data);
  free(regular_token_data);
  return 0;
}
