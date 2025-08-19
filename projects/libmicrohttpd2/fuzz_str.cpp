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
//
////////////////////////////////////////////////////////////////////////////////
#include <cstring>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "mhd_str.h"
}

static void fuzz_tokens(FuzzedDataProvider& fdp) {
  // Prepare random string for string comparison
  std::string payload1 = fdp.ConsumeRandomLengthString(1024);
  std::string payload2 = fdp.ConsumeRandomLengthString(1024);
  std::string payload3 = fdp.ConsumeRandomLengthString(1024);
  const char *payload_str1 = payload1.c_str();
  const char *payload_str2 = payload2.c_str();
  const char *payload_str3 = payload3.c_str();

  // Fuzz mhd_str_equal_caseless_n
  mhd_str_equal_caseless_n(payload_str1, payload_str2, fdp.ConsumeIntegral<size_t>());

  // Fuzz mhd_str_equal_caseless_bin_n
  const size_t min_len = std::min(strlen(payload_str1), strlen(payload_str2));
  if (min_len) {
    mhd_str_equal_caseless_bin_n(payload_str1, payload_str2, min_len);
  }

  // Fuzz mhd_str_has_token_caseless
  mhd_str_has_token_caseless(payload_str1, payload_str2, strlen(payload_str1));
  mhd_str_has_token_caseless(payload_str1, payload_str2, strlen(payload_str2));

  // Fuzz mhd_str_remove_token_caseless
  ssize_t out_sz = (ssize_t)fdp.ConsumeIntegralInRange<int>(1, 1024);
  char *out_buf = (char*) malloc((size_t)out_sz);
  mhd_str_remove_token_caseless(payload_str1, strlen(payload_str1), payload_str2, strlen(payload_str2),
                                out_buf, &out_sz);
  free(out_buf);

  // Fuzz mhd_str_starts_with_token_opt_param
  struct MHD_String mhd_str1 {
    strlen(payload_str1), payload_str1
  };
  struct MHD_String mhd_str2 {
    strlen(payload_str2), payload_str2
  };
  mhd_str_starts_with_token_opt_param(&mhd_str1, &mhd_str2);

  // Fuzz mhd_str_starts_with_token_req_param
  bool needs_uni = fdp.ConsumeBool();
  struct MHD_String mhd_str3 {
    strlen(payload_str3), payload_str3
  };
  struct mhd_BufferConst str3_buf { 0, nullptr };
  mhd_str_starts_with_token_req_param(&mhd_str1, &mhd_str2, &mhd_str3, &str3_buf, &needs_uni);
}

static void fuzz_conversion(FuzzedDataProvider& fdp) {
  // Prepare random string for string/int conversion
  std::string payload = fdp.ConsumeRandomLengthString(1024);
  const char *payload_str = payload.c_str();

  uint_fast32_t u32 = 0;
  uint_fast64_t u64 = 0;
  char small[4], big[128];
  size_t max_len = fdp.ConsumeIntegralInRange<size_t>(0, strlen(payload_str));

  // Fuzz conversion between string and uint64 with random payload
  mhd_str_to_uint64(payload_str, &u64);
  mhd_str_to_uint64_n(payload_str, max_len, &u64);
  mhd_strx_to_uint64(payload_str, &u64);
  mhd_strx_to_uint64_n(payload_str, max_len, &u64);
  mhd_uint64_to_str((uint_fast64_t)fdp.ConsumeIntegral<uint64_t>(), small, sizeof(small));
  mhd_uint64_to_str((uint_fast64_t)fdp.ConsumeIntegral<uint64_t>(), big, sizeof(big));

  // Fuzz string to uint32 conversion with random payload string
  mhd_strx_to_uint32(payload_str, &u32);
  mhd_strx_to_uint32_n(payload_str, max_len, &u32);

  // Fuzz uint16 to string conversion with random payload
  mhd_uint16_to_str((uint_least16_t)fdp.ConsumeIntegralInRange<unsigned>(0, 65535), small, sizeof(small));
  mhd_uint16_to_str((uint_least16_t)fdp.ConsumeIntegralInRange<unsigned>(0, 65535), big, sizeof(big));
}

static void fuzz_decode(FuzzedDataProvider& fdp) {
  // Prepare random data for string decode
  bool ignored = false;
  std::string payload = fdp.ConsumeRandomLengthString(1024);
  char *payload_str = payload.data();

  // Fuzz decode functions with random payload
  char *out1 = (char*) malloc(strlen(payload_str));
  char *out2 = (char*) malloc(strlen(payload_str));
  if (out1) {
    mhd_str_pct_decode_strict_n(payload_str, strlen(payload_str), out1, strlen(payload_str));
  }
  if (out2) {
    mhd_str_pct_decode_lenient_n(payload_str, strlen(payload_str), out2, strlen(payload_str), &ignored);
  }

  // Fuzz decode in place functions with random payload
  mhd_str_pct_decode_in_place_strict(payload_str);
  mhd_str_pct_decode_in_place_lenient(payload_str, &ignored);

  free(out1);
  free(out2);
}

static void fuzz_quoted(FuzzedDataProvider& fdp) {
  // Prepare random data for quote and equality check
  std::string payload1 = fdp.ConsumeRandomLengthString(1024);
  std::string payload2 = fdp.ConsumeRandomLengthString(1024);
  const char *payload_str1 = payload1.c_str();
  const char *payload_str2 = payload2.c_str();

  // Fuzz mhd_str_equal_quoted_bin_n with random string payload as binary
  mhd_str_equal_quoted_bin_n(payload_str1, strlen(payload_str1), payload_str2, strlen(payload_str2));

  // Fuzz mhd_str_quote with random string payload
  size_t max_out = strlen(payload_str1) * 2;
  char *out = (char*) malloc(max_out);
  if (out) {
    mhd_str_quote(payload_str1, strlen(payload_str1), out, max_out);
  }
  free(out);

  max_out = strlen(payload_str2) * 2;
  out = (char*) malloc(max_out);
  if (out) {
    mhd_str_quote(payload_str2, strlen(payload_str2), out, max_out);
  }

  free(out);
}

static void fuzz_base64(FuzzedDataProvider& fdp) {
  // Prepare random data for base64 conversion
  std::string payload = fdp.ConsumeRandomLengthString(1024);
  char *payload_str = payload.data();

  // Prepare a valid base64 string from random payload
  static const char valid_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (size_t i = 0; i < strlen(payload_str); i++) {
    payload_str[i] = valid_chars[((uint8_t)i) % 64];
  }

  // Pad the base64 string with ==
  if (strlen(payload_str) >= 1 && fdp.ConsumeBool()) {
    payload_str[strlen(payload_str) - 1] = '=';
  }
  if (strlen(payload_str) >= 2 && fdp.ConsumeBool()) {
    payload_str[strlen(payload_str) - 2] = '=';
  }

  // Fuzz mhd_base64_to_bin_n with the random base64 string
  size_t max_out = (strlen(payload_str) / 4) * 4;
  uint8_t* out = (uint8_t*) malloc(strlen(payload_str));
  if (out) {
    mhd_base64_to_bin_n(payload_str, strlen(payload_str), out, max_out);
    free(out);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  for (int i = 0; i < fdp.ConsumeIntegralInRange<unsigned>(1, 6); i++) {
    switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
      case 0: fuzz_tokens(fdp); break;
      case 1: fuzz_conversion(fdp); break;
      case 2: fuzz_decode(fdp); break;
      case 3: fuzz_quoted(fdp); break;
      case 4: fuzz_base64(fdp); break;
    }
  }
  return 0;
}
