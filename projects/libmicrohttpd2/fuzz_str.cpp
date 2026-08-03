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

#include "mhd_str.h"
#include "microhttpd2.h"


static void fuzz_tokens(FuzzedDataProvider& fdp) {
  // Prepare random string for string comparison
  std::string payload1 = fdp.ConsumeRandomLengthString(1024);
  std::string payload2 = fdp.ConsumeRandomLengthString(1024);
  std::string payload3 = fdp.ConsumeRandomLengthString(1024);
  const char *payload_str1 = payload1.c_str();
  const char *payload_str2 = payload2.c_str();
  const char *payload_str3 = payload3.c_str();
  size_t payload_size1 = payload1.size();
  size_t payload_size2 = payload2.size();
  size_t payload_size3 = payload3.size();

  // Fuzz mhd_str_equal_caseless
  mhd_str_equal_caseless(payload_str1, payload_str2);

  // Fuzz mhd_str_equal_caseless_n
  mhd_str_equal_caseless_n(payload_str1, payload_str2, fdp.ConsumeIntegral<size_t>());

  // Fuzz mhd_str_equal_caseless_bin_n
  const size_t min_len = std::min(payload_size1, payload_size2);
  if (min_len) {
    mhd_str_equal_caseless_bin_n(payload_str1, payload_str2, min_len);
  }

  // Fuzz mhd_str_has_token_caseless
  mhd_str_has_token_caseless(payload_str1, payload_str2, payload_size1);
  mhd_str_has_token_caseless(payload_str1, payload_str2, payload_size2);

  // Fuzz mhd_str_remove_token_caseless
  ssize_t out_sz = (ssize_t)fdp.ConsumeIntegralInRange<int>(1, 1024);
  char *out_buf = (char*) malloc((size_t)out_sz);
  mhd_str_remove_token_caseless(payload_str1, payload_size1, payload_str2, payload_size2,
                                out_buf, &out_sz);
  free(out_buf);

  // Fuzz mhd_str_starts_with_token_opt_param
  struct MHD_String mhd_str1 {
    payload_size1, payload_str1
  };
  struct MHD_String mhd_str2 {
    payload_size2, payload_str2
  };
  mhd_str_starts_with_token_opt_param(&mhd_str1, &mhd_str2);

  // Fuzz mhd_str_starts_with_token_req_param
  bool needs_uni = fdp.ConsumeBool();
  struct MHD_String mhd_str3 {
    payload_size3, payload_str3
  };
  struct mhd_BufferConst str3_buf { 0, nullptr };
  mhd_str_starts_with_token_req_param(&mhd_str1, &mhd_str2, &mhd_str3, &str3_buf, &needs_uni);
}

static void fuzz_conversion(FuzzedDataProvider& fdp) {
  // Prepare random string for string/int conversion
  std::string payload = fdp.ConsumeRandomLengthString(1024);
  const char *payload_str = payload.c_str();
  size_t payload_size = payload.size();

  uint_fast32_t u32 = 0;
  uint_fast64_t u64 = 0;
  char small[4], big[128];
  size_t max_len = fdp.ConsumeIntegralInRange<size_t>(0, payload_size);

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
  mhd_uint32_to_strx((uint_fast32_t)fdp.ConsumeIntegral<uint32_t>(), small, sizeof(small));
  mhd_uint32_to_strx((uint_fast32_t)fdp.ConsumeIntegral<uint32_t>(), big, sizeof(big));

  // Fuzz uint16 to string conversion with random payload
  mhd_uint16_to_str((uint_least16_t)fdp.ConsumeIntegralInRange<unsigned>(0, 65535), small, sizeof(small));
  mhd_uint16_to_str((uint_least16_t)fdp.ConsumeIntegralInRange<unsigned>(0, 65535), big, sizeof(big));

  // Fuzz uint8 to string conversion with random payload
  uint8_t min_digits = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);
  mhd_uint8_to_str_pad((uint8_t)fdp.ConsumeIntegral<uint8_t>(), min_digits, small, sizeof(small));
  mhd_uint8_to_str_pad((uint8_t)fdp.ConsumeIntegral<uint8_t>(), min_digits, big, sizeof(big));
}

static void fuzz_decode(FuzzedDataProvider& fdp) {
  // Prepare random data for string decode
  bool ignored = false;
  std::string payload = fdp.ConsumeRandomLengthString(1024);
  char *payload_str = payload.data();
  size_t payload_size = payload.size();

  // Fuzz decode functions with random payload
  char *out1 = (char*) malloc(payload_size);
  char *out2 = (char*) malloc(payload_size);
  if (out1) {
    mhd_str_pct_decode_strict_n(payload_str, payload_size, out1, payload_size);
  }
  if (out2) {
    mhd_str_pct_decode_lenient_n(payload_str, payload_size, out2, payload_size, &ignored);
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
  size_t payload_size1 = payload1.size();
  size_t payload_size2 = payload2.size();

  // Fuzz mhd_str_equal_quoted_bin_n with random string payload as binary
  mhd_str_equal_quoted_bin_n(payload_str1, payload_size1, payload_str2, payload_size2);

  // Fuzz mhd_str_equal_caseless_quoted_bin_n with random string payload as binary
  mhd_str_equal_caseless_quoted_bin_n(payload_str1, payload_size1, payload_str2, payload_size2);

  // Fuzz mhd_str_quote and mhd_str_unquote with random string payload
  size_t max_out = payload_size1 * 2;
  char *out = (char*) malloc(max_out);
  if (out) {
    mhd_str_quote(payload_str1, payload_size1, out, max_out);
    mhd_str_unquote(payload_str1, payload_size1, out);
  }
  free(out);

  max_out = payload_size2 * 2;
  out = (char*) malloc(max_out);
  if (out) {
    mhd_str_quote(payload_str2, payload_size2, out, max_out);
    mhd_str_unquote(payload_str2, payload_size2, out);
  }
  free(out);
}

static void fuzz_base64(FuzzedDataProvider& fdp) {
  // Prepare random data for base64 conversion
  std::string payload = fdp.ConsumeRandomLengthString(1024);
  char *payload_str = payload.data();
  size_t payload_size = payload.size();

  // Prepare a valid base64 string from random payload
  static const char valid_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (size_t i = 0; i < payload_size; i++) {
    payload_str[i] = valid_chars[((uint8_t)i) % 64];
  }

  // Fuzz mhd_base64_to_bin_n with the random base64 string
  size_t max_out = (payload.size() / 4) * 4;
  uint8_t* out = (uint8_t*) malloc(payload_size);
  if (out) {
    mhd_base64_to_bin_n(payload_str, payload_size, out, max_out);
    free(out);
  }
}

static void fuzz_transformation(FuzzedDataProvider& fdp) {
  // Fuzz targets in multiple rounds
  for (int i = 0; i < fdp.ConsumeIntegralInRange<unsigned>(1, 8); i++) {
    // Generate random integer
    int value = fdp.ConsumeIntegral<int>();

    // Fuzz conversion functions
    MHD_http_method_to_string(static_cast<MHD_HTTP_Method>(value));
    MHD_protocol_version_to_string(static_cast<MHD_HTTP_ProtocolVersion>(value));
  }
}

static void fuzz_hex_conversion(FuzzedDataProvider& fdp) {
  // Prepare random data for hex conversion
  std::string payload = fdp.ConsumeRandomLengthString(1024);
  char *payload_str = payload.data();
  size_t payload_size = payload.size();

  // Fuzz mhd_hex_to_bin with random payload
  uint8_t *bin_out = (uint8_t*) malloc(payload_size);
  if (bin_out) {
    mhd_hex_to_bin(payload_str, payload_size, bin_out);
    free(bin_out);
  }

  // Fuzz mhd_bin_to_hex with random payload
  char *hex_out = (char *) malloc(payload_size * 2);
  if (hex_out) {
    if (!payload.empty()) {
      mhd_bin_to_hex(payload_str, payload_size, hex_out);
    }
    free(hex_out);
  }

  char *hexz_out = (char *) malloc(payload_size * 2 + 1);
  if (hexz_out) {
    if (!payload.empty()) {
      mhd_bin_to_hex_z(payload_str, payload_size, hexz_out);
    }
    free(hexz_out);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  for (int i = 0; i < fdp.ConsumeIntegralInRange<unsigned>(1, 6); i++) {
    switch (fdp.ConsumeIntegralInRange<int>(0, 7)) {
      case 0: fuzz_tokens(fdp); break;
      case 1: fuzz_conversion(fdp); break;
      case 2: fuzz_decode(fdp); break;
      case 3: fuzz_quoted(fdp); break;
      case 4: fuzz_base64(fdp); break;
      case 5: fuzz_transformation(fdp); break;
      case 6: fuzz_hex_conversion(fdp); break;
    }
  }
  return 0;
}
