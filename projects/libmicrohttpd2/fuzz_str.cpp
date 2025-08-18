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

static inline char *generate_cstr(const std::vector<uint8_t>& vec, bool sanitise) {
  char *ptr = (char*) malloc(vec.size() + 1);
  if (!ptr) {
    return nullptr;
  }

  if (sanitise) {
    for (size_t i = 0; i < vec.size(); i++) {
      char c = (char) vec[i];
      if (c == 0 || c == ' ' || c == '\t' || c == ',' || c == '=') {
        c = '_';
      }
      ptr[i] = c;
    }
  } else {
    if (vec.size()) {
      memcpy(ptr, vec.data(), vec.size());
    }
  }

  ptr[vec.size()] = '\0';
  return ptr;
}

static void fuzz_tokens(FuzzedDataProvider& fdp) {
  // Prepare random data
  std::vector<uint8_t> raw1 = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  std::vector<uint8_t> raw2 = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));

  char *str1 = generate_cstr(raw1, fdp.ConsumeBool());
  char *str2 = generate_cstr(raw2, fdp.ConsumeBool());
  if (!str1 || !str2) {
    free(str1);
    free(str2);
    return;
  }

  // Fuzz mhd_str_equal_caseless_n
  mhd_str_equal_caseless_n(str1, str2, fdp.ConsumeIntegral<size_t>());

  // Fuzz mhd_str_equal_caseless_bin_n
  const size_t min_len = std::min(raw1.size(), raw2.size());
  if (min_len) {
    char *bin1 = (char*)malloc(raw1.size());
    char *bin2 = (char*)malloc(raw2.size());
    if (bin1 && bin2) {
      if (!raw1.empty()) {
        memcpy(bin1, raw1.data(), raw1.size());
      }
      if (!raw2.empty()) {
        memcpy(bin2, raw2.data(), raw2.size());
      }

      mhd_str_equal_caseless_bin_n(bin1, bin2, min_len);
    }
    free(bin1);
    free(bin2);
  }

  // Fuzz mhd_str_has_token_caseless
  mhd_str_has_token_caseless(str1, str2, strlen(str1));
  mhd_str_has_token_caseless(str1, str2, strlen(str2));

  // Fuzz mhd_str_remove_token_caseless
  ssize_t out_sz = (ssize_t)fdp.ConsumeIntegralInRange<int>(1, 1024);
  char *out_buf = (char*) malloc((size_t)out_sz);
  mhd_str_remove_token_caseless(str1, strlen(str1), str2, strlen(str2),
                                out_buf, &out_sz);
  free(out_buf);

  // Fuzz mhd_str_starts_with_token_opt_param
  struct MHD_String s_str1 {
    strlen(str1), str1
  };
  struct MHD_String s_str2 {
    strlen(str2), str2
  };
  mhd_str_starts_with_token_opt_param(&s_str1, &s_str2);

  // Fuzz mhd_str_starts_with_token_req_param
  bool needs_uni = fdp.ConsumeBool();
  std::vector<uint8_t> raw3 = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  char *str3 = generate_cstr(raw3, fdp.ConsumeBool());
  struct MHD_String s_str3 {
    strlen(str3), str3
  };
  struct mhd_BufferConst str3_buf { 0, nullptr };
  mhd_str_starts_with_token_req_param(&s_str1, &s_str2, &s_str3, &str3_buf, &needs_uni);

  free(str1);
  free(str2);
  free(str3);
}

static void fuzz_conversion(FuzzedDataProvider& fdp) {
  // Prepare random data
  std::vector<uint8_t> raw = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  char *str = generate_cstr(raw, fdp.ConsumeBool());

  if (!str) {
    free(str);
    return;
  }

  uint_fast32_t u32 = 0;
  uint_fast64_t u64 = 0;
  char small[4], big[128];
  size_t max_len = fdp.ConsumeIntegralInRange<size_t>(0, strlen(str));

  // Fuzz unint64 conversion
  mhd_str_to_uint64(str, &u64);
  mhd_str_to_uint64_n(str, max_len, &u64);
  mhd_strx_to_uint64(str, &u64);
  mhd_strx_to_uint64_n(str, max_len, &u64);
  mhd_uint64_to_str((uint_fast64_t)fdp.ConsumeIntegral<uint64_t>(), small, sizeof(small));
  mhd_uint64_to_str((uint_fast64_t)fdp.ConsumeIntegral<uint64_t>(), big, sizeof(big));

  // Fuzz uint32 conversion
  mhd_strx_to_uint32(str, &u32);
  mhd_strx_to_uint32_n(str, max_len, &u32);

  // Fuzz uint16 conversion
  mhd_uint16_to_str((uint_least16_t)fdp.ConsumeIntegralInRange<unsigned>(0, 65535), small, sizeof(small));
  mhd_uint16_to_str((uint_least16_t)fdp.ConsumeIntegralInRange<unsigned>(0, 65535), big, sizeof(big));

  free(str);
}

static void fuzz_decode(FuzzedDataProvider& fdp) {
  // Prepare random data
  bool ignored = false;
  std::vector<uint8_t> raw = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  char *str = generate_cstr(raw, fdp.ConsumeBool());

  if (!str) {
    free(str);
    return;
  }

  // Fuzz decode functions
  char *out1 = (char*) malloc(strlen(str));
  char *out2 = (char*) malloc(strlen(str));
  if (out1) {
    mhd_str_pct_decode_strict_n(str, strlen(str), out1, strlen(str));
  }
  if (out2) {
    mhd_str_pct_decode_lenient_n(str, strlen(str), out2, strlen(str), &ignored);
  }

  // Fuzz decode in place functions
  mhd_str_pct_decode_in_place_strict(str);
  mhd_str_pct_decode_in_place_lenient(str, &ignored);

  free(out1);
  free(out2);
  free(str);
}

static void fuzz_quoted(FuzzedDataProvider& fdp) {
  // Prepare random data
  std::vector<uint8_t> raw1 = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  std::vector<uint8_t> raw2 = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));

  char *str1 = generate_cstr(raw1, fdp.ConsumeBool());
  char *str2 = generate_cstr(raw2, fdp.ConsumeBool());
  if (!str1 || !str2) {
    free(str1);
    free(str2);
    return;
  }

  // Fuzz mhd_str_equal_quoted_bin_n
  mhd_str_equal_quoted_bin_n(str1, strlen(str1), str2, strlen(str2));

  // Fuzz mhd_str_quote
  size_t max_out = strlen(str1) * 2;
  char *out = (char*) malloc(max_out);
  if (out) {
    mhd_str_quote(str1, strlen(str1), out, max_out);
  }
  free(out);

  max_out = strlen(str2) * 2;
  out = (char*) malloc(max_out);
  if (out) {
    mhd_str_quote(str2, strlen(str2), out, max_out);
  }

  free(out);
  free(str1);
  free(str2);
}

static void fuzz_base64(FuzzedDataProvider& fdp) {
  // Prepare random data
  std::vector<uint8_t> raw = fdp.ConsumeBytes<uint8_t>(
      fdp.ConsumeIntegralInRange<size_t>(0, 1024));
  char *str = generate_cstr(raw, fdp.ConsumeBool());

  if (!str) {
    free(str);
    return;
  }

  // Prepare a base64 string
  static const char valid_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (size_t i = 0; i < strlen(str); i++) {
    str[i] = valid_chars[((uint8_t)i) % 64];
  }

  // Pad the base 64 with ==
  if (strlen(str) >= 1 && fdp.ConsumeBool()) {
    str[strlen(str) - 1] = '=';
  }
  if (strlen(str) >= 2 && fdp.ConsumeBool()) {
    str[strlen(str) - 2] = '=';
  }

  // Fuzz mhd_base64_to_bin_n
  size_t max_out = (strlen(str) / 4) * 4;
  uint8_t* out = (uint8_t*) malloc(strlen(str));
  if (out) {
    mhd_base64_to_bin_n(str, strlen(str), out, max_out);
    free(out);
  }

  free(str);
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
