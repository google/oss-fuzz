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
  // Prepare random data
  std::string string1 = fdp.ConsumeRandomLengthString(1024);
  std::string string2 = fdp.ConsumeRandomLengthString(1024);
  std::string string3 = fdp.ConsumeRandomLengthString(1024);
  const char *str1 = string1.c_str();
  const char *str2 = string2.c_str();
  const char *str3 = string3.c_str();

  // Fuzz mhd_str_equal_caseless_n
  mhd_str_equal_caseless_n(str1, str2, fdp.ConsumeIntegral<size_t>());

  // Fuzz mhd_str_equal_caseless_bin_n
  const size_t min_len = std::min(strlen(str1), strlen(str2));
  if (min_len) {
    mhd_str_equal_caseless_bin_n(str1, str2, min_len);
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
  struct MHD_String s_str3 {
    strlen(str3), str3
  };
  struct mhd_BufferConst str3_buf { 0, nullptr };
  mhd_str_starts_with_token_req_param(&s_str1, &s_str2, &s_str3, &str3_buf, &needs_uni);
}

static void fuzz_conversion(FuzzedDataProvider& fdp) {
  // Prepare random data
  std::string string = fdp.ConsumeRandomLengthString(1024);
  const char *str = string.c_str();

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
}

static void fuzz_decode(FuzzedDataProvider& fdp) {
  // Prepare random data
  bool ignored = false;
  std::string string = fdp.ConsumeRandomLengthString(1024);
  char *str = string.data();

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
}

static void fuzz_quoted(FuzzedDataProvider& fdp) {
  // Prepare random data
  std::string string1 = fdp.ConsumeRandomLengthString(1024);
  std::string string2 = fdp.ConsumeRandomLengthString(1024);
  const char *str1 = string1.c_str();
  const char *str2 = string2.c_str();

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
}

static void fuzz_base64(FuzzedDataProvider& fdp) {
  // Prepare random data
  std::string string = fdp.ConsumeRandomLengthString(1024);
  char *str = string.data();

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
