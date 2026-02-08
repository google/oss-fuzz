/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Fuzz neovim's base64 encode/decode implementation.
 *
 * Neovim has its own optimized base64 codec in src/nvim/base64.c that uses
 * 8-byte-at-a-time processing with endian conversion. This fuzzer tests
 * both decoding arbitrary (potentially malformed) input and round-tripping
 * through encode→decode.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Stub implementations of neovim's memory functions.
 * Same rationale as in fuzz_nvim_vterm.c.
 */
void *xmalloc(size_t size) {
  void *p = malloc(size ? size : 1);
  if (!p) abort();
  return p;
}

void xfree(void *p) {
  free(p);
}

void *xcalloc(size_t count, size_t size) {
  void *p = calloc(count ? count : 1, size ? size : 1);
  if (!p) abort();
  return p;
}

void *xrealloc(void *p, size_t size) {
  void *r = realloc(p, size ? size : 1);
  if (!r) abort();
  return r;
}

void *xmallocz(size_t size) {
  void *p = xmalloc(size + 1);
  ((char *)p)[size] = '\0';
  return p;
}

void *xmemdupz(const void *data, size_t len) {
  void *p = xmallocz(len);
  memcpy(p, data, len);
  return p;
}

void preserve_exit(const char *errmsg) {
  (void)errmsg;
  abort();
}

/* Forward declarations from nvim/base64.h */
char *base64_encode(const char *src, size_t src_len);
char *base64_decode(const char *src, size_t src_len, size_t *out_lenp);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 4096)
    return 0;

  /* Mode 0: decode arbitrary data (test malformed input handling) */
  /* Mode 1: encode then decode (round-trip consistency) */
  int mode = data[0] & 1;
  const char *input = (const char *)(data + 1);
  size_t input_len = size - 1;

  if (mode == 0) {
    /* Try to decode potentially malformed base64 */
    size_t out_len = 0;
    char *decoded = base64_decode(input, input_len, &out_len);
    if (decoded) {
      xfree(decoded);
    }
  } else {
    /* Encode raw bytes, then decode back and verify round-trip */
    char *encoded = base64_encode(input, input_len);
    if (encoded) {
      size_t decoded_len = 0;
      char *decoded = base64_decode(encoded, strlen(encoded), &decoded_len);
      if (decoded) {
        /* Verify round-trip: decoded output must match original input */
        if (decoded_len != input_len ||
            memcmp(decoded, input, input_len) != 0) {
          abort(); /* Round-trip failure is a bug */
        }
        xfree(decoded);
      }
      xfree(encoded);
    }
  }

  return 0;
}
