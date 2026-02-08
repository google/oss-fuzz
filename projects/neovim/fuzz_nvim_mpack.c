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
 * Fuzz neovim's bundled mpack (MessagePack) tokenizer.
 *
 * Neovim uses MessagePack as the wire format for its RPC API (the protocol
 * between neovim and UI clients, plugins, etc.). The mpack library under
 * src/mpack/ is a minimal C implementation that tokenizes msgpack data.
 *
 * This fuzzer is completely standalone — mpack has NO dependencies on
 * neovim internals (no xmalloc, no nvim headers). It only uses standard C.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* mpack API — include the header directly from neovim's source tree */
#include "mpack/mpack_core.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 8192)
    return 0;

  mpack_tokbuf_t tokbuf;
  mpack_token_t tok;

  mpack_tokbuf_init(&tokbuf);

  const char *buf = (const char *)data;
  size_t buflen = size;

  /* Read all tokens from the msgpack data until exhausted or error */
  while (buflen > 0) {
    int rc = mpack_read(&tokbuf, &buf, &buflen, &tok);
    if (rc == MPACK_ERROR) {
      break; /* Invalid msgpack — expected for fuzz input */
    }
    if (rc == MPACK_EOF) {
      break; /* Need more data — input exhausted */
    }
    /* MPACK_OK — token parsed successfully, continue */
  }

  return 0;
}
