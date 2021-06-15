/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "config.h"
#include "syshead.h"
#include "misc.h"
#include "buffer.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  struct gc_arena gc;
  struct buffer *bufp;
  struct buffer buf, buf2;
  struct buffer_list *buflistp = NULL;

  gc = gc_new();
  bufp = NULL;

  std::string inp1 = provider.ConsumeRandomLengthString();
  std::string inp2 = provider.ConsumeRandomLengthString();

  // Single buffer testing
  buf = string_alloc_buf(inp1.c_str(), &gc);
  bufp = &buf;

  buf_clear(bufp);
  buf2 = clone_buf(bufp);
  free_buf(&buf2);

  buf_defined(bufp);
  buf_str(bufp);
  buf_len(bufp);
  buf_bend(bufp);
  buf_bptr(bufp);

  skip_leading_whitespace(inp1.c_str());

  buf_string_match_head_str(bufp, inp1.c_str());

  buf_reverse_capacity(bufp);
  buf_forward_capacity_total(bufp);
  buf_forward_capacity(bufp);
  convert_to_one_line(bufp);
  buf_catrunc(bufp, inp2.c_str());

  // buflist testing
  buflistp = buffer_list_new(10);
  buffer_list_push(buflistp, inp1.c_str());
  buffer_list_push(buflistp, inp2.c_str());
  buffer_list_defined(buflistp);
  buffer_list_peek(buflistp);
  buffer_list_pop(buflistp);

  // Cleanup
  buffer_list_free(buflistp);
  gc_free(&gc);

  return 0;
}
