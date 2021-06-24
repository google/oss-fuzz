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

// Returns a NULL-terminated C string that should be freed by the caller.
char *get_modifiable_string(FuzzedDataProvider &provider) {
  std::string s1 = provider.ConsumeRandomLengthString();
  char *tmp = (char *)malloc(s1.size() + 1);
  memcpy(tmp, s1.c_str(), s1.size());
  tmp[s1.size()] = '\0';
  return tmp;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  struct gc_arena gc;
  struct buffer *bufp;
  struct buffer buf, buf2;
  struct buffer_list *buflistp = NULL;
  ssize_t generic_ssizet, _size;
  char *tmp;
  char *tmp2;
  char match;

  gc = gc_new();
  bufp = NULL;

  int total_to_fuzz = provider.ConsumeIntegralInRange(1, 20);
  for (int i = 0; i < total_to_fuzz; i++) {
    if (bufp == NULL) {
      generic_ssizet = provider.ConsumeIntegralInRange(0, 1);
      if (generic_ssizet == 0) {
        _size = provider.ConsumeIntegralInRange(0, 100);
        buf = alloc_buf_gc(_size, &gc);
        bufp = &buf;
      } else {
        tmp = get_modifiable_string(provider);
        buf = string_alloc_buf(tmp, &gc);
        bufp = &buf;
        free(tmp);
        tmp = NULL;
      }
    } else {
#define NUM_TARGETS 32
      generic_ssizet = provider.ConsumeIntegralInRange(0, NUM_TARGETS);
      switch (generic_ssizet) {
      case 0:
        buf_clear(bufp);
        break;
      case 1:
        buf2 = clone_buf(bufp);
        free_buf(&buf2);
        break;
      case 2:
        buf_defined(bufp);
        break;
      case 3:
        buf_valid(bufp);
        break;
      case 4:
        buf_bptr(bufp);
        break;
      case 5:
        buf_len(bufp);
        break;
      case 6:
        buf_bend(bufp);
        break;
      case 7:
        buf_blast(bufp);
        break;
      case 8:
        buf_str(bufp);
        break;
      case 9:
        generic_ssizet = provider.ConsumeIntegralInRange(0, 255);
        buf_rmtail(bufp, (uint8_t)generic_ssizet);
        break;
      case 10:
        buf_chomp(bufp);
        break;
      case 11:
        tmp = get_modifiable_string(provider);
        skip_leading_whitespace(tmp);
        free(tmp);
        tmp = NULL;
        break;
      case 12:
        tmp = get_modifiable_string(provider);
        chomp(tmp);
        free(tmp);
        tmp = NULL;
        break;
      case 13:
        tmp = get_modifiable_string(provider);
        tmp2 = get_modifiable_string(provider);
        rm_trailing_chars(tmp, tmp2);
        free(tmp);
        free(tmp2);
        tmp = NULL;
        tmp2 = NULL;
        break;
      case 14:
        tmp = get_modifiable_string(provider);
        string_clear(tmp);
        free(tmp);
        tmp = NULL;
        break;
      case 15:
        tmp = get_modifiable_string(provider);
        buf_string_match_head_str(bufp, tmp);
        free(tmp);
        tmp = NULL;
        break;
      case 16:
        tmp = get_modifiable_string(provider);
        buf_string_compare_advance(bufp, tmp);
        free(tmp);
        tmp = NULL;
        break;
      case 17:
        generic_ssizet = provider.ConsumeIntegralInRange(0, 255);

        tmp = get_modifiable_string(provider);
        if (strlen(tmp) > 0) {
          buf_parse(bufp, (int)generic_ssizet, tmp, strlen(tmp));
        }

        free(tmp);
        tmp = NULL;
        break;
      case 18:
        tmp = get_modifiable_string(provider);
        string_mod(tmp, provider.ConsumeIntegral<unsigned int>(),
                   provider.ConsumeIntegral<unsigned int>(),
                   provider.ConsumeIntegral<char>());

        free(tmp);
        tmp = NULL;
        break;
      case 19:
        tmp = get_modifiable_string(provider);
        match = provider.ConsumeIntegral<char>();
        if (match != 0) {
          string_replace_leading(tmp, match, provider.ConsumeIntegral<char>());
        }

        free(tmp);
        tmp = NULL;
        break;
      case 20:
        tmp = get_modifiable_string(provider);
        buf_write(bufp, tmp, strlen(tmp));

        free(tmp);
        tmp = NULL;
        break;
      case 21:
        tmp = get_modifiable_string(provider);

        buf_write_prepend(bufp, tmp, strlen(tmp));

        free(tmp);
        tmp = NULL;
        break;
      case 22:
        buf_write_u8(bufp, provider.ConsumeIntegral<int>());
        break;
      case 23:
        buf_write_u16(bufp, provider.ConsumeIntegral<int>());
        break;
      case 24:
        buf_write_u32(bufp, provider.ConsumeIntegral<int>());
        break;
      case 25:
        tmp = get_modifiable_string(provider);
        buf_catrunc(bufp, tmp);
        free(tmp);
        tmp = NULL;
        break;
      case 26:
        convert_to_one_line(bufp);
        break;
      case 27:
        buf_advance(bufp, provider.ConsumeIntegral<int>());
        break;
      case 28:
        buf_prepend(bufp, provider.ConsumeIntegral<int>());
        break;
      case 29:
        buf_reverse_capacity(bufp);
        break;
      case 30:
        buf_forward_capacity_total(bufp);
        break;
      case 31:
        buf_forward_capacity(bufp);
        break;
      case 32:
        tmp = get_modifiable_string(provider);
        buf_puts(bufp, tmp);
        free(tmp);
        tmp = NULL;
        break;
      }
    }

    if (buflistp == NULL) {
      buflistp = buffer_list_new(provider.ConsumeIntegralInRange(0, 200));
    } else {
#define NUM_LIST_TARGETS 6
      generic_ssizet = provider.ConsumeIntegralInRange(0, NUM_LIST_TARGETS);
      switch (generic_ssizet) {
      case 0:
        buffer_list_free(buflistp);
        buflistp = NULL;
        break;
      case 1:
        buffer_list_defined(buflistp);
        break;
      case 2:
        tmp = get_modifiable_string(provider);
        buffer_list_push(buflistp, tmp);
        free(tmp);
        tmp = NULL;
        break;
      case 3:
        buffer_list_peek(buflistp);
        break;
      case 4:
        buffer_list_pop(buflistp);
        break;
      case 5:
        tmp = get_modifiable_string(provider);
        buffer_list_aggregate_separator(
            buflistp, provider.ConsumeIntegralInRange(0, 1024), tmp);

        free(tmp);
        tmp = NULL;
        break;
      case 6:
        buffer_list_aggregate(buflistp,
                              provider.ConsumeIntegralInRange(0, 1024));
        break;
      }
    }
  }

  // Cleanup
  buffer_list_free(buflistp);
  gc_free(&gc);

  return 0;
}
