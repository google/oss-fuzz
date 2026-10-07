/* Copyright 2023 Google LLC
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

/*
 * The main idea behind this fuzzer is the generate arbitrary stack traces
 * by way of recursive funcitons, and then using various calls to libunwind
 * apis arbitrarily.
 */
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void get_random_reg(int);
void get_proc_name();
void dispatch(const uint8_t *data, size_t size);
void check_is_signal();
void get_save_loc(int reg);
void recurse1(const uint8_t *data, size_t size);
void recurse2(const uint8_t *data, size_t size);
void recurse3(const uint8_t *data, size_t size);
void recurse4(const uint8_t *data, size_t size);

void get_save_loc(int regnum) {
  unw_cursor_t cursor;
  unw_context_t uc;
  unw_word_t reference_reg;

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);
  unw_save_loc_t loc;
  while (unw_step(&cursor) > 0) {
    unw_get_save_loc(&cursor, regnum, &loc);
  }
}

void get_random_reg(int regnum) {
  unw_cursor_t cursor;
  unw_context_t uc;
  unw_word_t reference_reg;

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);
  while (unw_step(&cursor) > 0) {
    unw_get_reg(&cursor, regnum, &reference_reg);
  }
}

void check_is_signal() {
  unw_cursor_t cursor;
  unw_context_t uc;
  unw_word_t reference_reg;

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);
  while (unw_step(&cursor) > 0) {
    if (unw_is_signal_frame(&cursor)) {
      return;
    }
  }
}

void get_proc_name() {
  unw_cursor_t cursor;
  unw_context_t uc;

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);
  while (unw_step(&cursor) > 0) {
    unw_word_t offset;
    char buf[512];
    unw_get_proc_name(&cursor, buf, sizeof(buf), &offset);
  }
}

void dispatch(const uint8_t *data, size_t size) {
  if (size < 8) {
    return;
  }
  uint8_t decider = data[0] % 4;
  data += 2;
  size -= 2;
  if (decider == 0) {
    recurse1(data, size);
  } else if (decider == 1) {
    recurse2(data, size);
  } else if (decider == 2) {
    recurse3(data, size);
  } else {
    recurse4(data, size);
  }
}

void recurse1(const uint8_t *data, size_t size) {
  if (data[0] == 0x01) {
    get_proc_name();
  }
  data += 2;
  size -= 2;

  dispatch(data, size);
  return;
}

void recurse2(const uint8_t *data, size_t size) {
  if (data[0] == 0x01) {
    get_random_reg((int)data[1]);
  }
  data += 2;
  size -= 2;

  dispatch(data, size);
  return;
}

void recurse3(const uint8_t *data, size_t size) {
  if (data[0] == 0x01) {
    check_is_signal((int)data[1]);
  }
  data += 2;
  size -= 2;

  dispatch(data, size);
  return;
}

void recurse4(const uint8_t *data, size_t size) {
  if (data[0] == 0x01) {
    get_save_loc((int)data[1]);
  }
  data += 2;
  size -= 2;

  dispatch(data, size);
  return;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Ensure we have a bit of data but not too much to cause stackoverflows.
  if (size < 12 || size > 512) {
    return 0;
  }

  dispatch(data, size);
  return 0;
}
