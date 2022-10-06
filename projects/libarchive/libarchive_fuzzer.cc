// Copyright 2016 Google Inc.
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
#include <vector>

#include "archive.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  struct archive *a = archive_read_new();

  archive_read_support_filter_all(a);
  archive_read_support_format_all(a);
  archive_read_support_format_empty(a);
  archive_read_support_format_raw(a);

  archive_read_open_memory(a, buf, len);

  struct archive_entry *entry;
  while(1) {
    int ret = archive_read_next_header(a, &entry);
    if (ret == ARCHIVE_EOF || ret == ARCHIVE_FATAL)
      break;
    if (ret == ARCHIVE_RETRY)
      continue;

    const void* buff;
    size_t size;
    int64_t offset;
    while ((ret = archive_read_data_block(a, &buff, &size, &offset)) > 0)
      ;
    if (ret == ARCHIVE_FATAL)
      break;
  }

  archive_read_free(a);
  return 0;
}
