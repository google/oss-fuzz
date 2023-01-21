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
#include "archive_entry.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  struct archive *a = archive_read_new();

  archive_read_support_filter_all(a);
  archive_read_support_format_all(a);
  archive_read_support_format_empty(a);
  archive_read_support_format_raw(a);
  archive_read_support_format_gnutar(a);

  if (ARCHIVE_OK != archive_read_set_options(a, "zip:ignorecrc32,tar:read_concatenated_archives,tar:mac-ext")) {
    return 0;
  }

  if (ARCHIVE_OK != archive_read_open_memory(a, buf, len)) {
    archive_read_free(a);
    return 0;
  }

  archive_read_add_passphrase(a, "secret");

  while(1) {
    std::vector<uint8_t> data_buffer(getpagesize(), 0);
    struct archive_entry *entry;
    int ret = archive_read_next_header(a, &entry);
    if (ret == ARCHIVE_EOF || ret == ARCHIVE_FATAL)
      break;
    if (ret == ARCHIVE_RETRY)
      continue;

    (void)archive_entry_pathname(entry);
    (void)archive_entry_pathname_utf8(entry);
    (void)archive_entry_pathname_w(entry);

    (void)archive_entry_atime(entry);
    (void)archive_entry_birthtime(entry);
    (void)archive_entry_ctime(entry);
    (void)archive_entry_dev(entry);
    (void)archive_entry_digest(entry, ARCHIVE_ENTRY_DIGEST_SHA1);
    (void)archive_entry_filetype(entry);
    (void)archive_entry_gid(entry);
    (void)archive_entry_is_data_encrypted(entry);
    (void)archive_entry_is_encrypted(entry);
    (void)archive_entry_is_metadata_encrypted(entry);
    (void)archive_entry_mode(entry);
    (void)archive_entry_mtime(entry);
    (void)archive_entry_size(entry);
    (void)archive_entry_uid(entry);

    ssize_t r;
    while ((r = archive_read_data(a, data_buffer.data(),
            data_buffer.size())) > 0)
      ;
    if (r == ARCHIVE_FATAL)
      break;
  }

  archive_read_has_encrypted_entries(a);
  archive_read_format_capabilities(a);
  archive_file_count(a);
  archive_seek_data(a, 0, SEEK_SET);

  archive_read_free(a);
  return 0;
}
