// Copyright 2020 Google LLC
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

#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "ext2fs/ext2fs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char* fname = "/tmp/ext2_test_file";

  // Write our data to a temp file.
  int fd = open(fname, O_RDWR|O_CREAT|O_TRUNC);
  write(fd, data, size);
  close(fd);

  ext2_filsys fs;
  errcode_t retval = ext2fs_open(
      fname,
      EXT2_FLAG_IGNORE_CSUM_ERRORS, 0, 0,
      unix_io_manager,
      &fs);

  if (!retval) {
    retval = ext2fs_check_directory(fs, EXT2_ROOT_INO);
    ext2fs_close(fs);
  }

  return 0;
}
