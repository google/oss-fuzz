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
#include <unistd.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "ext2fs/ext2fs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  enum Fuzzer {
    ext2fsReadBlockBitmap,
    ext2fsReadInodeBitmap,
    kMaxValue = ext2fsReadInodeBitmap
  };

  FuzzedDataProvider stream(data, size);
  const Fuzzer f = stream.ConsumeEnum<Fuzzer>();
  static const char* fname = "/dev/shm/ext2_test_file";

  // Write our data to a temp file.
  int fd = open(fname, O_RDWR|O_CREAT|O_TRUNC);
  std::vector<char> buffer = stream.ConsumeRemainingBytes<char>();
  write(fd, buffer.data(), buffer.size());
  close(fd);

  ext2_filsys fs;
  errcode_t retval = ext2fs_open(
      fname,
      0, 0, 0,
      unix_io_manager,
      &fs);

  if (!retval) {
    switch (f) {
      case ext2fsReadBlockBitmap: {
        ext2fs_read_block_bitmap(fs);
        break;
      }
      case ext2fsReadInodeBitmap: {
        ext2fs_read_inode_bitmap(fs);
        break;
      }
      default: {
        return 0;
      }
    }
    ext2fs_close(fs);
  }

  return 0;
}
