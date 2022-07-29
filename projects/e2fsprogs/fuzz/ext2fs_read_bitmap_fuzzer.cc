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
#include <assert.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "ext2fs/ext2fs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  enum FuzzerType {
    ext2fsReadBlockBitmap,
    ext2fsReadInodeBitmap,
    kMaxValue = ext2fsReadInodeBitmap
  };

  FuzzedDataProvider stream(data, size);
  const FuzzerType f = stream.ConsumeEnum<FuzzerType>();
  const int flags = stream.ConsumeIntegral<int>();

  static const char* fname = "ext2_test_file";

  // Write our data to a temp file.
  int fd = syscall(SYS_memfd_create, fname, 0);
  std::vector<char> buffer = stream.ConsumeRemainingBytes<char>();
  write(fd, buffer.data(), buffer.size());

  std::string fspath("/proc/self/fd/" + std::to_string(fd));

  ext2_filsys fs;
  errcode_t retval = ext2fs_open(
      fspath.c_str(),
      flags | EXT2_FLAG_IGNORE_CSUM_ERRORS, 0, 0,
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
        assert(false);
      }
    }
    ext2fs_close(fs);
  }
  close(fd);

  return 0;
}
