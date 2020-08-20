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

#include "sleuthkit/tsk/tsk_tools_i.h"
#include "sleuthkit_mem_img.h"

#ifndef FSTYPE
#error Define FSTYPE as a valid value of TSK_FS_TYPE_ENUM.
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  TSK_IMG_INFO *img;
  TSK_FS_INFO *fs;

  img = mem_open(data, size);
  if (img == nullptr)
    return 0;

  fs = tsk_fs_open_img(img, 0, FSTYPE);
  if (fs != nullptr) {
    tsk_fs_fls(fs, TSK_FS_FLS_FULL, fs->root_inum, TSK_FS_DIR_WALK_FLAG_RECURSE,
               nullptr, 0);

    fs->close(fs);
  }

  img->close(img);
  return 0;
}
