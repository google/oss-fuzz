// Copyright 2021 Google LLC
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
#include "sleuthkit/tsk/fs/tsk_fs.h"
#include "sleuthkit/tsk/pool/tsk_pool.h"
#include "sleuthkit_mem_img.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  TSK_IMG_INFO* img;
  TSK_IMG_INFO* pool_img;
  TSK_FS_INFO* fs;
  const TSK_POOL_INFO* pool;

  img = mem_open(data, size);
  if (img == nullptr) {
    return 0;
  }
  pool = tsk_pool_open_img_sing(img, 0, TSK_POOL_TYPE_APFS);

  if (pool == nullptr) {
    goto out_img;
  }
  // Pool start block is APFS container specific and is hard coded for now
  pool_img = pool->get_img_info(pool, (TSK_DADDR_T) 106);

  if (pool_img == nullptr) {
    goto out_pool;
  }
  fs = tsk_fs_open_img_decrypt(pool_img, 0, TSK_FS_TYPE_APFS_DETECT, "");

  if (fs != nullptr) {
    tsk_fs_fls(fs, TSK_FS_FLS_FULL, fs->root_inum, TSK_FS_DIR_WALK_FLAG_RECURSE, nullptr, 0);

    fs->close(fs);
  }
  tsk_img_close(pool_img);

out_pool:
  tsk_pool_close(pool);

out_img:
  tsk_img_close(img);

  return 0;
}
