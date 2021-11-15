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

#ifndef MEM_IMG_H
#define MEM_IMG_H

#include <stddef.h>
#include <stdint.h>

#include "sleuthkit/tsk/tsk_tools_i.h"

typedef struct {
  TSK_IMG_INFO img_info;
  const uint8_t *data;
  size_t size;
} IMG_MEM_INFO;

static ssize_t mem_read(TSK_IMG_INFO *img_info, TSK_OFF_T offset, char *buf,
                        size_t len) {
  IMG_MEM_INFO *mem_info = reinterpret_cast<IMG_MEM_INFO *>(img_info);
  // Bounds-checking exists in the real drivers.
  if (offset > mem_info->size) {
    return -1;
  }
  ssize_t read_len = len;
  if (offset + len > mem_info->size) {
    read_len = mem_info->size - offset;
  }
  if (memcpy(buf, mem_info->data + offset, read_len) == nullptr) {
    return -1;
  } else {
    return read_len;
  }
}

static void mem_close(TSK_IMG_INFO *img_info) {
  IMG_MEM_INFO *mem_info = reinterpret_cast<IMG_MEM_INFO *>(img_info);
  tsk_deinit_lock(&(img_info->cache_lock));
  free(mem_info);
}

static void mem_imgstat(TSK_IMG_INFO *img_info, FILE *hFile) {}

TSK_IMG_INFO *mem_open(const uint8_t *data, size_t size) {
  IMG_MEM_INFO *inmemory_img =
      reinterpret_cast<IMG_MEM_INFO *>(malloc(sizeof(IMG_MEM_INFO)));
  TSK_IMG_INFO *img;
  if (inmemory_img == nullptr) {
    return nullptr;
  }
  img = reinterpret_cast<TSK_IMG_INFO *>(inmemory_img);
  img->itype = TSK_IMG_TYPE_RAW;
  img->read = mem_read;
  img->close = mem_close;
  img->imgstat = mem_imgstat;
  img->size = size;
  img->sector_size = 512;
  tsk_init_lock(&(img->cache_lock));
  inmemory_img->data = data;
  inmemory_img->size = size;
  return img;
}

#endif // # MEM_IMG_H
