/*
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "basisu_transcoder.cpp"

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
  basist::basisu_transcoder_init();

  basist::etc1_global_selector_codebook* globalCodebook = new basist::etc1_global_selector_codebook(basist::g_global_selector_cb_size, basist::g_global_selector_cb);
  basist::basisu_transcoder transcoder(globalCodebook);

  if (transcoder.validate_header(data, size)) {
    basist::basisu_file_info fileInfo;
    if (transcoder.get_file_info(data, size, fileInfo)) {
      basist::basisu_image_info info;
      if (transcoder.get_image_info(data, size, info, 0)) {
        if (transcoder.start_transcoding(data, size)) {
          uint32_t descW, descH, blocks;
          for (uint32_t level = 0; level < info.m_total_levels; level++) {
            transcoder.get_image_level_desc(data, size, 0, level, descW, descH, blocks);
          }
        }
      }
    }
  }

  delete globalCodebook;
  return 0;
}