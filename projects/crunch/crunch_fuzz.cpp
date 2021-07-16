/* Copyright 2021 Google LLC
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
#include <cstddef>
#include <cstdint>
#include <string>
#include "crnlib.h"
#include "dds_defs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  crn_uint32 crn_size = static_cast<crn_uint32>(size);
  void *dds = crn_decompress_crn_to_dds(data, crn_size);
  if (!dds) {
    return 0;
  }
  crn_texture_desc tex_desc;

  // See crnlib.h where cCRNMaxFaces and cCRNMaxLevels are defined for details
  // on the library/file limits used within crunch.
  crn_uint32 *images[cCRNMaxFaces * cCRNMaxLevels];
  bool success = crn_decompress_dds_to_images(dds, crn_size, images, tex_desc);
  crn_free_block(dds);
  if (!success) {
    return 0;
  }
  crn_free_all_images(images, tex_desc);
  return 0;
}

