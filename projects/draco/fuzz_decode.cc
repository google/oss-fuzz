// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Fuzz target for Draco 3D mesh/point cloud decoding.
// Exercises DecodeMeshFromBuffer and DecodePointCloudFromBuffer on
// arbitrary (potentially malformed) compressed geometry data.

#include <cstddef>
#include <cstdint>
#include <memory>

#include "draco/compression/decode.h"
#include "draco/core/decoder_buffer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  draco::DecoderBuffer buffer;
  buffer.Init(reinterpret_cast<const char *>(data), size);

  draco::Decoder decoder;

  // Try decoding as mesh first, then as point cloud.
  auto mesh_status = decoder.DecodeMeshFromBuffer(&buffer);
  if (mesh_status.ok()) {
    auto mesh = std::move(mesh_status).value();
    // Access decoded data to exercise attribute accessors.
    for (int i = 0; i < mesh->num_attributes(); ++i) {
      auto attr = mesh->attribute(i);
      if (attr && mesh->num_points() > 0) {
        std::vector<float> values(attr->num_components());
        attr->GetValue(draco::AttributeValueIndex(0), values.data());
      }
    }
  }

  buffer.Init(reinterpret_cast<const char *>(data), size);
  auto pc_status = decoder.DecodePointCloudFromBuffer(&buffer);
  if (pc_status.ok()) {
    auto pc = std::move(pc_status).value();
    for (int i = 0; i < pc->num_attributes(); ++i) {
      auto attr = pc->attribute(i);
      if (attr && pc->num_points() > 0) {
        std::vector<float> values(attr->num_components());
        attr->GetValue(draco::AttributeValueIndex(0), values.data());
      }
    }
  }

  return 0;
}
