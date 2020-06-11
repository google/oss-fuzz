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

#include <fuzzer/FuzzedDataProvider.h>

#include "draco/src/draco/mesh/mesh.h"
#include "draco/src/draco/mesh/triangle_soup_mesh_builder.h"
#include "draco/src/draco/compression/encode.h"
#include "draco/src/draco/compression/expert_encode.h"
#include "draco/src/draco/core/encoder_buffer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  // Build the mesh
  draco::TriangleSoupMeshBuilder mesh_builder;
  FuzzedDataProvider stream(data, size);

  const uint num_faces = 5;
  mesh_builder.Start(num_faces);

  const int32_t pos_att_id = mesh_builder.AddAttribute(
      draco::GeometryAttribute::POSITION,
      stream.ConsumeFloatingPoint<float>(),
      draco::DT_FLOAT32
    );
  const int32_t tex_att_id_0 = mesh_builder.AddAttribute(
      draco::GeometryAttribute::TEX_COORD,
      stream.ConsumeFloatingPoint<float>(),
      draco::DT_FLOAT32
    );
  const int32_t tex_att_id_1 = mesh_builder.AddAttribute(
      draco::GeometryAttribute::TEX_COORD,
      stream.ConsumeFloatingPoint<float>(),
      draco::DT_FLOAT32
    );

  uint i;
  for (i = 0; i < num_faces; i++) {
    mesh_builder.SetAttributeValuesForFace(
        pos_att_id,
        draco::FaceIndex(i),
        draco::Vector3f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data(),
        draco::Vector3f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data(),
        draco::Vector3f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data()
      );
    mesh_builder.SetAttributeValuesForFace(
        tex_att_id_0,
        draco::FaceIndex(i),
        draco::Vector2f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data(),
        draco::Vector2f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data(),
        draco::Vector2f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data());
    mesh_builder.SetAttributeValuesForFace(
        tex_att_id_1,
        draco::FaceIndex(i),
        draco::Vector2f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data(),
        draco::Vector2f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data(),
        draco::Vector2f(
            stream.ConsumeFloatingPoint<float>(),
            stream.ConsumeFloatingPoint<float>()
          ).data());
  }

  auto mesh = mesh_builder.Finalize();
  if (mesh == NULL)
    return 0;

  // Encode the mesh
  draco::Encoder encoder;
  encoder.SetAttributeQuantization(draco::GeometryAttribute::POSITION,
    stream.ConsumeIntegral<int>());
  encoder.SetAttributeQuantization(draco::GeometryAttribute::TEX_COORD,
    stream.ConsumeIntegral<int>());

  draco::EncoderBuffer buffer;
  encoder.EncodeMeshToBuffer(*mesh.get(), &buffer);

  return 0;
}
