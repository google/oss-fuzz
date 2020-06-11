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

#include "draco/src/draco/compression/decode.h"
#include "draco/src/draco/core/decoder_buffer.h"
#include "draco/src/draco/mesh/mesh.h"
#include "draco/src/draco/point_cloud/point_cloud.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // std::unique_ptr<draco::PointCloud> pc(/* initialize point cloud */);
  // draco::DecoderBuffer buffer;
  //
  //
  // draco::Encoder encoder;
  // encoder.EncodePointCloudToBuffer(*pc, &buffer);

  // FuzzedDataProvider stream(data, size);
  // draco::PointCloudBuilder pc_builder;
  //
  // int kNumPoints = stream.ConsumeIntegral<int>();
  // int kNumGenAttCoords0 = stream.ConsumeIntegral<int>();
  // int kNumGenAttCoords1 = stream.ConsumeIntegral<int>();
  // pc_builder.Start(kNumPoints);
  //
  // // Add one position attribute and two generic attributes.
  // const int32_t pos_att_id = pc_builder.AddAttribute(
  //     draco::GeometryAttribute::POSITION, stream.ConsumeIntegral<int>(), draco::DT_FLOAT32);
  // const int32_t gen_att_id_0 = pc_builder.AddAttribute(
  //     draco::GeometryAttribute::GENERIC, kNumGenAttCoords0, draco::DT_UINT32);
  // const int32_t gen_att_id_1 = pc_builder.AddAttribute(
  //     draco::GeometryAttribute::GENERIC, kNumGenAttCoords1, draco::DT_UINT8);
  //
  // std::vector<uint32_t> gen_att_data_0(kNumGenAttCoords0);
  // std::vector<uint32_t> gen_att_data_1(kNumGenAttCoords1);
  //
  // // Initialize the attribute values.
  // for (draco::PointIndex i(0); i < kNumPoints; ++i) {
  //   const float pos_coord = static_cast<float>(i.value());
  //   pc_builder.SetAttributeValueForPoint(
  //       pos_att_id, i,
  //       draco::Vector3f(pos_coord, -pos_coord, pos_coord).data());
  //
  //   for (int j = 0; j < kNumGenAttCoords0; ++j) {
  //     gen_att_data_0[j] = i.value();
  //   }
  //   pc_builder.SetAttributeValueForPoint(gen_att_id_0, i,
  //                                        gen_att_data_0.data());
  //
  //   for (int j = 0; j < kNumGenAttCoords1; ++j) {
  //     gen_att_data_1[j] = -i.value();
  //   }
  //   pc_builder.SetAttributeValueForPoint(gen_att_id_1, i,
  //                                        gen_att_data_1.data());
  // }
  //
  // std::unique_ptr<draco::PointCloud> pc = pc_builder.Finalize(false);
  // if (pc == NULL)
  //   return 0;
  //
  // draco::EncoderBuffer buffer;
  // draco::Encoder encoder;
  // encoder.SetEncodingMethod(draco::POINT_CLOUD_KD_TREE_ENCODING);
  //
  //
  // encoder.SetAttributeQuantization(draco::GeometryAttribute::POSITION, 16);
  // encoder.EncodePointCloudToBuffer(*pc, &buffer);

  return 0;
}
