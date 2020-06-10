#include "draco/src/draco/compression/decode.h"
#include "draco/src/draco/core/decoder_buffer.h"
#include "draco/src/draco/mesh/mesh.h"
#include "draco/src/draco/point_cloud/point_cloud.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  draco::DecoderBuffer buffer;
  buffer.Init(reinterpret_cast<const char *>(data), size);

  // Decode the input data into a geometry. We do not care about the return
  // value for this test.
  const auto statusor = draco::Decoder::GetEncodedGeometryType(&buffer);
  if (!statusor.ok())
    return 0;
  const draco::EncodedGeometryType geom_type = statusor.value();
  if (geom_type == draco::TRIANGULAR_MESH) {
    draco::Decoder decoder;
    decoder.DecodeMeshFromBuffer(&buffer);
  } else if (geom_type == draco::POINT_CLOUD) {
    // Failed to decode it as mesh, so let's try to decode it as a point
    // cloud.
    draco::Decoder decoder;
    decoder.DecodePointCloudFromBuffer(&buffer);
  }

  return 0;
}
