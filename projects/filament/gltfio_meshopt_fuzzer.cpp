// Copyright 2024 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

// OSS-Fuzz target: filament gltfio EXT_meshopt_compression decode path.
// Feeds raw bytes as a glTF/GLB to filament's real cgltf, then runs the real
// filament::gltfio::utility::decodeMeshoptCompression. Covers F2 (index %3), #3/#4 (oct/quat filters),
// #5 (vertex byteStride>256 stack overflow), #7 (index sequence stride!=2).
// NOTE: these meshopt preconditions are assert-only; build with -DNDEBUG (release, as OSS-Fuzz does for
// the address sanitizer build) so the asserts are compiled out and ASan observes the real OOB writes.
#include <cgltf.h>                 // filament third_party/cgltf (declarations; impl is in gltfio_core)
#include "Utility.h"               // filament::gltfio::utility::decodeMeshoptCompression
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    cgltf_options opts; memset(&opts, 0, sizeof(opts));
    cgltf_data* gltf = nullptr;
    if (cgltf_parse(&opts, data, size, &gltf) != cgltf_result_success) return 0;
    if (cgltf_load_buffers(&opts, gltf, nullptr) == cgltf_result_success) {
        filament::gltfio::utility::decodeMeshoptCompression(gltf);   // real gltfio code path
    }
    cgltf_free(gltf);
    return 0;
}
