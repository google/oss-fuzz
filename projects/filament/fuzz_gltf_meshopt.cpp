/* Copyright 2023 Google LLC
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
#include <cstdlib>
#include <cstring>

#define CGLTF_IMPLEMENTATION
#include "cgltf.h"
#include "meshoptimizer.h"

static void decompress_meshopt_buffers(cgltf_data* data) {
    for (cgltf_size i = 0; i < data->buffer_views_count; ++i) {
        cgltf_meshopt_compression* compression =
                &data->buffer_views[i].meshopt_compression;

        if (compression->buffer == nullptr ||
                compression->buffer->data == nullptr) {
            continue;
        }

        if (compression->offset + compression->size >
                compression->buffer->size) {
            continue;
        }

        const unsigned char* source =
                (const unsigned char*)compression->buffer->data +
                compression->offset;

        switch (compression->mode) {
            case cgltf_meshopt_compression_mode_attributes:
                break;
            case cgltf_meshopt_compression_mode_triangles:
                if (compression->count % 3 != 0) continue;
                if (compression->stride != 2 && compression->stride != 4)
                    continue;
                if (compression->filter !=
                        cgltf_meshopt_compression_filter_none)
                    continue;
                break;
            case cgltf_meshopt_compression_mode_indices:
                if (compression->stride != 2 && compression->stride != 4)
                    continue;
                if (compression->filter !=
                        cgltf_meshopt_compression_filter_none)
                    continue;
                break;
            default:
                continue;
        }

        switch (compression->filter) {
            case cgltf_meshopt_compression_filter_none:
                break;
            case cgltf_meshopt_compression_filter_octahedral:
                if (compression->stride != 4 && compression->stride != 8)
                    continue;
                break;
            case cgltf_meshopt_compression_filter_quaternion:
                if (compression->stride != 8) continue;
                break;
            case cgltf_meshopt_compression_filter_exponential:
                if (compression->stride % 4 != 0) continue;
                break;
            default:
                continue;
        }

        const size_t decodedSize = compression->count * compression->stride;

        void* destination = malloc(decodedSize);
        if (!destination) continue;

        int error = 0;
        switch (compression->mode) {
            case cgltf_meshopt_compression_mode_attributes:
                error = meshopt_decodeVertexBuffer(
                        destination, compression->count,
                        compression->stride, source, compression->size);
                break;
            case cgltf_meshopt_compression_mode_triangles:
                error = meshopt_decodeIndexBuffer(
                        destination, compression->count,
                        compression->stride, source, compression->size);
                break;
            case cgltf_meshopt_compression_mode_indices:
                error = meshopt_decodeIndexSequence(
                        destination, compression->count,
                        compression->stride, source, compression->size);
                break;
            default:
                break;
        }

        if (error != 0) {
            free(destination);
            continue;
        }

        switch (compression->filter) {
            case cgltf_meshopt_compression_filter_none:
                break;
            case cgltf_meshopt_compression_filter_octahedral:
                meshopt_decodeFilterOct(
                        destination, compression->count, compression->stride);
                break;
            case cgltf_meshopt_compression_filter_quaternion:
                meshopt_decodeFilterQuat(
                        destination, compression->count, compression->stride);
                break;
            case cgltf_meshopt_compression_filter_exponential:
                meshopt_decodeFilterExp(
                        destination, compression->count, compression->stride);
                break;
            default:
                break;
        }

        free(destination);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    cgltf_options options = {};
    cgltf_data* parsed = nullptr;

    cgltf_result result = cgltf_parse(&options, data, size, &parsed);
    if (result != cgltf_result_success) {
        return 0;
    }

    if (parsed->buffers_count > 0 && parsed->bin != nullptr) {
        parsed->buffers[0].data = (void*)parsed->bin;
        parsed->buffers[0].size = parsed->bin_size;
    }

    if (cgltf_validate(parsed) == cgltf_result_success) {
        decompress_meshopt_buffers(parsed);
    }

    if (parsed->buffers_count > 0) {
        parsed->buffers[0].data = nullptr;
    }

    cgltf_free(parsed);
    return 0;
}
