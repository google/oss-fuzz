// Fuzz target for Google Filament's glTF parser and meshopt decompression.
//
// Exercises the code path in gltfio's ResourceLoader:
//   cgltf_parse → cgltf_validate → decompress meshopt-compressed buffer views

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
