// OSS-Fuzz target: filament gltfio accessor unpack path (sparse accessors + bounds).
// Feeds raw bytes as a glTF/GLB to filament's real cgltf, then unpacks every accessor into a buffer sized
// for its base count -- exactly as gltfio's ResourceLoader does. Covers #6 (sparse-accessor CONTROLLED heap
// OOB write via cgltf_accessor_unpack_floats) and accessor/bufferView bounds issues. The sparse OOB write is
// NOT assert-gated, so it is found under ASan even in debug builds (and in release, cgltf_validate is off).
#include <cgltf.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    cgltf_options opts; memset(&opts, 0, sizeof(opts));
    cgltf_data* gltf = nullptr;
    if (cgltf_parse(&opts, data, size, &gltf) != cgltf_result_success) return 0;
    if (cgltf_load_buffers(&opts, gltf, nullptr) == cgltf_result_success) {
        for (cgltf_size i = 0; i < gltf->accessors_count; ++i) {
            cgltf_accessor* a = &gltf->accessors[i];
            cgltf_size n = cgltf_accessor_unpack_floats(a, nullptr, 0);   // base count * components
            if (n == 0 || n > (8u << 20)) continue;                       // bound work
            float* out = (float*) malloc(n * sizeof(float));              // sized for base count (as gltfio)
            if (out) { cgltf_accessor_unpack_floats(a, out, n); free(out); }
        }
    }
    cgltf_free(gltf);
    return 0;
}
