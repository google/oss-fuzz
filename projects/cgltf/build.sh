#!/bin/bash -eu

# Build the enhanced cgltf fuzz harness.
# This exercises: cgltf_parse -> cgltf_validate -> cgltf_load_buffers
#   -> cgltf_accessor_read_float / cgltf_accessor_unpack_floats
# which cover the sparse accessor code paths where CVEs have been found.

cat > $SRC/cgltf_fuzz.c << 'HARNESS'
#define CGLTF_IMPLEMENTATION
#include "cgltf.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 4 || Size > 2 * 1024 * 1024)
        return 0;

    cgltf_options options;
    memset(&options, 0, sizeof(options));
    options.type = cgltf_file_type_invalid; /* auto-detect glb/gltf */

    cgltf_data *data = NULL;
    cgltf_result res = cgltf_parse(&options, Data, Size, &data);
    if (res != cgltf_result_success)
        return 0;

    /* Validate: checks accessor bounds, sparse index ranges, etc. */
    if (cgltf_validate(data) != cgltf_result_success)
    {
        cgltf_free(data);
        return 0;
    }

    /* Load buffers: for GLB this binds the BIN chunk pointer;
     * for glTF with data URIs this decodes base64. */
    cgltf_load_buffers(&options, data, NULL);

    /* Exercise accessor read paths including sparse accessor handling. */
    for (cgltf_size i = 0; i < data->accessors_count; i++)
    {
        cgltf_accessor *acc = &data->accessors[i];

        /* cgltf_accessor_unpack_floats: covers sparse values iteration */
        cgltf_size float_count = cgltf_accessor_unpack_floats(acc, NULL, 0);
        if (float_count > 0 && float_count < 1024 * 1024)
        {
            cgltf_float *floats = (cgltf_float *)calloc(float_count, sizeof(cgltf_float));
            if (floats)
            {
                cgltf_accessor_unpack_floats(acc, floats, float_count);
                free(floats);
            }
        }

        /* cgltf_accessor_read_float: covers cgltf_find_sparse_index */
        if (acc->count > 0 && acc->count < 65536)
        {
            cgltf_size num_components = cgltf_num_components(acc->type);
            if (num_components > 0)
            {
                cgltf_float out[16];
                cgltf_size limit = acc->count < 64 ? acc->count : 64;
                for (cgltf_size j = 0; j < limit; j++)
                {
                    cgltf_accessor_read_float(acc, j, out, num_components);
                }
            }
        }
    }

    cgltf_free(data);
    return 0;
}
HARNESS

$CC $CFLAGS -I/src/cgltf -c $SRC/cgltf_fuzz.c -o $WORK/cgltf_fuzz.o
$CC $CFLAGS $LIB_FUZZING_ENGINE $WORK/cgltf_fuzz.o -o $OUT/cgltf_fuzz

# Copy seed corpus from cgltf test data
mkdir -p $OUT/cgltf_fuzz_seed_corpus
if [ -d /src/cgltf/test/glTF-Sample-Models ]; then
    find /src/cgltf/test/glTF-Sample-Models -name "*.glb" -o -name "*.gltf" | head -50 | while read f; do
        cp "$f" $OUT/cgltf_fuzz_seed_corpus/ 2>/dev/null || true
    done
fi

# Copy dictionary
cp /src/cgltf/fuzz/gltf.dict $OUT/cgltf_fuzz.dict 2>/dev/null || \
cat > $OUT/cgltf_fuzz.dict << 'DICT'
# glTF keywords
"accessors"
"bufferViews"
"buffers"
"meshes"
"nodes"
"scenes"
"materials"
"textures"
"images"
"samplers"
"skins"
"animations"
"cameras"
"extensions"
"extras"
"sparse"
"indices"
"values"
"componentType"
"count"
"type"
"byteOffset"
"byteLength"
"byteStride"
"bufferView"
"buffer"
"asset"
"version"
"VEC2"
"VEC3"
"VEC4"
"MAT2"
"MAT3"
"MAT4"
"SCALAR"
# GLB magic
"\x67\x6C\x54\x46"
# glTF chunk types
"\x4A\x53\x4F\x4E"
"\x42\x49\x4E\x00"
DICT
