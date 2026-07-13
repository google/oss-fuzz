// Copyright 2026 Google LLC
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
// raylib model loader fuzzer harness
// Targets: OBJ, IQM, GLTF, VOX, M3D parsers

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "raylib.h"

static const char *extensions[] = {
    ".obj", ".iqm", ".gltf", ".glb", ".vox", ".m3d",
};
#define NUM_EXTENSIONS 6
#define MAX_INPUT_SIZE (256 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > MAX_INPUT_SIZE) return 0;

    int ext_idx = data[0] % NUM_EXTENSIONS;
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    char tmppath[256];
    snprintf(tmppath, sizeof(tmppath), "/dev/shm/fuzz_raylib_%d%s",
             getpid(), extensions[ext_idx]);

    FILE *f = fopen(tmppath, "wb");
    if (!f) return 0;
    fwrite(payload, 1, payload_size, f);
    fclose(f);

    Model model = LoadModel(tmppath);

    // Manual cleanup to avoid GPU stub issues in UnloadModel
    if (model.meshes != NULL) {
        for (int i = 0; i < model.meshCount; i++) {
            RL_FREE(model.meshes[i].vertices);
            RL_FREE(model.meshes[i].texcoords);
            RL_FREE(model.meshes[i].texcoords2);
            RL_FREE(model.meshes[i].normals);
            RL_FREE(model.meshes[i].tangents);
            RL_FREE(model.meshes[i].colors);
            RL_FREE(model.meshes[i].indices);
            RL_FREE(model.meshes[i].animVertices);
            RL_FREE(model.meshes[i].animNormals);
            RL_FREE(model.meshes[i].boneWeights);
            RL_FREE(model.meshes[i].boneIndices);
            RL_FREE(model.meshes[i].vboId);
        }
        RL_FREE(model.meshes);
    }
    RL_FREE(model.materials);
    RL_FREE(model.meshMaterial);
    RL_FREE(model.skeleton.bones);
    RL_FREE(model.boneMatrices);

    unlink(tmppath);
    return 0;
}
