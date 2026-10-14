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

// OSS-Fuzz target: filament .filamesh loader (MeshReader::loadMeshFromBuffer).
// Covers F1 (UV1 alloc-vs-decode heap OOB write) and the .filamesh compressed paths.
// Uses a headless NOOP-backend Engine so it runs without a GPU. The OOB in F1 is not assert-gated,
// so it is found under ASan in both debug and release builds.
#include <filament/Engine.h>
#include <filament/VertexBuffer.h>
#include <filament/IndexBuffer.h>
#include <filament/MaterialInstance.h>
#include <filameshio/MeshReader.h>
#include <utils/Entity.h>
#include <cstdint>
#include <cstddef>

using namespace filament;
using filamesh::MeshReader;

static Engine* g_engine = nullptr;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    g_engine = Engine::create(Engine::Backend::NOOP);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!g_engine) return 0;
    MeshReader::Mesh mesh = MeshReader::loadMeshFromBuffer(
        g_engine, data, size, nullptr, nullptr, (MaterialInstance*) nullptr);
    if (mesh.vertexBuffer) g_engine->destroy(mesh.vertexBuffer);
    if (mesh.indexBuffer)  g_engine->destroy(mesh.indexBuffer);
    if (!mesh.renderable.isNull()) g_engine->destroy(mesh.renderable);
    return 0;
}
