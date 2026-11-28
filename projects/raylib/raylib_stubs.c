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
// Stub implementations for raylib functions not needed for model parsing fuzzing
// These prevent linking against the full raylib (which requires OpenGL/X11/GLFW)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "raylib.h"
#include "rlgl.h"

// --- Core file/path functions (needed for parsers) ---

unsigned char *LoadFileData(const char *fileName, int *dataSize) {
    FILE *f = fopen(fileName, "rb");
    if (!f) { *dataSize = 0; return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); *dataSize = 0; return NULL; }
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) { fclose(f); *dataSize = 0; return NULL; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    *dataSize = (int)rd;
    return buf;
}

void UnloadFileData(unsigned char *data) { free(data); }

char *LoadFileText(const char *fileName) {
    FILE *f = fopen(fileName, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, sz, f);
    buf[rd] = '\0';
    fclose(f);
    return buf;
}

void UnloadFileText(char *text) { free(text); }

bool SaveFileText(const char *fileName, const char *text) { (void)fileName; (void)text; return false; }

bool IsFileExtension(const char *fileName, const char *ext) {
    const char *dot = strrchr(fileName, '.');
    if (!dot) return false;
    return (strcasecmp(dot, ext) == 0);
}

const char *GetDirectoryPath(const char *filePath) {
    static char dirPath[512];
    strncpy(dirPath, filePath, sizeof(dirPath) - 1);
    dirPath[sizeof(dirPath) - 1] = '\0';
    char *last = strrchr(dirPath, '/');
    if (last) *last = '\0';
    else dirPath[0] = '\0';
    return dirPath;
}

const char *GetFileNameWithoutExt(const char *filePath) {
    static char name[256];
    const char *last = strrchr(filePath, '/');
    const char *base = last ? last + 1 : filePath;
    strncpy(name, base, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    char *dot = strrchr(name, '.');
    if (dot) *dot = '\0';
    return name;
}

const char *GetWorkingDirectory(void) {
    static char cwd[512] = "/dev/shm";
    return cwd;
}

const char *TextFormat(const char *text, ...) {
    static char buf[512];
    va_list args;
    va_start(args, text);
    vsnprintf(buf, sizeof(buf), text, args);
    va_end(args);
    return buf;
}

// --- Memory management ---
void *MemAlloc(unsigned int size) { return calloc(1, size); }
void MemFree(void *ptr) { free(ptr); }

// --- Texture/Image stubs (return empty) ---
Texture2D LoadTexture(const char *fileName) { (void)fileName; Texture2D t = {0}; return t; }
Texture2D LoadTextureFromImage(Image image) { (void)image; Texture2D t = {0}; return t; }
Image LoadImage(const char *fileName) { (void)fileName; Image img = {0}; return img; }
Image LoadImageFromMemory(const char *fileType, const unsigned char *fileData, int dataSize) {
    (void)fileType; (void)fileData; (void)dataSize;
    Image img = {0}; return img;
}
Color *LoadImageColors(Image image) { (void)image; return NULL; }
void UnloadImage(Image image) { (void)image; }
void UnloadImageColors(Color *colors) { (void)colors; }
Color GetImageColor(Image image, int x, int y) { (void)image; (void)x; (void)y; Color c = {0}; return c; }
void UnloadShader(Shader shader) { (void)shader; }

// LoadMaterialDefault is defined in rmodels.c, no stub needed

// --- rlgl stubs (all no-ops) ---
void rlActiveTextureSlot(int slot) { (void)slot; }
void rlBegin(int mode) { (void)mode; }
void rlEnd(void) {}
void rlColor3f(float r, float g, float b) { (void)r; (void)g; (void)b; }
void rlColor4ub(unsigned char r, unsigned char g, unsigned char b, unsigned char a) { (void)r; (void)g; (void)b; (void)a; }
void rlNormal3f(float x, float y, float z) { (void)x; (void)y; (void)z; }
void rlTexCoord2f(float x, float y) { (void)x; (void)y; }
void rlVertex3f(float x, float y, float z) { (void)x; (void)y; (void)z; }
void rlPushMatrix(void) {}
void rlPopMatrix(void) {}
void rlTranslatef(float x, float y, float z) { (void)x; (void)y; (void)z; }
void rlRotatef(float angle, float x, float y, float z) { (void)angle; (void)x; (void)y; (void)z; }
void rlScalef(float x, float y, float z) { (void)x; (void)y; (void)z; }
void rlViewport(int x, int y, int width, int height) { (void)x; (void)y; (void)width; (void)height; }

void rlEnableShader(unsigned int id) { (void)id; }
void rlDisableShader(void) {}
void rlEnableTexture(unsigned int id) { (void)id; }
void rlDisableTexture(void) {}
void rlEnableTextureCubemap(unsigned int id) { (void)id; }
void rlDisableTextureCubemap(void) {}
bool rlEnableVertexArray(unsigned int vaoId) { (void)vaoId; return true; }
void rlDisableVertexArray(void) {}
void rlEnableVertexAttribute(unsigned int index) { (void)index; }
void rlDisableVertexAttribute(unsigned int index) { (void)index; }
void rlEnableVertexBuffer(unsigned int id) { (void)id; }
void rlDisableVertexBuffer(void) {}
void rlEnableVertexBufferElement(unsigned int id) { (void)id; }
void rlDisableVertexBufferElement(void) {}
void rlEnableWireMode(void) {}
void rlDisableWireMode(void) {}

void rlSetTexture(unsigned int id) { (void)id; }
void rlSetUniform(int locIndex, const void *value, int uniformType, int count) {
    (void)locIndex; (void)value; (void)uniformType; (void)count;
}
void rlSetUniformMatrix(int locIndex, Matrix mat) { (void)locIndex; (void)mat; }
void rlSetUniformMatrices(int locIndex, const Matrix *mat, int count) { (void)locIndex; (void)mat; (void)count; }
void rlSetVertexAttribute(unsigned int index, int compSize, int type, bool normalized, int stride, int offset) {
    (void)index; (void)compSize; (void)type; (void)normalized; (void)stride; (void)offset;
}
void rlSetVertexAttributeDefault(int locIndex, const void *value, int attribType, int count) {
    (void)locIndex; (void)value; (void)attribType; (void)count;
}
void rlSetVertexAttributeDivisor(unsigned int index, int divisor) { (void)index; (void)divisor; }
void rlSetMatrixModelview(Matrix view) { (void)view; }
void rlSetMatrixProjection(Matrix proj) { (void)proj; }

unsigned int rlLoadVertexArray(void) { return 1; }
unsigned int rlLoadVertexBuffer(const void *buffer, int size, bool dynamic) { (void)buffer; (void)size; (void)dynamic; return 1; }
unsigned int rlLoadVertexBufferElement(const void *buffer, int size, bool dynamic) { (void)buffer; (void)size; (void)dynamic; return 1; }
void rlUnloadVertexArray(unsigned int vaoId) { (void)vaoId; }
void rlUnloadVertexBuffer(unsigned int vboId) { (void)vboId; }
void rlUnloadTexture(unsigned int id) { (void)id; }
void rlUpdateVertexBuffer(unsigned int bufferId, const void *data, int dataSize, int offset) {
    (void)bufferId; (void)data; (void)dataSize; (void)offset;
}

void rlDrawVertexArray(int offset, int count) { (void)offset; (void)count; }
void rlDrawVertexArrayElements(int offset, int count, const void *buffer) { (void)offset; (void)count; (void)buffer; }
void rlDrawVertexArrayInstanced(int offset, int count, int instances) { (void)offset; (void)count; (void)instances; }
void rlDrawVertexArrayElementsInstanced(int offset, int count, const void *buffer, int instances) {
    (void)offset; (void)count; (void)buffer; (void)instances;
}

Matrix rlGetMatrixModelview(void) { Matrix m = {0}; m.m0=1; m.m5=1; m.m10=1; m.m15=1; return m; }
Matrix rlGetMatrixProjection(void) { Matrix m = {0}; m.m0=1; m.m5=1; m.m10=1; m.m15=1; return m; }
Matrix rlGetMatrixTransform(void) { Matrix m = {0}; m.m0=1; m.m5=1; m.m10=1; m.m15=1; return m; }
Matrix rlGetMatrixProjectionStereo(int eye) { (void)eye; Matrix m = {0}; m.m0=1; m.m5=1; m.m10=1; m.m15=1; return m; }
Matrix rlGetMatrixViewOffsetStereo(int eye) { (void)eye; Matrix m = {0}; m.m0=1; m.m5=1; m.m10=1; m.m15=1; return m; }
bool rlIsStereoRenderEnabled(void) { return false; }

unsigned int rlGetShaderIdDefault(void) { return 0; }
int *rlGetShaderLocsDefault(void) { static int locs[32] = {0}; return locs; }
unsigned int rlGetTextureIdDefault(void) { return 0; }

int rlGetFramebufferWidth(void) { return 800; }
int rlGetFramebufferHeight(void) { return 600; }
