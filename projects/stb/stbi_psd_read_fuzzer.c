/* Copyright 2024 Google LLC

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
#ifdef __cplusplus
extern "C" {
#endif

#define STBI_NO_JPEG
#define STBI_NO_PNG
#define STBI_NO_BMP
#define STBI_NO_GIF
#define STBI_NO_TGA
#define STBI_NO_PIC
#define STBI_NO_PNM
#define STBI_NO_HDR

#define STB_IMAGE_IMPLEMENTATION
#include "../stb_image.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    stbi__context s;
    stbi__start_mem(&s, data, size);

    int x, y, comp;
    stbi__result_info ri;
    int bpc = 8; // Bits per channel

    void *result = stbi__psd_load(&s, &x, &y, &comp, 0, &ri, bpc);
    if (result) {
        free(result);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
