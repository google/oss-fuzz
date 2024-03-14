/* Copyright 2024 Google Inc.

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

#define STB_IMAGE_IMPLEMENTATION
#include "../stb_image.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    int x, y, comp, z;
    int *delays = NULL; 

    if (size > INT_MAX) {
        return 0; 
    }

    stbi_uc *image = stbi_load_gif_from_memory(data, (int)size, &delays, &x, &y, &z, &comp, 0);

    if (image) {
        stbi_image_free(image);
        if (delays) {
            STBI_FREE(delays); 
        }
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
