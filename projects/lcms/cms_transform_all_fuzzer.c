/* Copyright 2022 Google LLC
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

#include <stdint.h>
#include "lcms2.h"

void
run_test(const uint8_t *data,
         size_t size,
         uint32_t intent_id,
         uint32_t input_format,
         uint32_t output_format,
         uint32_t flags) {
 if (size < 2) {
   return;
 }

 size_t mid = size / 2;

 cmsHPROFILE hInProfile, hOutProfile;
 cmsHTRANSFORM hTransform;

 hInProfile = cmsOpenProfileFromMem(data, mid);
 hOutProfile = cmsOpenProfileFromMem(data + mid, size - mid);
 hTransform = cmsCreateTransform(hInProfile, input_format, hOutProfile,
                                 output_format, intent_id, flags);
 cmsCloseProfile(hInProfile);
 cmsCloseProfile(hOutProfile);

 if (hTransform) {
   cmsDeleteTransform(hTransform);
 }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if (size < 16) {
  return 0;
 }

 // Generate a random set of args for cmsCreateTransform
 uint32_t input_format  = *((const uint32_t *)data);
 uint32_t output_format = *((const uint32_t *)data+1);
 uint32_t flags         = *((const uint32_t *)data+2);
 uint32_t intent        = *((const uint32_t *)data+3) % 16;
 data += 16;
 size -= 16;

 run_test(data, size, intent, input_format, output_format, flags);
 return 0;
}
