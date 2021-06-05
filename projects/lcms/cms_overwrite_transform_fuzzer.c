// Copyright 2020 Google LLC
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

#include <stdint.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 if (size < 2) {
   return 0;
 }

 size_t mid = size / 2;

 cmsHPROFILE hInProfile, hOutProfile;
 cmsHTRANSFORM hTransform;

 hInProfile = cmsOpenProfileFromMem(data, mid);
 hOutProfile = cmsOpenProfileFromMem(data + mid, size - mid);
 hTransform = cmsCreateTransform(hInProfile, TYPE_BGR_8, hOutProfile,
                                 TYPE_BGR_8, INTENT_PERCEPTUAL, 0);
 cmsCloseProfile(hInProfile);
 cmsCloseProfile(hOutProfile);

 if (hTransform) {
   cmsDeleteTransform(hTransform);
 }
 return 0;
}
