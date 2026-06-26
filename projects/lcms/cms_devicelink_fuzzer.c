/* Copyright 2023 Google LLC
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

#include "lcms2.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size < 5) {
    return 0;
  }

  /* Read ink limit safely (avoid unaligned read UB) */
  uint32_t raw;
  memcpy(&raw, data, sizeof(raw));
  cmsFloat64Number limit = raw % 401;
  data += 4;
  size -= 4;

  /* Use fuzz input to select color space */
  cmsColorSpaceSignature colorSpaces[] = {
    cmsSigCmykData, cmsSigCmyData, cmsSigRgbData
  };
  cmsColorSpaceSignature cs = colorSpaces[data[0] % 3];
  data += 1;
  size -= 1;

  cmsHPROFILE deviceLink = cmsCreateInkLimitingDeviceLink(cs, limit);
  if (!deviceLink) {
    return 0;
  }

  /* Create an output profile to build a transform with the device link */
  cmsHPROFILE outProfile = cmsCreate_sRGBProfile();
  if (!outProfile) {
    cmsCloseProfile(deviceLink);
    return 0;
  }

  cmsUInt32Number nComponents = cmsChannelsOf(cs);
  cmsUInt32Number srcFormat = COLORSPACE_SH(PT_ANY) |
                              CHANNELS_SH(nComponents) | BYTES_SH(1);

  cmsHTRANSFORM hTransform = cmsCreateTransform(
      deviceLink, srcFormat, outProfile, TYPE_BGR_8, 0, 0);
  cmsCloseProfile(deviceLink);
  cmsCloseProfile(outProfile);

  if (!hTransform) {
    return 0;
  }

  /* Feed fuzz data through the transform */
  if (size >= nComponents) {
    uint8_t output[4];
    cmsDoTransform(hTransform, data, output, 1);
  }

  cmsDeleteTransform(hTransform);

  return 0;
}
