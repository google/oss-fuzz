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

// An extended cmsDoTransform fuzzer. The idea is to include a range of
// input/output source formats.

void
run_test(const uint8_t *data,
         size_t size,
         uint32_t intent,
         uint32_t flags, int dstVal) {
  if (size < 2) {
    return;
  }

  cmsHPROFILE srcProfile = cmsOpenProfileFromMem(data, size);
  if (!srcProfile) return;

  // Select dstProfile and dstFormat
  cmsHPROFILE dstProfile;
  uint32_t dstFormat;
  if (dstVal == 1) {
    dstProfile = cmsCreateLab4Profile(NULL);
    dstFormat = TYPE_Lab_8;
  }
  else if (dstVal == 2) {
    dstProfile = cmsCreateLab2Profile(NULL);
    dstFormat = TYPE_LabV2_8;
  }
  else if (dstVal == 3) {
    cmsToneCurve* gamma18;
    gamma18 = cmsBuildGamma(0, 1.8);
    dstProfile = cmsCreateGrayProfile(NULL, gamma18);
    cmsFreeToneCurve(gamma18);
    dstFormat = TYPE_GRAY_FLT | EXTRA_SH(1);
  }
  else if (dstVal == 4) {
    dstProfile = cmsCreateXYZProfile();
    dstFormat = TYPE_XYZ_16;
  }
  else if (dstVal == 5) {
    dstProfile = cmsCreateXYZProfile();
    dstFormat = TYPE_XYZ_DBL;
  }
  else if (dstVal == 6) {
    dstProfile = cmsCreateLab4Profile(NULL);
    dstFormat = TYPE_Lab_DBL;
  }
  else if (dstVal == 7) {
    dstProfile = cmsCreateLab4Profile(NULL);
    dstFormat = TYPE_Lab_DBL;
  }
  else {
    dstProfile = cmsCreate_sRGBProfile();
    dstFormat = TYPE_RGB_8;
  }

  if (!dstProfile) {
    cmsCloseProfile(srcProfile);
    return;
  }

  // Extract srcFormat from the random src profile
  cmsColorSpaceSignature srcCS = cmsGetColorSpace(srcProfile);
  cmsUInt32Number nSrcComponents = cmsChannelsOf(srcCS);
  cmsUInt32Number srcFormat;
  if (srcCS == cmsSigLabData) {
    if (dstVal != 7) {
        srcFormat =
            COLORSPACE_SH(PT_Lab) | CHANNELS_SH(nSrcComponents) | BYTES_SH(0);
    }
    else {
        srcFormat =
            COLORSPACE_SH(PT_Lab) | CHANNELS_SH(nSrcComponents) | BYTES_SH(0) | FLOAT_SH(1);
    }
  } else {
    srcFormat =
        COLORSPACE_SH(PT_ANY) | CHANNELS_SH(nSrcComponents) | BYTES_SH(1);
  }

  // Create the transform
  cmsContext ctx = cmsCreateContext(NULL, NULL);
  cmsHTRANSFORM hTransform = cmsCreateTransformTHR(
    ctx,
    srcProfile,
    srcFormat,
    dstProfile,
    dstFormat,
    intent,
    flags);

  cmsCloseProfile(srcProfile);
  cmsCloseProfile(dstProfile);
  if (!hTransform) return;


  // Do transformation.
  // The output buffer type depends on the dstFormat
  // The input buffer type depends on the srcFormat.
  if (T_BYTES(srcFormat) == 0) {  // 0 means double
    // Ensure output is large enough
    long long output[nSrcComponents*4];
    double input[nSrcComponents];
    for (uint32_t i = 0; i < nSrcComponents; i++) input[i] = 0.5f;
    cmsDoTransform(hTransform, input, output, 1);
  } 
  else {
    uint8_t input[nSrcComponents];
    for (uint32_t i = 0; i < nSrcComponents; i++) input[i] = 128;

    if (dstFormat == TYPE_XYZ_16) {
      cmsCIEXYZ output_XYZ = { 0, 0, 0 };
      cmsDoTransform(hTransform, input, &output_XYZ, 1);
    }
    else if (dstFormat == TYPE_XYZ_DBL) {
      cmsCIEXYZTRIPLE out[4];
      cmsDoTransform(hTransform, input, out, 1);
    }
    else if (dstFormat == TYPE_Lab_DBL) {
      cmsCIELab Lab1;
      cmsDoTransform(hTransform, input, &Lab1, 1);
    }
    else {
      uint8_t output[4];
      cmsDoTransform(hTransform, input, output, 1);
    }
  }
  cmsDeleteTransform(hTransform);
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 12) {
    return 0;
  }

  uint32_t flags         = *((const uint32_t *)data+0);
  uint32_t intent        = *((const uint32_t *)data+1) % 16;
  int decider = *((int*)data+2) % 10;
  data += 12;
  size -= 12;

  // Transform using various output formats.
  run_test(data, size, intent, flags, decider);

  return 0;
}
