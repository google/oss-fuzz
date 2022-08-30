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

/* Fuzzer that creates a transform with the following vars initialized by way
 * of fuzzer data:
 * - srcFormat
 * - dstFormat
 * - profile
 * Then applies the transform once on a input derived from the fuzzer.
 * This input data and output data to cmsDoTransform is allocated such
 * that it is large enough for any input/output types.
 */ 
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2048) {
    return 0;
  }
  uint8_t *profile_data = NULL;
  uint8_t *input_data = NULL;
  uint8_t *output_data = NULL;

  // Create a random src and dst format
  uint32_t srcFormat = *(uint32_t*)data;
  data += 4;
  size -= 4;
  uint32_t dstFormat = *(uint32_t*)data;
  data += 4;
  size -= 4;

  profile_data = (uint8_t*)malloc(512);
  memcpy(profile_data, data, 512);
  data += 512;
  size -= 512;
  cmsHPROFILE srcProfile = cmsOpenProfileFromMem(profile_data, 512);
  if (!srcProfile) {
    goto cleanup;
  }

  cmsHPROFILE dstProfile = cmsCreate_sRGBProfile();
  if (!dstProfile) {
    cmsCloseProfile(srcProfile);
    goto cleanup;
  }

  cmsColorSpaceSignature srcCS = cmsGetColorSpace(srcProfile);
  cmsUInt32Number nSrcComponents = cmsChannelsOf(srcCS);

  // allocate input buffer with fuzz data. Choose a large enough size so
  // overflows wont occur due to erroneous typing.
  if (size < nSrcComponents * 80) {
    cmsCloseProfile(srcProfile);
    cmsCloseProfile(dstProfile);
    goto cleanup;
  }
  input_data = (uint8_t *)malloc(nSrcComponents * 80);
  memcpy(input_data, data, nSrcComponents*80);
  // Make empty output data
  output_data = (uint8_t *)malloc(nSrcComponents * 80);

  cmsUInt32Number intent = 0;
  cmsUInt32Number flags = 0;
  cmsHTRANSFORM hTransform = cmsCreateTransform(
      srcProfile, srcFormat, dstProfile, dstFormat, intent, flags);
  cmsCloseProfile(srcProfile);
  cmsCloseProfile(dstProfile);

  if (!hTransform) {
    goto cleanup;
  }

  // Do the transform
  cmsDoTransform(hTransform, input_data, output_data, 1);
  cmsDeleteTransform(hTransform);

cleanup:
  if (output_data != NULL) {
    free(output_data);
  }
  if (input_data != NULL) {
    free(input_data);
  }
  if (profile_data != NULL) {
    free(profile_data);
  }

  return 0;
}
