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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size < 16) {
    return 0;
  }

  cmsHPROFILE hInProfile = cmsOpenProfileFromMem(data, size);
  if (!hInProfile) {
    return 0;
  }

  cmsHPROFILE hOutProfile = cmsCreate_sRGBProfile();
  if (!hOutProfile) {
    cmsCloseProfile(hInProfile);
    return 0;
  }
  cmsColorSpaceSignature srcCS = cmsGetColorSpace(hInProfile);
  cmsUInt32Number nSrcComponents = cmsChannelsOf(srcCS);
  cmsUInt32Number srcFormat;
  if (srcCS == cmsSigLabData) {
    srcFormat =
        COLORSPACE_SH(PT_Lab) | CHANNELS_SH(nSrcComponents) | BYTES_SH(0);
  } else {
    srcFormat =
        COLORSPACE_SH(PT_ANY) | CHANNELS_SH(nSrcComponents) | BYTES_SH(1);
  }
  cmsHTRANSFORM hTransform = cmsCreateTransform(
      hInProfile, srcFormat, hOutProfile, TYPE_BGR_8,
      *((const uint32_t *)data + 3) % 16, *((const uint32_t *)data + 2));

  cmsCloseProfile(hInProfile);
  cmsCloseProfile(hOutProfile);
  if (!hTransform) {
    return 0;
  }

  cmsFloat64Number version;
  if (*((const uint32_t *)data + 3) % 2 == 0) {
    version = 3.4;
  } else {
    version = 4.4;
  }

  // cmsTransform2DeviceLink
  cmsHPROFILE devicelinkProfile = cmsTransform2DeviceLink(
      hTransform, version, *((const uint32_t *)data + 2));

  // clean up
  cmsDeleteTransform(hTransform);
  if (devicelinkProfile) {
    cmsCloseProfile(devicelinkProfile);
  }

  // cmsCreateLinearizationDeviceLink
  cmsToneCurve *tone = cmsBuildGamma(NULL, *((const uint32_t *)data + 3));
  if (!tone) {
    return 0;
  }
  // 15 curves, so it can handle all color spaces
  cmsToneCurve *rgb_curves[15] = {tone, tone, tone, tone, tone,
                                  tone, tone, tone, tone, tone,
                                  tone, tone, tone, tone, tone};
  cmsHPROFILE linearizationDeviceLinkProfile =
      cmsCreateLinearizationDeviceLink(srcCS, rgb_curves);

  cmsFreeToneCurve(tone);

  if (linearizationDeviceLinkProfile) {
    cmsCloseProfile(linearizationDeviceLinkProfile);
  }

  return 0;
}
