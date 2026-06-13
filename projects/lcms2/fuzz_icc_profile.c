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

// Fuzz harness for the lcms2 ICC profile parser and color transform pipeline.
//
// lcms2 (Little Color Management System) is the ICC color profile library used
// by Chromium, GIMP, KDE, LibreOffice, ImageMagick, and virtually every Linux
// desktop application that handles color-managed images.
//
// ICC profiles are embedded in JPEG, PNG, TIFF, and WebP images and are
// therefore attacker-controlled in any application that opens untrusted images.
//
// Coverage:
//   cmsOpenProfileFromMem()  – parses arbitrary ICC profile data from memory
//   cmsGetProfileInfo()      – reads header and description strings
//   cmsGetColorSpace()       – reads PCS and colorspace tags
//   cmsCreateTransform()     – builds the full color transform pipeline
//     - connects two profiles: the input profile under test + sRGB output
//     - exercises gamut mapping, TRC curves, matrix/LUT processing
//   cmsDoTransform()         – runs a small pixel batch through the transform
//   cmsDetectBlackPoint()    – exercises black-point compensation code

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#include "lcms2.h"

// Suppress lcms2 error output during fuzzing.
static void null_error_handler(cmsContext ctx, cmsUInt32Number code,
                               const char *text) {
  (void)ctx;
  (void)code;
  (void)text;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cmsSetLogErrorHandler(null_error_handler);

  // Open the fuzz-supplied ICC profile.
  cmsHPROFILE hInput = cmsOpenProfileFromMem(data, (cmsUInt32Number)size);
  if (!hInput) return 0;

  // Read basic header fields.
  cmsColorSpaceSignature cs = cmsGetColorSpace(hInput);
  cmsColorSpaceSignature pcs = cmsGetPCS(hInput);
  cmsUInt32Number icc_version = cmsGetEncodedICCversion(hInput);
  (void)cs;
  (void)pcs;
  (void)icc_version;

  // Read the profile description string (API returns wchar_t).
  wchar_t desc[256];
  cmsGetProfileInfo(hInput, cmsInfoDescription, "en", "US",
                    desc, sizeof(desc) / sizeof(wchar_t));

  // Try to build a transform from the fuzz-supplied profile to sRGB.
  // This exercises the full gamut mapping / TRC / matrix / LUT code paths.
  cmsHPROFILE hSRGB = cmsCreate_sRGBProfile();
  if (hSRGB) {
    // Determine input channel count to set the correct formatter.
    cmsUInt32Number channels =
        cmsChannelsOfColorSpace(cmsGetColorSpace(hInput));
    cmsUInt32Number in_format  = BYTES_SH(1) | CHANNELS_SH(channels);
    cmsUInt32Number out_format = TYPE_RGB_8;

    cmsHTRANSFORM hXform = cmsCreateTransform(
        hInput, in_format, hSRGB, out_format, INTENT_PERCEPTUAL, 0);
    if (hXform) {
      // Run a tiny batch through the transform.
      uint8_t src[64] = {0};
      uint8_t dst[64];
      cmsUInt32Number npixels = sizeof(src) / (channels > 0 ? channels : 1);
      if (npixels > 0 && npixels <= sizeof(src))
        cmsDoTransform(hXform, src, dst, npixels);
      cmsDeleteTransform(hXform);
    }

    // Also try sRGB -> fuzz profile transform.
    cmsHTRANSFORM hRevXform = cmsCreateTransform(
        hSRGB, TYPE_RGB_8, hInput, in_format, INTENT_RELATIVE_COLORIMETRIC, 0);
    if (hRevXform)
      cmsDeleteTransform(hRevXform);

    cmsCloseProfile(hSRGB);
  }

  // Black point detection exercises auxiliary metadata code paths.
  cmsCIEXYZ bp;
  cmsDetectBlackPoint(&bp, hInput, INTENT_PERCEPTUAL, 0);

  cmsCloseProfile(hInput);
  return 0;
}
