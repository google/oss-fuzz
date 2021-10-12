/* Copyright 2021 Google LLC
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "dng_color_space.h"
#include "dng_date_time.h"
#include "dng_exceptions.h"
#include "dng_file_stream.h"
#include "dng_globals.h"
#include "dng_host.h"
#include "dng_ifd.h"
#include "dng_image_writer.h"
#include "dng_info.h"
#include "dng_linearization_info.h"
#include "dng_mosaic_info.h"
#include "dng_negative.h"
#include "dng_preview.h"
#include "dng_render.h"
#include "dng_simple_image.h"
#include "dng_tag_codes.h"
#include "dng_tag_types.h"
#include "dng_tag_values.h"

// Run a set of the operations high-level operations on the dng_sdk
// This code is inspired by dng_validate.cpp and performs many of the same
// operations in a simplified manner.
void runFuzzerWithVariableHost(char *filename, uint32_t dng_version,
                               bool linear, bool preview, bool should_proxy) {
  dng_host host;
  host.SetPreferredSize(0);
  host.SetMinimumSize(0);
  host.SetMaximumSize(0);
  host.SetSaveDNGVersion(dng_version);
  host.SetSaveLinearDNG(linear);
  host.SetForPreview(preview);
  host.ValidateSizes();

  AutoPtr<dng_negative> negative;
  try {
    dng_info info;
    dng_file_stream stream((const char *)filename);
    info.Parse(host, stream);
    info.PostParse(host);

    if (info.IsValidDNG()) {
      negative.Reset(host.Make_dng_negative());
      negative->Parse(host, stream, info);
      negative->PostParse(host, stream, info);
      negative->ReadStage1Image(host, stream, info);
      if (info.fMaskIndex != -1) {
        negative->ReadTransparencyMask(host, stream, info);
      }

      negative->SynchronizeMetadata();
      negative->SetFourColorBayer();
      negative->BuildStage2Image(host);
      negative->BuildStage3Image(host, 1);

      if (should_proxy) {
        dng_image_writer writer;
        negative->ConvertToProxy(host, writer, 1);
      }

      if (negative->NeedFlattenTransparency(host)) {
        negative->FlattenTransparency(host);
      }

      // Write DNG
      dng_file_stream stream3("/tmp/randdng1", true);
      dng_image_writer writer3;
      dng_preview_list previewList;
      writer3.WriteDNG(host, stream3, *negative.Get(), &previewList,
                       dng_version, false);

      // Write TIFF
      dng_file_stream stream2("/tmp/randpng", true);
      const dng_image &stage3 = *negative->Stage3Image();
      dng_image_writer writer2;
      writer2.WriteTIFF(host, stream2, stage3,
                        stage3.Planes() >= 3 ? piRGB : piBlackIsZero);

      // Create a renderer
      dng_render render(host, *negative);
      AutoPtr<dng_image> finalImage;
      finalImage.Reset(render.Render());
    }
  } catch (dng_exception &e) {
    // dng_sdk throws C++ exceptions on errors
    // catch them here to prevent libFuzzer from crashing.
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  // parse the data using a variable set of options for dng_host
  runFuzzerWithVariableHost(filename, dngVersion_None, true, false, false);
  runFuzzerWithVariableHost(filename, dngVersion_1_0_0_0, true, true, false);
  runFuzzerWithVariableHost(filename, dngVersion_1_1_0_0, true, true, false);
  runFuzzerWithVariableHost(filename, dngVersion_1_2_0_0, true, true, false);
  runFuzzerWithVariableHost(filename, dngVersion_1_3_0_0, true, true, false);
  runFuzzerWithVariableHost(filename, dngVersion_1_4_0_0, true, true, false);
  runFuzzerWithVariableHost(filename, dngVersion_1_4_0_0, false, false, true);

  unlink(filename);
  return 0;
}
