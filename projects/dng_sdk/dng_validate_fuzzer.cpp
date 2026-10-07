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
#include <fuzzer/FuzzedDataProvider.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  // Set the various sizes
  gPreferredSize = provider.ConsumeIntegral<uint32_t>();
  gMinimumSize = provider.ConsumeIntegral<uint32_t>();
  gMaximumSize = provider.ConsumeIntegral<uint32_t>();

  gDumpDNG.Clear();
  char dumpDNGFilename[256];
  if (provider.ConsumeBool()) {
    sprintf(dumpDNGFilename, "/tmp/libfuzzer-dng.%d.dng", getpid());
    gDumpDNG.Set(dumpDNGFilename); 
  }

  gDumpStage1.Clear();
  char dumpStage1Filename[256];
  if (provider.ConsumeBool()) {
    sprintf(dumpStage1Filename, "/tmp/libfuzzer-stage1.%d.dng", getpid());
    gDumpStage1.Set(dumpStage1Filename); 
  }
  

  gDumpStage2.Clear();
  char dumpStage2Filename[256];
  if (provider.ConsumeBool()) {
    sprintf(dumpStage2Filename, "/tmp/libfuzzer-stage2.%d.dng", getpid());
    gDumpStage2.Set(dumpStage2Filename); 
  }

  gDumpStage3.Clear();
  char dumpStage3Filename[256];
  if (provider.ConsumeBool()) {
    sprintf(dumpStage3Filename, "/tmp/libfuzzer-stage3.%d.dng", getpid());
    gDumpStage3.Set(dumpStage3Filename); 
  }

  gDumpTIF.Clear();
  char dumpTifFilename[256];
  if (provider.ConsumeBool()) {
    sprintf(dumpTifFilename, "/tmp/libfuzzer-tif.%d.tif", getpid());
    gDumpTIF.Set(dumpTifFilename); 
  }

  gProxyDNGSize = provider.ConsumeIntegral<uint32_t>();
  gMosaicPlane = provider.ConsumeIntegral<int32_t>();


  gFourColorBayer = provider.ConsumeBool();

  switch (provider.ConsumeIntegralInRange(0, 7)) {
    case 0:
      gFinalSpace = &dng_space_sRGB::Get ();
      break;
    case 1:
      gFinalSpace = &dng_space_AdobeRGB::Get ();
      break;
    case 2:
      gFinalSpace = &dng_space_ProPhoto::Get ();
      break;
    case 3:
      gFinalSpace = &dng_space_ColorMatch::Get ();
      break;
    case 4:
      gFinalSpace = &dng_space_GrayGamma18::Get ();
      break;
    case 5:
      gFinalSpace = &dng_space_GrayGamma22::Get ();
      break;
    default:
      gFinalSpace = &dng_space_sRGB::Get ();
      break;
  }

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  std::string restData = provider.ConsumeRemainingBytesAsString();
  if (restData.size() > 0) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(restData.c_str(), restData.size(), 1, fp);
    fclose(fp);

    // Target
    dng_validate(filename);

    // cleanup file
    unlink(filename);
  }
  return 0;
}
