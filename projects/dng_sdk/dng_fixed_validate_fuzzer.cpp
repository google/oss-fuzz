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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Set the various sizes
  gPreferredSize = 0;
  gMinimumSize = 0;
  gMaximumSize = 0;

  gDumpDNG.Clear();
  char dumpDNGFilename[256];
  sprintf(dumpDNGFilename, "/tmp/libfuzzer-dng.%d.dng", getpid());
  gDumpDNG.Set(dumpDNGFilename); 

  gDumpStage1.Clear();
  char dumpStage1Filename[256];
  sprintf(dumpStage1Filename, "/tmp/libfuzzer-stage1.%d.dng", getpid());
  gDumpStage1.Set(dumpStage1Filename); 

  gDumpStage2.Clear();
  char dumpStage2Filename[256];
  sprintf(dumpStage2Filename, "/tmp/libfuzzer-stage2.%d.dng", getpid());
  gDumpStage2.Set(dumpStage2Filename); 

  gDumpStage3.Clear();
  char dumpStage3Filename[256];
  sprintf(dumpStage3Filename, "/tmp/libfuzzer-stage3.%d.dng", getpid());
  gDumpStage3.Set(dumpStage3Filename); 

  gDumpTIF.Clear();
  char dumpTifFilename[256];
  sprintf(dumpTifFilename, "/tmp/libfuzzer-tif.%d.tif", getpid());
  gDumpTIF.Set(dumpTifFilename); 

  gProxyDNGSize = 1024;
  gMosaicPlane = 32;


  gFourColorBayer = true;
  gFinalSpace = &dng_space_sRGB::Get ();

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
      return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  // Target
  dng_validate(filename);

  // cleanup file
  unlink(filename);

  return 0;
}
