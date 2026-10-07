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
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "lcms2.h"

cmsTagSignature tagsToRead[] = {
  cmsSigGreenColorantTag,
  cmsSigGreenMatrixColumnTag,
  cmsSigGreenTRCTag,
  cmsSigMeasurementTag,
  cmsSigNamedColorTag,
  cmsSigPreview1Tag,
  cmsSigPs2CRD2Tag,
  cmsSigPs2CRD3Tag,
  cmsSigRedTRCTag,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d.icc", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  cmsHPROFILE hProfile = cmsOpenProfileFromFile(filename, "r");
  // If we have a profile, perform a set of operations
  if (hProfile) {
    char tagBuffer[4];

    // Perform multiple tag reads. Read tags twice as behavior matters
    // if tags have been read before.
    for (int j = 0; j < 2; j++) {
      for (int i = 0; i < sizeof(tagsToRead)/sizeof(tagsToRead[0]); i++) {
        cmsReadRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
        cmsReadRawTag(hProfile, tagsToRead[i], NULL, 0);
        cmsReadRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
        cmsReadTag(hProfile, tagsToRead[i]);
      }
    }

    // Read profile info
    cmsInfoType info = data[0] % 4;
    char outBuffer[100];

    cmsGetProfileInfoASCII(hProfile, info, "DEN", "DEN", outBuffer, 100);
    cmsGetTagCount(hProfile);
    if (size > 2) {
      cmsGetTagSignature(hProfile, (cmsUInt32Number)data[1]);
    }
    if (size > 40) {
      cmsTagSignature tag = *((uint32_t *)(data+5));
      cmsTagLinkedTo(hProfile, tag);
    }

    // Save to random file
    cmsSaveProfileToFile(hProfile, "random.icc");
    cmsCloseProfile(hProfile);
  }

  // Let's write the profile now.
  hProfile = cmsOpenProfileFromFile(filename, "w");
  if (hProfile) {
    char tagBuffer[4] = {'a', 'a', 'a', 'a'};

    // Perform multiple tag reads
    for (int j = 0; j < 2; j++) {
      for (int i = 0; i < sizeof(tagsToRead)/sizeof(tagsToRead[0]); i++) {
        cmsReadRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
        cmsReadRawTag(hProfile, tagsToRead[i], NULL, 0);
        cmsReadRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
        cmsReadTag(hProfile, tagsToRead[i]);
      }
    }

    for (int i = 0; i < sizeof(tagsToRead)/sizeof(tagsToRead[0]); i++) {
      cmsWriteRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
    }

    for (int j = 0; j < 2; j++) {
      for (int i = 0; i < sizeof(tagsToRead)/sizeof(tagsToRead[0]); i++) {
        cmsReadRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
        cmsReadRawTag(hProfile, tagsToRead[i], NULL, 0);
        cmsReadRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
        cmsReadTag(hProfile, tagsToRead[i]);
      }
    }

    for (int i = 0; i < sizeof(tagsToRead)/sizeof(tagsToRead[0]); i++) {
      cmsWriteRawTag(hProfile, tagsToRead[i], tagBuffer, 4);
    }

    // Save to random file
    cmsSaveProfileToFile(hProfile, "random.icc");
    cmsCloseProfile(hProfile);
  }

  unlink(filename);
  return 0;
}
