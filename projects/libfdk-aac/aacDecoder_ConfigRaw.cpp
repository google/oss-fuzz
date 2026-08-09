// Copyright 2019 Google Inc.
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

#include "aacdecoder_lib.h"
#include <stdint.h>

#define FILEREAD_MAX_LAYERS 1

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  HANDLE_AACDECODER aacDecoderInfo = NULL;

  UCHAR *conf[FILEREAD_MAX_LAYERS];
  UINT confSize[FILEREAD_MAX_LAYERS];

  if (Size > 255) return 0;

  aacDecoderInfo = aacDecoder_Open(TT_MP4_ADIF, FILEREAD_MAX_LAYERS);
  FDK_ASSERT(aacDecoderInfo != NULL);

  for (UINT layer = 0; layer < FILEREAD_MAX_LAYERS; layer++) {
    conf[layer] = const_cast<UCHAR *>(Data);
    confSize[layer] = Size;
  }

  aacDecoder_ConfigRaw(aacDecoderInfo, conf, confSize);
  aacDecoder_Close(aacDecoderInfo);
  return 0;
}
