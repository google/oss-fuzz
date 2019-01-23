#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec_def.h"
#include "codec_app_def.h"
#include "codec_api.h"
#include "read_config.h"
#include "typedefs.h"
#include "measure_time.h"

// CC=clang CXX=clang++ CFLAGS="-fsanitize=address,fuzzer-no-link -g" CXXFLAGS="-fsanitize=address,fuzzer-no-link -g" LDFLAGS="-fsanitize=address,fuzzer-no-link" make -j$(nproc) USE_ASM=No BUILDTYPE=Debug libraries
// clang++ -fsanitize=address -g -O3 -I./codec/api/svc -I./codec/console/common/inc -I./codec/common/inc -L. -lFuzzer -lstdc++ fuzz_decoder.cpp libopenh264.a

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  int32_t i;
  int32_t iBufPos = 0;
  int32_t iEndOfStreamFlag;
  int32_t iSliceSize;
  ISVCDecoder *pDecoder;
  SDecodingParam sDecParam = {0};
  SBufferInfo sDstBufInfo;
  uint8_t* pBuf;
  uint8_t* pData[3] = {NULL};
  uint8_t uiStartCode[4] = {0, 0, 0, 1};

  pBuf = new uint8_t[size + 4];
  if (pBuf == NULL) {
    goto label_exit;
  }
  memcpy (pBuf, data, size);
  memcpy (pBuf + size, &uiStartCode[0], 4);
  memset (&sDstBufInfo, 0, sizeof(SBufferInfo));

  // TODO: is this the best/fastest ERROR_CON to use?
  sDecParam.eEcActiveIdc = ERROR_CON_SLICE_COPY;
  // TODO: should we also fuzz VIDEO_BITSTREAM_SVC
  sDecParam.sVideoProperty.eVideoBsType = VIDEO_BITSTREAM_AVC;
  
  WelsCreateDecoder (&pDecoder);
  pDecoder->Initialize (&sDecParam);

  while (1) {
    if (iBufPos >= size) {
      iEndOfStreamFlag = 1;
      if (iEndOfStreamFlag)
        pDecoder->SetOption (DECODER_OPTION_END_OF_STREAM, (void*)&iEndOfStreamFlag);
      break;
    }

    for (i = 0; i < size; i++) {
      if ((pBuf[iBufPos + i] == 0 && pBuf[iBufPos + i + 1] == 0 && pBuf[iBufPos + i + 2] == 0 && pBuf[iBufPos + i + 3] == 1
          && i > 0) || (pBuf[iBufPos + i] == 0 && pBuf[iBufPos + i + 1] == 0 && pBuf[iBufPos + i + 2] == 1 && i > 0)) {
        break;
      }
    }
    iSliceSize = i;
    if (iSliceSize < 4) {
      if (iSliceSize == 0) {
        // I don't think this should happen but let's just avoid the hang
        goto label_cleanup;
      }
      iBufPos += iSliceSize;
      continue;
    }

    pDecoder->DecodeFrameNoDelay (pBuf + iBufPos, iSliceSize, pData, &sDstBufInfo);
    iBufPos += iSliceSize;
  }

label_cleanup:
  pDecoder->Uninitialize ();
  WelsDestroyDecoder (pDecoder);

label_exit:
  if (pBuf) {
    delete[] pBuf;
    pBuf = NULL;
  }

  return 0;
}
