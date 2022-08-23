// Copyright 2022 Google LLC
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

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <tiffio.h>
#include <tiffio.hxx>

#include <stdio.h>

#include <fuzzer/FuzzedDataProvider.h>


#define __TIFFSafeMultiply(t,v,m) ((((t)(m) != (t)0) && (((t)(((v)*(m))/(m))) == (t)(v))) ? (t)((v)*(m)) : (t)0)

const uint64_t MAX_SIZE = 500000000;

extern "C" void handle_error(const char *unused, const char *unused2, va_list unused3) {
    return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if(Size<5) {
    return 0;
  }
  FuzzedDataProvider fdp(Data, Size);
  TIFF      *tif1;
  uint32_t width = 10;
  const uint32_t  length = 40;
  const uint32_t  rows_per_strip = 1;
  tsize_t stripsize;
  tstrip_t stripcount;

  const char *filename = "test_packbits.tif";
  tif1 = TIFFOpen(filename, "w");
  if (!tif1) {
      fprintf (stderr, "Can't create test TIFF file %s.\n", filename);
      return 1;
  }

  switch (fdp.ConsumeIntegralInRange(0, 2)) {
    case 0:
      if (!TIFFSetField(tif1, TIFFTAG_COMPRESSION, COMPRESSION_PACKBITS)) {
          fprintf (stderr, "Can't set Compression tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_IMAGEWIDTH, width)) {
          fprintf (stderr, "Can't set ImageWidth tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_IMAGELENGTH, length)) {
          fprintf (stderr, "Can't set ImageLength tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_BITSPERSAMPLE, 8)) {
          fprintf (stderr, "Can't set BitsPerSample tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_SAMPLESPERPIXEL, 1)) {
          fprintf (stderr, "Can't set SamplesPerPixel tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_ROWSPERSTRIP, rows_per_strip)) {
          fprintf (stderr, "Can't set SamplesPerPixel tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG)) {
          fprintf (stderr, "Can't set PlanarConfiguration tag.\n");
          TIFFClose(tif1);
          return 0;
      }
    case 1:
      if (!TIFFSetField(tif1, TIFFTAG_COMPRESSION, COMPRESSION_NONE)) {
          fprintf (stderr, "Can't set Compression tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_IMAGEWIDTH, width)) {
          fprintf (stderr, "Can't set ImageWidth tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      if (!TIFFSetField(tif1, TIFFTAG_IMAGELENGTH, length)) {
          fprintf (stderr, "Can't set ImageWidth tag.\n");
          TIFFClose(tif1);
          return 0;
      }
      TIFFSetField(tif1, TIFFTAG_BITSPERSAMPLE, 8);
      TIFFSetField(tif1, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
      TIFFSetField(tif1, TIFFTAG_SAMPLESPERPIXEL, 1);
      TIFFSetField(tif1, TIFFTAG_ROWSPERSTRIP, 1);
  }

  stripsize=TIFFStripSize(tif1);
  stripcount=TIFFNumberOfStrips(tif1);
  std::vector<uint8_t> rBytes = fdp.ConsumeRemainingBytes<uint8_t>();

  TIFFWriteEncodedStrip( tif1, (tstrip_t)0, (void *)rBytes.data(), (int)rBytes.size() );
  TIFFClose(tif1);

  return 0;
}

