// Copyright 2020 Google LLC
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ImfArray.h>
#include <ImfTiledRgbaFile.h>

// Handle the case when the custom namespace is not exposed
#include <ImfChannelList.h>
#include <ImfMultiPartInputFile.h>
#include <ImfMultiPartOutputFile.h>
#include <ImfPartType.h>
#include <ImfTiledInputPart.h>
#include <ImfTiledOutputPart.h>
#include <OpenEXRConfig.h>
#include <ImfStdIO.h>

using namespace OPENEXR_IMF_INTERNAL_NAMESPACE;
using IMATH_NAMESPACE::Box2i;

namespace {

void readImageONE(TiledRgbaInputFile *in, int dwx, int dwy) {
  try {
    const Box2i &dw = in->dataWindow();

    int w = dw.max.x - dw.min.x + 1;
    int h = dw.max.y - dw.min.y + 1;

    Array2D<Rgba> pixels(h, w);
    in->setFrameBuffer(&pixels[-dwy][-dwx], 1, w);
    in->readTiles(0, in->numXTiles() - 1, 0, in->numYTiles() - 1);
  } catch (...) {
  }
}

void readImageONE2(IStream& is) {
  MultiPartInputFile *in;
  try {
    in = new MultiPartInputFile(is);
  } catch (...) {
    return;
  }

  TiledInputPart *inpart;
  try {
    for (int p = 0; p < in->parts(); p++) {
      try {
        inpart = new TiledInputPart(*in, p);
      } catch (...) {
        inpart = NULL;
        continue;
      }

      const Box2i &dw = inpart->header().dataWindow();

      int w = dw.max.x - dw.min.x + 1;
      int h = dw.max.y - dw.min.y + 1;
      int dwx = dw.min.x;
      int dwy = dw.min.y;

      Array2D<Rgba> pixels(h, w);
      FrameBuffer i;
      i.insert("R", Slice(HALF, (char *)&(pixels[-dwy][-dwx].r), sizeof(Rgba),
                          w * sizeof(Rgba)));
      i.insert("G", Slice(HALF, (char *)&(pixels[-dwy][-dwx].g), sizeof(Rgba),
                          w * sizeof(Rgba)));
      i.insert("B", Slice(HALF, (char *)&(pixels[-dwy][-dwx].b), sizeof(Rgba),
                          w * sizeof(Rgba)));
      i.insert("A", Slice(HALF, (char *)&(pixels[-dwy][-dwx].a), sizeof(Rgba),
                          w * sizeof(Rgba)));

      inpart->setFrameBuffer(i);
      inpart->readTiles(0, inpart->numXTiles() - 1, 0, inpart->numYTiles() - 1);

      delete inpart;
      inpart = NULL;
    }
  } catch (...) {
    delete inpart;
  }

  delete in;
}

void readImageMIP(TiledRgbaInputFile *in, int dwx, int dwy) {
  try {
    int numLevels = in->numLevels();
    Array<Array2D<Rgba> > levels2(numLevels);

    for (int level = 0; level < numLevels; ++level) {
      int levelWidth = in->levelWidth(level);
      int levelHeight = in->levelHeight(level);
      levels2[level].resizeErase(levelHeight, levelWidth);

      in->setFrameBuffer(&(levels2[level])[-dwy][-dwx], 1, levelWidth);
      in->readTiles(0, in->numXTiles(level) - 1, 0, in->numYTiles(level) - 1,
                    level);
    }
  } catch (...) {
  }
}

void readImageRIP(TiledRgbaInputFile *in, int dwx, int dwy) {
  try {
    int numXLevels = in->numXLevels();
    int numYLevels = in->numYLevels();
    Array2D<Array2D<Rgba> > levels2(numYLevels, numXLevels);

    for (int ylevel = 0; ylevel < numYLevels; ++ylevel) {
      for (int xlevel = 0; xlevel < numXLevels; ++xlevel) {
        int levelWidth = in->levelWidth(xlevel);
        int levelHeight = in->levelHeight(ylevel);
        levels2[ylevel][xlevel].resizeErase(levelHeight, levelWidth);
        in->setFrameBuffer(&(levels2[ylevel][xlevel])[-dwy][-dwx], 1,
                           levelWidth);

        in->readTiles(0, in->numXTiles(xlevel) - 1, 0,
                      in->numYTiles(ylevel) - 1, xlevel, ylevel);
      }
    }
  } catch (...) {
  }
}

}  // namespace

static void fuzzImage(IStream& is) {
  Header::setMaxImageSize(10000, 10000);
  Header::setMaxTileSize(10000, 10000);

  TiledRgbaInputFile *in;
  try {
    in = new TiledRgbaInputFile(is);
  } catch (...) {
    return;
  }

  const Box2i &dw = in->dataWindow();
  int dwx = dw.min.x;
  int dwy = dw.min.y;

  readImageMIP(in, dwx, dwy);
  readImageRIP(in, dwx, dwy);
  readImageONE(in, dwx, dwy);
  readImageONE2(is);

  delete in;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const std::string s(reinterpret_cast<const char*>(data), size);
  StdISStream is;
  is.str(s);

  fuzzImage(is);
  return 0;
}
