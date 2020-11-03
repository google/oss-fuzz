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
#include <vector>

#include <ImfArray.h>
#include <ImfInputPart.h>
#include <ImfMultiPartInputFile.h>
#include <ImfChannelList.h>
#include <ImfRgbaFile.h>
#include <ImfStdIO.h>

using namespace OPENEXR_IMF_INTERNAL_NAMESPACE;
using IMATH_NAMESPACE::Box2i;
using std::vector;
using std::max;
namespace {

static void readSingle(IStream& is) {
  try { 

    RgbaInputFile in(is);

    const Box2i &dw = in.dataWindow();

    int w = dw.max.x - dw.min.x + 1;
    int dx = dw.min.x;

    if (w > (1 << 24)) return;

    Array<Rgba> pixels(w);
    in.setFrameBuffer(&pixels[-dx], 1, 0);

    // read up to 10,000 scanlines from file
    int step = max( 1 , (dw.max.y - dw.min.y + 1) / 10000);
    for (int y = dw.min.y; y <= dw.max.y; y+=step) in.readPixels(y);
 
  } catch (...) {
  }
}

static void readMulti(IStream& is) {
  MultiPartInputFile *file;
  try {
    file = new MultiPartInputFile(is);
  } catch (...) {
    return;
  }

  for (int p = 0; p < file->parts(); p++) {
    InputPart *in;
    try {
      in = new InputPart(*file, p);
    } catch (...) {
      continue;
    }

    try {
      const Box2i &dw = in->header().dataWindow();

      int w = dw.max.x - dw.min.x + 1;
      int dx = dw.min.x;

      if (w > (1 << 24))
      {
	      throw std::logic_error("ignoring - very wide datawindow\n");
      }
 
      FrameBuffer i;
      //
      // read all channels present (later channels will overwrite earlier ones)
      vector<half> otherChannels(w);
      const ChannelList& channelList = in->header().channels();
      for (ChannelList::ConstIterator c = channelList.begin() ; c != channelList.end() ; ++c )
      {
	      i.insert(c.name(),Slice(HALF, (char*)&otherChannels[-dx] , sizeof(half) , 0 ));
      }     

      // always try to read RGBA even if not present in file
      Array<Rgba> pixels(w);
      i.insert("R", Slice(HALF, (char *)&(pixels[-dx].r), sizeof(Rgba), 0));
      i.insert("G", Slice(HALF, (char *)&(pixels[-dx].g), sizeof(Rgba), 0));
      i.insert("B", Slice(HALF, (char *)&(pixels[-dx].b), sizeof(Rgba), 0));
      i.insert("A", Slice(HALF, (char *)&(pixels[-dx].a), sizeof(Rgba), 0));




      in->setFrameBuffer(i);
      // read up to 10,000 scanlines from file
      int step = max( 1 , (dw.max.y - dw.min.y + 1) / 10000);
      for (int y = dw.min.y; y <= dw.max.y; y+=step) in->readPixels(y);
    } catch (...) {
    }

    delete in;
  }

  delete file;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const std::string s(reinterpret_cast<const char*>(data), size);
  {
    StdISStream is;
    is.str(s);
    readSingle(is);
  }
  {  
    StdISStream is;
    is.str(s);
    readMulti(is);
  }
  return 0;
}
