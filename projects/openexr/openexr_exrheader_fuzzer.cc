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

#include "ImfNamespace.h"
#include <ImfBoxAttribute.h>
#include <ImfChannelListAttribute.h>
#include <ImfChromaticitiesAttribute.h>
#include <ImfCompressionAttribute.h>
#include <ImfDoubleAttribute.h>
#include <ImfEnvmapAttribute.h>
#include <ImfFloatAttribute.h>
#include <ImfHeader.h>
#include <ImfIntAttribute.h>
#include <ImfKeyCodeAttribute.h>
#include <ImfLineOrderAttribute.h>
#include <ImfMatrixAttribute.h>
#include <ImfMultiPartInputFile.h>
#include <ImfPreviewImageAttribute.h>
#include <ImfRationalAttribute.h>
#include <ImfStdIO.h>
#include <ImfStringAttribute.h>
#include <ImfStringVectorAttribute.h>
#include <ImfTileDescriptionAttribute.h>
#include <ImfTimeCodeAttribute.h>
#include <ImfVecAttribute.h>
#include <ImfVersion.h>

#include <iomanip>
#include <iostream>

using namespace OPENEXR_IMF_NAMESPACE;
using namespace std;

void dumpTimeCode(TimeCode tc) {
  tc.hours();
  tc.minutes();
  tc.seconds();
  tc.frame();

  tc.dropFrame();
  tc.colorFrame();
  tc.fieldPhase();
  tc.bgf0();
  tc.bgf1();
  tc.bgf2();
  tc.userData();
}

void dumpChannelList(const ChannelList &cl) {
  for (ChannelList::ConstIterator i = cl.begin(); i != cl.end(); ++i) {
    i.name();
    i.channel();
  }
}

void dumpInfo(IStream &is) {
  MultiPartInputFile in(is, 0);
  int parts = in.parts();

  getVersion(in.version());
  getFlags(in.version());

  for (int p = 0; p < parts; ++p) {
    const Header &h = in.header(p);

    if (parts != 1) {
      in.partComplete(p);
    }

    for (Header::ConstIterator i = h.begin(); i != h.end(); ++i) {
      const Attribute *a = &i.attribute();
      i.name();
      a->typeName();

      if (const Box2iAttribute *ta = dynamic_cast<const Box2iAttribute *>(a)) {
        ta->value();
      }

      else if (const Box2fAttribute *ta =
                   dynamic_cast<const Box2fAttribute *>(a)) {
        ta->value();
      } else if (const ChannelListAttribute *ta =
                     dynamic_cast<const ChannelListAttribute *>(a)) {
        dumpChannelList(ta->value());
      } else if (const ChromaticitiesAttribute *ta =
                     dynamic_cast<const ChromaticitiesAttribute *>(a)) {
        ta->value();
      } else if (const DoubleAttribute *ta =
                     dynamic_cast<const DoubleAttribute *>(a)) {
        ta->value();
      } else if (const FloatAttribute *ta =
                     dynamic_cast<const FloatAttribute *>(a)) {
        ta->value();
      } else if (const IntAttribute *ta =
                     dynamic_cast<const IntAttribute *>(a)) {
        ta->value();
      } else if (const KeyCodeAttribute *ta =
                     dynamic_cast<const KeyCodeAttribute *>(a)) {
        ta->value().filmMfcCode();
        ta->value().filmType();
        ta->value().prefix();
        ta->value().count();
        ta->value().perfOffset();
        ta->value().perfsPerFrame();
        ta->value().perfsPerCount();
      } else if (const M33fAttribute *ta =
                     dynamic_cast<const M33fAttribute *>(a)) {
        ta->value();
      } else if (const M44fAttribute *ta =
                     dynamic_cast<const M44fAttribute *>(a)) {
        ta->value();
      } else if (const PreviewImageAttribute *ta =
                     dynamic_cast<const PreviewImageAttribute *>(a)) {
        ta->value().width();
        ta->value().height();
      } else if (const StringAttribute *ta =
                     dynamic_cast<const StringAttribute *>(a)) {
        ta->value();
      } else if (const StringVectorAttribute *ta =
                     dynamic_cast<const StringVectorAttribute *>(a)) {
        for (StringVector::const_iterator i = ta->value().begin();
             i != ta->value().end(); ++i) {
          *i;
        }
      } else if (const RationalAttribute *ta =
                     dynamic_cast<const RationalAttribute *>(a)) {
        ta->value();
      } else if (const TileDescriptionAttribute *ta =
                     dynamic_cast<const TileDescriptionAttribute *>(a)) {
        ta->value();

      } else if (const TimeCodeAttribute *ta =
                     dynamic_cast<const TimeCodeAttribute *>(a)) {
        dumpTimeCode(ta->value());
      } else if (const V2iAttribute *ta =
                     dynamic_cast<const V2iAttribute *>(a)) {
        ta->value();
      } else if (const V2fAttribute *ta =
                     dynamic_cast<const V2fAttribute *>(a)) {
        ta->value();
      } else if (const V3iAttribute *ta =
                     dynamic_cast<const V3iAttribute *>(a)) {
        ta->value();
      } else if (const V3fAttribute *ta =
                     dynamic_cast<const V3fAttribute *>(a)) {
        ta->value();
      }
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  const std::string s(reinterpret_cast<const char *>(data), size);
  StdISStream is;
  is.str(s);

  try {
    dumpInfo(is);
  } catch (...) {
    ;
  }

  return 0;
}
