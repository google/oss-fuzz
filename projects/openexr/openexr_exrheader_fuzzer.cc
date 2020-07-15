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


//-----------------------------------------------------------------------------
//
//	Utility program to print an image file's header
//
//-----------------------------------------------------------------------------

#include "ImfNamespace.h"
#include <ImfMultiPartInputFile.h>
#include <ImfBoxAttribute.h>
#include <ImfChannelListAttribute.h>
#include <ImfChromaticitiesAttribute.h>
#include <ImfCompressionAttribute.h>
#include <ImfDoubleAttribute.h>
#include <ImfEnvmapAttribute.h>
#include <ImfFloatAttribute.h>
#include <ImfIntAttribute.h>
#include <ImfKeyCodeAttribute.h>
#include <ImfLineOrderAttribute.h>
#include <ImfMatrixAttribute.h>
#include <ImfPreviewImageAttribute.h>
#include <ImfRationalAttribute.h>
#include <ImfStringAttribute.h>
#include <ImfStringVectorAttribute.h>
#include <ImfTileDescriptionAttribute.h>
#include <ImfTimeCodeAttribute.h>
#include <ImfVecAttribute.h>
#include <ImfVersion.h>
#include <ImfHeader.h>
#include <ImfStdIO.h>

#include <iostream>
#include <iomanip>


using namespace OPENEXR_IMF_NAMESPACE;
using namespace std;


void
printCompression (Compression c)
{
    switch (c)
    {
        case NO_COMPRESSION:
            cout << "none";
            break;

        case RLE_COMPRESSION:
            cout << "run-length encoding";
            break;

        case ZIPS_COMPRESSION:
            cout << "zip, individual scanlines";
            break;

        case ZIP_COMPRESSION:
            cout << "zip, multi-scanline blocks";
            break;

        case PIZ_COMPRESSION:
            cout << "piz";
            break;

        case PXR24_COMPRESSION:
            cout << "pxr24";
            break;

        case B44_COMPRESSION:
            cout << "b44";
            break;

        case B44A_COMPRESSION:
            cout << "b44a";
            break;

        case DWAA_COMPRESSION:
            cout << "dwa, small scanline blocks";
            break;

        case DWAB_COMPRESSION:
            cout << "dwa, medium scanline blocks";
            break;

        default:
            cout << int (c);
            break;
    }
}


void
printLineOrder (LineOrder lo)
{
    switch (lo)
    {
        case INCREASING_Y:
            cout << "increasing y";
            break;

        case DECREASING_Y:
            cout << "decreasing y";
            break;

        case RANDOM_Y:
            cout << "random y";
            break;

        default:
            cout << int (lo);
            break;
    }
}


void
printPixelType (PixelType pt)
{
    switch (pt)
    {
        case UINT:
            cout << "32-bit unsigned integer";
            break;

        case HALF:
            cout << "16-bit floating-point";
            break;

        case FLOAT:
            cout << "32-bit floating-point";
            break;

        default:
            cout << "type " << int (pt);
            break;
    }
}


void
printLevelMode (LevelMode lm)
{
    switch (lm)
    {
        case ONE_LEVEL:
            cout << "single level";
            break;

        case MIPMAP_LEVELS:
            cout << "mip-map";
            break;

        case RIPMAP_LEVELS:
            cout << "rip-map";
            break;

        default:
            cout << "level mode " << int (lm);
            break;
    }
}


void
printLevelRoundingMode (LevelRoundingMode lm)
{
    switch (lm)
    {
        case ROUND_DOWN:
            cout << "down";
            break;

        case ROUND_UP:
            cout << "up";
            break;

        default:
            cout << "mode " << int (lm);
            break;
    }
}


void
printTimeCode (TimeCode tc)
{
    cout << "    "
    "time " <<
    setfill ('0') <<
#ifndef HAVE_COMPLETE_IOMANIP
    setw (2) << tc.hours() << ":" <<
    setw (2) << tc.minutes() << ":" <<
    setw (2) << tc.seconds() << ":" <<
    setw (2) << tc.frame() << "\n" <<
#else
    setw (2) << right << tc.hours() << ":" <<
    setw (2) << right << tc.minutes() << ":" <<
    setw (2) << right << tc.seconds() << ":" <<
    setw (2) << right << tc.frame() << "\n" <<
#endif
    setfill (' ') <<
    "    "
    "drop frame " << tc.dropFrame() << ", "
    "color frame " << tc.colorFrame() << ", "
    "field/phase " << tc.fieldPhase() << "\n"
    "    "
    "bgf0 " << tc.bgf0() << ", "
    "bgf1 " << tc.bgf1() << ", "
    "bgf2 " << tc.bgf2() << "\n"
    "    "
    "user data 0x" << hex << tc.userData() << dec;
}


void
printEnvmap (Envmap e)
{
    switch (e)
    {
        case ENVMAP_LATLONG:
            cout << "latitude-longitude map";
            break;

        case ENVMAP_CUBE:
            cout << "cube-face map";
            break;

        default:
            cout << "map type " << int (e);
            break;
    }
}


void
printChannelList (const ChannelList &cl)
{
    for (ChannelList::ConstIterator i = cl.begin(); i != cl.end(); ++i)
    {
        cout << "\n    " << i.name() << ", ";

        printPixelType (i.channel().type);

        cout << ", sampling " <<
        i.channel().xSampling << " " <<
        i.channel().ySampling;

        if (i.channel().pLinear)
            cout << ", plinear";
    }
}


void
printInfo (IStream &is)
{
    MultiPartInputFile in(is, 0);
    int parts = in.parts();

    getVersion(in.version());
    setbase(16);
    getFlags(in.version());
    setbase(10);

    for (int p = 0; p < parts ; ++p)
    {
        const Header & h = in.header (p);

        if (parts != 1)
        {
            in.partComplete(p);

        }

        for (Header::ConstIterator i = h.begin(); i != h.end(); ++i)
        {
            const Attribute *a = &i.attribute();
            i.name();
            a->typeName();

            if (const Box2iAttribute *ta =
                            dynamic_cast <const Box2iAttribute *> (a))
            {
                ta->value().min;
                ta->value().max;
            }

            else if (const Box2fAttribute *ta =
                            dynamic_cast <const Box2fAttribute *> (a))
            {
                ta->value().min;
                ta->value().max;
            }
            else if (const ChannelListAttribute *ta =
                            dynamic_cast <const ChannelListAttribute *> (a))
            {
                printChannelList(ta->value());
            }
            else if (const ChromaticitiesAttribute *ta =
                            dynamic_cast <const ChromaticitiesAttribute *> (a))
            {
                ta->value().red;
                ta->value().green;
                ta->value().blue;
                ta->value().white;
            }
            else if (const CompressionAttribute *ta =
                            dynamic_cast <const CompressionAttribute *> (a))
            {
                printCompression(ta->value());
            }
            else if (const DoubleAttribute *ta =
                            dynamic_cast <const DoubleAttribute *> (a))
            {
                ta->value();
            }
            else if (const EnvmapAttribute *ta =
                            dynamic_cast <const EnvmapAttribute *> (a))
            {
                printEnvmap(ta->value());
            }
            else if (const FloatAttribute *ta =
                            dynamic_cast <const FloatAttribute *> (a))
            {
                ta->value();
            }
            else if (const IntAttribute *ta =
                            dynamic_cast <const IntAttribute *> (a))
            {
                ta->value();
            }
            else if (const KeyCodeAttribute *ta =
                            dynamic_cast <const KeyCodeAttribute *> (a))
            {
                ta->value().filmMfcCode();
                ta->value().filmType();
                ta->value().prefix();
                ta->value().count();
                ta->value().perfOffset();
                ta->value().perfsPerFrame();
                ta->value().perfsPerCount();
            }
            else if (const LineOrderAttribute *ta =
                            dynamic_cast <const LineOrderAttribute *> (a))
            {
                printLineOrder(ta->value());
            }
            else if (const M33fAttribute *ta =
                            dynamic_cast <const M33fAttribute *> (a))
            {
                ta->value();
            }
            else if (const M44fAttribute *ta =
                            dynamic_cast <const M44fAttribute *> (a))
            {
                ta->value();
            }
            else if (const PreviewImageAttribute *ta =
                            dynamic_cast <const PreviewImageAttribute *> (a))
            {
                cout << ": " <<
                ta->value().width()  << " by " <<
                ta->value().height() << " pixels";
            }
            else if (const StringAttribute *ta =
                            dynamic_cast <const StringAttribute *> (a))
            {
                cout << ": \"" << ta->value() << "\"";
            }
            else if (const StringVectorAttribute * ta =
                            dynamic_cast<const StringVectorAttribute *>(a))
            {
                cout << ":";

                for (StringVector::const_iterator i = ta->value().begin();
                                i != ta->value().end();
                                ++i)
                {
                    cout << "\n    \"" << *i << "\"";
                }
            }
            else if (const RationalAttribute *ta =
                            dynamic_cast <const RationalAttribute *> (a))
            {
                cout << ": " << ta->value().n << "/" << ta->value().d <<
                " (" << double (ta->value()) << ")";
            }
            else if (const TileDescriptionAttribute *ta =
                            dynamic_cast <const TileDescriptionAttribute *> (a))
            {
                cout << ":\n    ";

                printLevelMode (ta->value().mode);

                cout << "\n    tile size " <<
                ta->value().xSize << " by " <<
                ta->value().ySize << " pixels";

                if (ta->value().mode != ONE_LEVEL)
                {
                    cout << "\n    level sizes rounded ";
                    printLevelRoundingMode (ta->value().roundingMode);
                }
            }
            else if (const TimeCodeAttribute *ta =
                            dynamic_cast <const TimeCodeAttribute *> (a))
            {
                cout << ":\n";
                printTimeCode (ta->value());
            }
            else if (const V2iAttribute *ta =
                            dynamic_cast <const V2iAttribute *> (a))
            {
                cout << ": " << ta->value();
            }
            else if (const V2fAttribute *ta =
                            dynamic_cast <const V2fAttribute *> (a))
            {
                cout << ": " << ta->value();
            }
            else if (const V3iAttribute *ta =
                            dynamic_cast <const V3iAttribute *> (a))
            {
                cout << ": " << ta->value();
            }
            else if (const V3fAttribute *ta =
                            dynamic_cast <const V3fAttribute *> (a))
            {
                cout << ": " << ta->value();
            }

        }
    }

}



extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  const std::string s(reinterpret_cast<const char*>(data), size);
  StdISStream is;
  is.str(s);

  printInfo(is);

  return 0;
}
