///////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2012, Industrial Light & Magic, a division of Lucas
// Digital Ltd. LLC
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// *       Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// *       Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
// *       Neither the name of Industrial Light & Magic nor the names of
// its contributors may be used to endorse or promote products derived
// from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
///////////////////////////////////////////////////////////////////////////


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

#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>

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
printInfo (const char fileName[])
{
    MultiPartInputFile in (fileName);
    int parts = in.parts();

    //
    // Check to see if any parts are incomplete
    //

    bool fileComplete = true;

    for (int i = 0; i < parts && fileComplete; ++i)
        if (!in.partComplete (i))
            fileComplete = false;

    //
    // Print file name and file format version
    //

    cout << "\nfile " << fileName <<
            (fileComplete? "": " (incomplete)") <<
            ":\n\n";

    cout << "file format version: " <<
            getVersion (in.version()) << ", "
            "flags 0x" <<
            setbase (16) << getFlags (in.version()) << setbase (10) << "\n";

    //
    // Print the header of every part in the file
    //

    for (int p = 0; p < parts ; ++p)
    {
        const Header & h = in.header (p);

        if (parts != 1)
        {
            cout  << "\n\n part " << p <<
            (in.partComplete (p)? "": " (incomplete)") <<
            ":\n";

        }

        for (Header::ConstIterator i = h.begin(); i != h.end(); ++i)
        {
            const Attribute *a = &i.attribute();
            cout << i.name() << " (type " << a->typeName() << ")";

            if (const Box2iAttribute *ta =
                            dynamic_cast <const Box2iAttribute *> (a))
            {
                cout << ": " << ta->value().min << " - " << ta->value().max;
            }

            else if (const Box2fAttribute *ta =
                            dynamic_cast <const Box2fAttribute *> (a))
            {
                cout << ": " << ta->value().min << " - " << ta->value().max;
            }
            else if (const ChannelListAttribute *ta =
                            dynamic_cast <const ChannelListAttribute *> (a))
            {
                cout << ":";
                printChannelList (ta->value());
            }
            else if (const ChromaticitiesAttribute *ta =
                            dynamic_cast <const ChromaticitiesAttribute *> (a))
            {
                cout << ":\n"
                "    red   " << ta->value().red << "\n"
                "    green " << ta->value().green << "\n"
                "    blue  " << ta->value().blue << "\n"
                "    white " << ta->value().white;
            }
            else if (const CompressionAttribute *ta =
                            dynamic_cast <const CompressionAttribute *> (a))
            {
                cout << ": ";
                printCompression (ta->value());
            }
            else if (const DoubleAttribute *ta =
                            dynamic_cast <const DoubleAttribute *> (a))
            {
                cout << ": " << ta->value();
            }
            else if (const EnvmapAttribute *ta =
                            dynamic_cast <const EnvmapAttribute *> (a))
            {
                cout << ": ";
                printEnvmap (ta->value());
            }
            else if (const FloatAttribute *ta =
                            dynamic_cast <const FloatAttribute *> (a))
            {
                cout << ": " << ta->value();
            }
            else if (const IntAttribute *ta =
                            dynamic_cast <const IntAttribute *> (a))
            {
                cout << ": " << ta->value();
            }
            else if (const KeyCodeAttribute *ta =
                            dynamic_cast <const KeyCodeAttribute *> (a))
            {
                cout << ":\n"
                "    film manufacturer code " <<
                ta->value().filmMfcCode() << "\n"
                "    film type code " <<
                ta->value().filmType() << "\n"
                "    prefix " <<
                ta->value().prefix() << "\n"
                "    count " <<
                ta->value().count() << "\n"
                "    perf offset " <<
                ta->value().perfOffset() << "\n"
                "    perfs per frame " <<
                ta->value().perfsPerFrame() << "\n"
                "    perfs per count " <<
                ta->value().perfsPerCount();
            }
            else if (const LineOrderAttribute *ta =
                            dynamic_cast <const LineOrderAttribute *> (a))
            {
                cout << ": ";
                printLineOrder (ta->value());
            }
            else if (const M33fAttribute *ta =
                            dynamic_cast <const M33fAttribute *> (a))
            {
                cout << ":\n"
                "   (" <<
                ta->value()[0][0] << " " <<
                ta->value()[0][1] << " " <<
                ta->value()[0][2] << "\n    " <<
                ta->value()[1][0] << " " <<
                ta->value()[1][1] << " " <<
                ta->value()[1][2] << "\n    " <<
                ta->value()[2][0] << " " <<
                ta->value()[2][1] << " " <<
                ta->value()[2][2] << ")";
            }
            else if (const M44fAttribute *ta =
                            dynamic_cast <const M44fAttribute *> (a))
            {
                cout << ":\n"
                "   (" <<
                ta->value()[0][0] << " " <<
                ta->value()[0][1] << " " <<
                ta->value()[0][2] << " " <<
                ta->value()[0][3] << "\n    " <<
                ta->value()[1][0] << " " <<
                ta->value()[1][1] << " " <<
                ta->value()[1][2] << " " <<
                ta->value()[1][3] << "\n    " <<
                ta->value()[2][0] << " " <<
                ta->value()[2][1] << " " <<
                ta->value()[2][2] << " " <<
                ta->value()[2][3] << "\n    " <<
                ta->value()[3][0] << " " <<
                ta->value()[3][1] << " " <<
                ta->value()[3][2] << " " <<
                ta->value()[3][3] << ")";
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

            cout << '\n';
        }
    }

    cout << endl;
}


void
usageMessage (const char argv0[])
{
    std::cerr << "usage: " << argv0 << " imagefile [imagefile ...]\n";
}

static char *buf_to_file(const char *buf, size_t size) {
  char *name = strdup("/dev/shm/fuzz-XXXXXX");
  int fd = mkstemp(name);
  if (fd < 0) {
    perror("open");
    exit(1);
  }
  size_t pos = 0;
  while (pos < size) {
    int nbytes = write(fd, &buf[pos], size - pos);
    if (nbytes <= 0) {
      perror("write");
      exit(1);
    }
    pos += nbytes;
  }
  if (close(fd) != 0) {
    perror("close");
    exit(1);
  }
  return name;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  char *file = buf_to_file((const char *)data, size);
  if (file == NULL) {
    exit(EXIT_FAILURE);
  }

  try {
    printInfo(file);
  }
  catch (const std::exception &e) {
    ;
  }

  unlink(file);
  free(file);

  return 0;
}
