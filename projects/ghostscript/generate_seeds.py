#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Structured PostScript/PCL-XL seed generation for the ghostscript OSS-Fuzz
device fuzzers.

Every `gs_device_*` / `gstoraster_*` fuzzer feeds the input to Ghostscript on
stdin and renders it to a device (see gs_fuzzlib.h: the args end in `-_`).  The
shipped seed corpus is the stock `examples/*.ps,*.pdf`, which lean almost
entirely on DeviceRGB/DeviceGray and basic operators.

This script emits small, valid PostScript programs that each drive one of
those clusters, plus a couple of PCL-XL / PCL seeds for the dedicated
gs_pxl / gs_pcl fuzzers.  Pure Python stdlib, no Ghostscript needed at
generation time.

Usage:  python3 generate_seeds.py <output_dir>
"""

import os
import sys
import struct
import zlib
import io
import zipfile


def w(d, name, data):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("latin-1"))


PS_HEADER = "%!PS-Adobe-3.0\n"


# --------------------------------------------------------------------------
# PostScript colour spaces  ->  zcolor.c
# --------------------------------------------------------------------------
def ps_colorspaces():
    return PS_HEADER + r"""%%Title: colour space torture
%%EndComments
% --- CIEBasedABC
[ /CIEBasedABC <<
   /DecodeLMN [ {dup mul} bind {dup mul} bind {dup mul} bind ]
   /MatrixLMN [0.41 0.21 0.02 0.36 0.72 0.12 0.18 0.07 0.95]
   /WhitePoint [0.9505 1.0 1.089]
   /BlackPoint [0 0 0]
   /RangeABC [0 1 0 1 0 1]
>> ] setcolorspace
0.3 0.5 0.7 setcolor 20 20 80 80 rectfill
% --- CIEBasedA
[ /CIEBasedA << /DecodeA {dup mul} bind /MatrixA [1 1 1]
   /WhitePoint [0.9505 1.0 1.089] >> ] setcolorspace
0.6 setcolor 120 20 60 60 rectfill
% --- CIEBasedDEF
[ /CIEBasedDEF << /DecodeDEF [ {} bind {} bind {} bind ]
   /RangeDEF [0 1 0 1 0 1] /RangeHIJ [0 1 0 1 0 1]
   /Table [2 2 2 (\000\000\000\377\377\377\200\200\200\100\100\100)]
   /DecodeABC [ {} bind {} bind {} bind ]
   /MatrixABC [1 0 0 0 1 0 0 0 1]
   /WhitePoint [0.9505 1.0 1.089] >> ] setcolorspace
0.2 0.4 0.6 setcolor 20 120 60 60 rectfill
% --- Separation
[ /Separation /Spot /DeviceCMYK { dup 0 0 0 4 1 roll } bind ] setcolorspace
0.8 setcolor 120 120 60 60 rectfill
% --- DeviceN
[ /DeviceN [/C1 /C2] /DeviceRGB { 0.5 mul exch 0.5 mul exch 0 } bind ]
  setcolorspace
0.4 0.7 setcolor 200 20 60 60 rectfill
% --- Indexed over DeviceRGB
[ /Indexed /DeviceRGB 3 <ff0000 00ff00 0000ff ffffff> ] setcolorspace
2 setcolor 200 120 60 60 rectfill
% --- legacy operators
0.5 setgray 0 0 10 10 rectfill
0.1 0.2 0.3 setrgbcolor 10 0 10 10 rectfill
0.1 0.2 0.3 0.4 setcmykcolor 20 0 10 10 rectfill
0.5 0.6 0.7 sethsbcolor 30 0 10 10 rectfill
currentcolor pop currentcolorspace pop currentgray pop
showpage
"""


# --------------------------------------------------------------------------
# More colour spaces + colour-rendering dictionary  ->  gscie/gscrd/gsciemap
# --------------------------------------------------------------------------
def ps_color_rendering():
    return PS_HEADER + r"""%%Title: colour rendering + extra colour spaces
% --- CIEBasedDEFG (4-input CIE, e.g. CMYK device link)
[ /CIEBasedDEFG <<
   /DecodeDEFG [ {} bind {} bind {} bind {} bind ]
   /RangeDEFG [0 1 0 1 0 1 0 1] /RangeHIJK [0 1 0 1 0 1 0 1]
   /Table [2 2 2 2 (\000\000\000\377\377\377\200\200\200\100\100\100
                    \040\040\040\140\140\140\240\240\240\300\300\300
                    \020\020\020\060\060\060\120\120\120\160\160\160
                    \220\220\220\260\260\260\320\320\320\360\360\360)]
   /DecodeABC [ {} bind {} bind {} bind ]
   /MatrixABC [1 0 0 0 1 0 0 0 1]
   /WhitePoint [0.9505 1.0 1.089] >> ] setcolorspace
0.2 0.4 0.6 0.1 setcolor 20 20 60 60 rectfill
% --- a colour-rendering dictionary (CRD, type 1)
<< /ColorRenderingType 1
   /WhitePoint [0.9505 1.0 1.089] /BlackPoint [0 0 0]
   /MatrixPQR [1 0 0 0 1 0 0 0 1]
   /RangePQR [-0.5 2 -0.5 2 -0.5 2]
   /TransformPQR [ {3 -1 roll pop pop} bind {3 -1 roll pop pop} bind
                   {3 -1 roll pop pop} bind ]
   /MatrixLMN [1 0 0 0 1 0 0 0 1]
   /EncodeLMN [ {} bind {} bind {} bind ]
   /RangeLMN [0 1 0 1 0 1]
   /MatrixABC [1 0 0 0 1 0 0 0 1]
   /EncodeABC [ {} bind {} bind {} bind ]
   /RangeABC [0 1 0 1 0 1]
   /RenderTable null >> setcolorrendering
% --- black generation + undercolour removal (CMYK)
{ dup dup dup pop pop pop } bind setblackgeneration
{ 0.5 mul } bind setundercolorremoval
0.1 0.2 0.3 0.4 setcmykcolor 90 20 60 60 rectfill
% --- DeviceN with an attributes dict
[ /DeviceN [/Cyan /Magenta /Spot] /DeviceCMYK
  { 0 4 1 roll 0 } bind
  << /Subtype /NChannel /Colorants << /Spot
       [ /Separation /Spot /DeviceCMYK {0 0 0 4 1 roll} bind ] >> >> ]
  setcolorspace
0.3 0.4 0.5 setcolor 20 90 60 60 rectfill
% --- Separation /All
[ /Separation /All /DeviceCMYK { dup dup dup } bind ] setcolorspace
0.7 setcolor 90 90 60 60 rectfill
showpage
"""


# --------------------------------------------------------------------------
# Smooth shading (shfill, all ShadingType values)  ->  gxshade*.c
# --------------------------------------------------------------------------
def ps_shadings():
    return PS_HEADER + r"""%%Title: shadings
% Type 1 function-based shading
<< /ShadingType 1 /ColorSpace /DeviceRGB
   /Function << /FunctionType 2 /Domain [0 1] /C0 [1 0 0] /C1 [0 0 1] /N 1 >>
   /Domain [0 1 0 1] >> shfill
% Type 2 axial
gsave 0 0 100 100 rectclip
<< /ShadingType 2 /ColorSpace /DeviceRGB /Coords [0 0 200 200]
   /Extend [true true]
   /Function << /FunctionType 2 /Domain [0 1] /C0 [1 1 0] /C1 [0 1 1] /N 1 >>
>> shfill grestore
% Type 3 radial
gsave 100 0 100 100 rectclip
<< /ShadingType 3 /ColorSpace /DeviceRGB /Coords [150 50 0 150 50 60]
   /Extend [true true]
   /Function << /FunctionType 2 /Domain [0 1] /C0 [1 0 1] /C1 [0 0 0] /N 1 >>
>> shfill grestore
% Type 4 free-form Gouraud (inline data via DataSource string)
<< /ShadingType 4 /ColorSpace /DeviceRGB /BitsPerCoordinate 8
   /BitsPerComponent 8 /BitsPerFlag 8 /Decode [0 255 0 255 0 1 0 1 0 1]
   /DataSource <00 00 00 ff 00 00  00 ff 00 00 ff 00  00 80 80 00 00 ff>
>> shfill
% Type 5 lattice Gouraud
<< /ShadingType 5 /ColorSpace /DeviceRGB /BitsPerCoordinate 8
   /BitsPerComponent 8 /VerticesPerRow 2 /Decode [0 255 0 255 0 1 0 1 0 1]
   /DataSource <00 00 ff0000 ff 00 00ff00 00 ff 0000ff ff ff ffffff>
>> shfill
% Type 6 Coons patch
<< /ShadingType 6 /ColorSpace /DeviceRGB /BitsPerCoordinate 8
   /BitsPerComponent 8 /BitsPerFlag 8
   /Decode [0 255 0 255 0 1 0 1 0 1]
   /DataSource <00
     00 00 20 00 40 00 60 00 60 20 60 40 60 60 40 60 20 60 00 60 00 40 00 20
     ff0000 00ff00 0000ff ffff00>
>> shfill
showpage
"""


# --------------------------------------------------------------------------
# Transparency: groups, blend modes, soft masks, alpha  ->  gdevp14 / gxblend
# --------------------------------------------------------------------------
def ps_transparency():
    modes = ["Normal", "Multiply", "Screen", "Overlay", "Darken", "Lighten",
             "ColorDodge", "ColorBurn", "HardLight", "SoftLight", "Difference",
             "Exclusion", "Hue", "Saturation", "Color", "Luminosity"]
    body = [PS_HEADER, "%%Title: transparency\n"]
    body.append(".setblendmode where { pop } if\n")
    x = 10
    for i, m in enumerate(modes):
        body.append(
            "gsave /%s .setblendmode 0.7 .setfillconstantalpha\n"
            "1 0 0 setrgbcolor %d 20 40 40 rectfill\n"
            "0 0 1 setrgbcolor %d 40 40 40 rectfill grestore\n"
            % (m, x, x))
        x += 12
    # transparency group
    body.append(
        "<< /Subtype /Group /CS /DeviceRGB /I true /K false >>\n"
        "1 .begintransparencygroup\n"
        "0 1 0 setrgbcolor 60 100 80 80 rectfill\n"
        ".endtransparencygroup\n")
    body.append("showpage\n")
    return "".join(body)


# --------------------------------------------------------------------------
# Images: image / colorimage / imagemask, indexed, multiple bit depths
# --------------------------------------------------------------------------
def ps_images():
    return PS_HEADER + r"""%%Title: images
% 8-bit grayscale image
gsave 0 0 translate 100 100 scale
8 8 8 [8 0 0 8 0 0]
{ <0011223344556677> } image
grestore
% RGB colorimage
gsave 100 0 translate 100 100 scale
4 4 8 [4 0 0 4 0 0]
{ <ff0000 00ff00 0000ff ffffff ff00ff 00ffff ffff00 000000
   808080 404040 c0c0c0 200020 002000 000020 a0a000 00a0a0> }
false 3 colorimage
grestore
% imagemask
gsave 0 100 translate 60 60 scale
0 0 0 setrgbcolor
8 8 false [8 0 0 8 0 0] { <8142241818244281> } imagemask
grestore
% indexed image via image dict + Interpolate (gxiscale)
gsave 100 100 translate 80 80 scale
[ /Indexed /DeviceRGB 3 <ff0000 00ff00 0000ff ffffff> ] setcolorspace
<< /ImageType 1 /Width 2 /Height 2 /BitsPerComponent 2
   /Decode [0 3] /Interpolate true
   /ImageMatrix [2 0 0 2 0 0]
   /DataSource <00 40 80 c0> >> image
grestore
showpage
"""


# --------------------------------------------------------------------------
# Halftones / transfer functions  ->  gshtscr / gxht
# --------------------------------------------------------------------------
def ps_halftones():
    return PS_HEADER + r"""%%Title: halftones
% Type 1 spot halftone
<< /HalftoneType 1 /Frequency 60 /Angle 45
   /SpotFunction { 180 mul cos exch 180 mul cos add 2 div } bind >>
sethalftone
% Type 3 threshold halftone
<< /HalftoneType 3 /Width 2 /Height 2 /Thresholds <00 55 aa ff> >>
sethalftone
% legacy setscreen + transfer
60 30 { 180 mul cos exch 180 mul cos add 2 div } bind setscreen
{ 1 exch sub } bind settransfer
{1 exch sub}{1 exch sub}{1 exch sub}{1 exch sub} setcolortransfer
0.5 setgray 0 0 100 100 rectfill
showpage
"""


# --------------------------------------------------------------------------
# DSC-rich document  ->  dscparse.c (used by ps2write / eps handling)
# --------------------------------------------------------------------------
def ps_dsc():
    return r"""%!PS-Adobe-3.0
%%Title: DSC torture
%%Creator: seedgen
%%CreationDate: 2026
%%BoundingBox: 0 0 200 200
%%HiResBoundingBox: 0.0 0.0 200.0 200.0
%%DocumentMedia: Default 200 200 80 white ()
%%DocumentData: Clean7Bit
%%LanguageLevel: 3
%%Orientation: Portrait
%%PageOrder: Ascend
%%Pages: 2
%%DocumentNeededResources: font Helvetica
%%DocumentSuppliedResources: procset Seed 1.0 0
%%EndComments
%%BeginProlog
%%BeginResource: procset Seed 1.0 0
/box { newpath 0 0 moveto 50 0 rlineto 0 50 rlineto -50 0 rlineto closepath } def
%%EndResource
%%EndProlog
%%BeginSetup
/Helvetica findfont 12 scalefont setfont
%%EndSetup
%%Page: one 1
%%BeginPageSetup
gsave
%%EndPageSetup
20 20 moveto box 0.5 setgray fill
20 100 moveto (DSC page one) show
grestore
showpage
%%Page: two 2
gsave
0.2 0.4 0.6 setrgbcolor 30 30 box fill
grestore
showpage
%%Trailer
%%EOF
"""


# --------------------------------------------------------------------------
# Fonts / text: Type 3 font, show variants, clipping
# --------------------------------------------------------------------------
def ps_fonts_text():
    return PS_HEADER + r"""%%Title: fonts and text
% Type 3 user-defined font
8 dict dup begin
  /FontType 3 def
  /FontMatrix [0.01 0 0 0.01 0 0] def
  /FontBBox [0 0 100 100] def
  /Encoding 256 array def
  Encoding 65 /A put
  /CharProcs 2 dict def
  CharProcs begin
    /A { 0 0 moveto 100 0 lineto 50 100 lineto closepath fill } bind def
    /.notdef { } bind def
  end
  /BuildGlyph { exch /CharProcs get exch 2 copy known not { pop /.notdef } if
                get exec } bind def
end
/SeedType3 exch definefont pop
/SeedType3 findfont 24 scalefont setfont
20 150 moveto (AAA) show
% standard font show variants
/Helvetica findfont 14 scalefont setfont
20 120 moveto (kerned) 0 0 (k) 0 0 ashow
20 100 moveto (widthshow) 1 0 32 widthshow
20 80 moveto [3 2] 0 setdash 0 0 1 setrgbcolor (dashed clip) show
% text as clip path
20 40 moveto /Helvetica findfont 30 scalefont setfont
(CLIP) true charpath clip
0 0 200 200 8 { pop 0 1 0 setrgbcolor 0 0 200 200 rectfill } repeat
showpage
"""


# --------------------------------------------------------------------------
# PCL-XL (PCL6) seed for gs_pxl_fuzzer
# --------------------------------------------------------------------------
def pclxl_seed():
    # PCL-XL big-endian protocol; a minimal valid stream:
    #   ) HP-PCL XL;2;0  header, BeginSession, OpenDataSource, BeginPage,
    #   SetColorSpace, a rectangle, EndPage, CloseDataSource, EndSession.
    out = bytearray()
    out += b") HP-PCL XL;2;0;Comment Seed\n"

    def ubyte(tag, v):
        return bytes([0xc0, v, tag])         # ubyte attr + attr-id

    def uint16(v):
        return bytes([0xc1]) + struct.pack(">H", v)

    def attr(idbyte):
        return bytes([0xf8, idbyte])         # attribute id tag

    # BeginSession: UnitsPerMeasure (uint16 xy), MeasureName (ubyte), ...
    out += bytes([0xc0, 0x00, 0xf8, 0x29])             # ProtocolClass? skip
    # Simpler: use documented operator bytes.
    # UnitsPerMeasure = [600 600]
    out += bytes([0xc1]) + struct.pack(">H", 600)
    out += bytes([0xc1]) + struct.pack(">H", 600)
    out += attr(0x88)                                  # UnitsPerMeasure
    out += bytes([0xc0, 0x00]) + attr(0x86)            # MeasureName=eInch
    out += bytes([0x41])                               # BeginSession
    out += bytes([0xc0, 0x01]) + attr(0x1c)            # SourceType
    out += bytes([0x42])                               # OpenDataSource
    out += bytes([0xc0, 0x02]) + attr(0x28)            # ColorSpace=eRGB
    out += bytes([0x6a])                               # SetColorSpace
    out += bytes([0xc0, 0x00]) + attr(0x29)            # Orientation
    out += bytes([0xc0, 0x02]) + attr(0x25)            # MediaSize=Letter
    out += bytes([0x43])                               # BeginPage
    # rectangle
    out += uint16(100) + attr(0x53)                    # not strictly valid
    out += bytes([0x44])                               # EndPage
    out += bytes([0x45])                               # CloseDataSource-ish
    out += bytes([0x46])                               # EndSession-ish
    return bytes(out)


# --------------------------------------------------------------------------
# PCL5 seed for gs_pcl_fuzzer
# --------------------------------------------------------------------------
def pcl5_seed():
    ESC = b"\x1b"
    out = bytearray()
    out += ESC + b"E"                       # printer reset
    out += ESC + b"&l1O"                    # orientation landscape
    out += ESC + b"&l2A"                    # page size letter
    out += ESC + b"(s1p12v0s0b4099T"        # font selection
    out += ESC + b"&a100h200V"              # cursor position
    out += b"Hello PCL5 seed\r\n"
    out += ESC + b"*c100a100b0P"            # fill rectangle
    out += ESC + b"*v1S"                    # set source
    # raster graphics
    out += ESC + b"*t100R"                  # raster resolution
    out += ESC + b"*r0A"                    # start raster
    out += ESC + b"*b4W" + b"\xff\x00\xff\x00"
    out += ESC + b"*rB"                     # end raster
    out += ESC + b"E"
    return bytes(out)


# --------------------------------------------------------------------------
# Complex paths / stroking / clipping  ->  gxfill.c, gxstroke.c, gxclip.c
# --------------------------------------------------------------------------
def ps_paths():
    return PS_HEADER + r"""%%Title: paths, stroking, clipping
% self-intersecting star, even-odd vs nonzero winding
/star { newpath 100 190 moveto 140 20 lineto 10 130 lineto 190 130 lineto
        60 20 lineto closepath } def
gsave star 1 0 0 setrgbcolor eofill grestore
gsave 0 200 translate star 0 0 1 setrgbcolor fill grestore
% many overlapping subpaths in one fill (winding accumulation)
newpath 0 1 20 { dup 10 mul dup 5 add exch 80 add 40 0 360 arc } for
0 0.6 0 setrgbcolor fill
% bezier curves
newpath 10 250 moveto 60 380 140 380 190 250 curveto
30 300 lineto 100 350 170 300 closepath 0.4 0.2 0.8 setrgbcolor fill
% stroking: caps, joins, miter, dashes, zero-length dots
2 setlinecap 1 setlinejoin 8 setmiterlimit
[6 3 2 3] 1 setdash 5 setlinewidth
newpath 220 20 moveto 380 20 lineto 300 120 lineto stroke
0 setlinecap 0 setlinejoin [] 0 setdash
1 setlinewidth newpath 220 150 moveto 380 150 lineto stroke
% zero-length stroke with round caps -> dots
1 setlinecap 10 setlinewidth
newpath 240 200 moveto 240 200 lineto stroke
% complex clip then fill a big region
gsave newpath 220 220 moveto 380 220 lineto 300 380 lineto closepath
clip 0 1 1 setrgbcolor 200 200 200 200 rectfill grestore
% rectclip + eoclip
gsave 50 400 100 80 rectclip 0.9 0.5 0.1 setrgbcolor
0 0 600 600 rectfill grestore
showpage
"""


# --------------------------------------------------------------------------
# Image scaling / interpolation / mask types  ->  gxiscale.c, gxdownscale.c
# --------------------------------------------------------------------------
def ps_image_scaling():
    return PS_HEADER + r"""%%Title: image scaling, interpolation, mask types
% interpolated upscale of a tiny image (drives gxiscale)
gsave 0 0 translate 180 180 scale
<< /ImageType 1 /Width 4 /Height 4 /BitsPerComponent 8 /Interpolate true
   /Decode [0 1 0 1 0 1] /ImageMatrix [4 0 0 4 0 0]
   /DataSource <ff000000ff000000ff00ffffff
                808080404040c0c0c0202020a0a0a0
                100010300030500050700070> >> image
grestore
% large downscale (small dest from big source) -> downscaling path
gsave 200 200 translate 30 30 scale
<< /ImageType 1 /Width 32 /Height 32 /BitsPerComponent 1 /Interpolate false
   /Decode [0 1] /ImageMatrix [32 0 0 32 0 0]
   /DataSource { <aaaaaaaa55555555> } >> image
grestore
% 16-bit grayscale image
gsave 0 200 translate 90 90 scale
<< /ImageType 1 /Width 2 /Height 2 /BitsPerComponent 16
   /Decode [0 1] /ImageMatrix [2 0 0 2 0 0]
   /DataSource <0000ffffffff0000> >> image
grestore
% ImageType 4 colour-key masked image
gsave 200 0 translate 90 90 scale
<< /ImageType 4 /Width 2 /Height 2 /BitsPerComponent 8 /MaskColor [255]
   /Decode [0 1] /ImageMatrix [2 0 0 2 0 0]
   /DataSource <00ff80ff> >> image
grestore
% ImageType 3 explicit-mask image
gsave 100 100 translate 80 80 scale
<< /ImageType 3 /InterleaveType 3
   /DataDict << /ImageType 1 /Width 2 /Height 2 /BitsPerComponent 8
     /Decode [0 1 0 1 0 1] /ImageMatrix [2 0 0 2 0 0]
     /DataSource <ff0000 00ff00 0000ff ffffff> >>
   /MaskDict << /ImageType 1 /Width 2 /Height 2 /BitsPerComponent 1
     /Decode [0 1] /ImageMatrix [2 0 0 2 0 0]
     /DataSource <40> >> >> image
grestore
showpage
"""


# --------------------------------------------------------------------------
# setpagedevice parameter dictionaries  ->  gsparaml.c, gsdparam.c
# --------------------------------------------------------------------------
def ps_pagedevice_params():
    return PS_HEADER + r"""%%Title: page device parameters
<< /PageSize [200 200] /Margins [0 0] /HWResolution [72 72]
   /ImagingBBox null /Orientation 0 /Policies << /PageSize 3 /Policy 0 >>
   /BeginPage { pop } /EndPage { pop pop true }
   /Install {} /UseCIEColor true >> setpagedevice
currentpagedevice /PageSize get aload pop pop pop
% nested dict + array param types
<< /PageSize [200 200]
   /InputAttributes << 0 << /PageSize [200 200] >> /Priority [0] >>
   /OutputAttributes << 0 << >> >>
   /Deferred true /DeviceRenderingInfo << /MaxSeparations 4 >> >>
setpagedevice
% gsave/grestore of gstate + clippath/initclip
gsave clippath pathbbox 4 array astore pop grestore initclip
0.5 setgray 10 10 180 180 rectfill
showpage
"""


# --------------------------------------------------------------------------
# XPS (OpenXPS) packages  ->  xps/*.c + expat XML parser + (image) pngread
# The gs_xps_fuzzer feeds the file to gpdl, which detects the OPC ZIP and runs
# the XPS interpreter. The stock corpus has only a couple of sample .xps files.
# --------------------------------------------------------------------------
XPS_NS = "http://schemas.microsoft.com/xps/2005/06"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def _png_rgb(w, h):
    def chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d +
                struct.pack(">I", zlib.crc32(t + d) & 0xffffffff))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)   # 8-bit RGB
    raw = b""
    for y in range(h):
        raw += b"\x00" + bytes([(x * 32 + y * 16) & 255
                                for x in range(w) for _ in range(3)])
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def _tiff_rgb(w, h):
    """A minimal baseline (uncompressed RGB, single strip) TIFF, little-endian.
    Reachable as an XPS ImageBrush source -> xps/xpstiff.c + libtiff read."""
    tags = []                       # (tag, type, count, value-or-inline-bytes)
    strip = bytes([(x * 20 + y * 10 + c * 5) & 255
                   for y in range(h) for x in range(w) for c in range(3)])
    # out-of-line areas: BitsPerSample (3 shorts), strip data
    hdr_len = 8
    ifd_count = 11
    ifd_len = 2 + ifd_count * 12 + 4
    bps_off = hdr_len + ifd_len
    strip_off = bps_off + 6
    bps = struct.pack("<HHH", 8, 8, 8)

    def e(tag, typ, count, val):
        return struct.pack("<HHI", tag, typ, count) + val
    ifd = struct.pack("<H", ifd_count)
    ifd += e(256, 3, 1, struct.pack("<HH", w, 0))      # ImageWidth
    ifd += e(257, 3, 1, struct.pack("<HH", h, 0))      # ImageLength
    ifd += e(258, 3, 3, struct.pack("<I", bps_off))    # BitsPerSample ->off
    ifd += e(259, 3, 1, struct.pack("<HH", 1, 0))      # Compression none
    ifd += e(262, 3, 1, struct.pack("<HH", 2, 0))      # Photometric RGB
    ifd += e(273, 4, 1, struct.pack("<I", strip_off))  # StripOffsets
    ifd += e(277, 3, 1, struct.pack("<HH", 3, 0))      # SamplesPerPixel
    ifd += e(278, 3, 1, struct.pack("<HH", h, 0))      # RowsPerStrip
    ifd += e(279, 4, 1, struct.pack("<I", len(strip)))  # StripByteCounts
    ifd += e(284, 3, 1, struct.pack("<HH", 1, 0))      # PlanarConfig
    ifd += e(339, 3, 1, struct.pack("<HH", 1, 0))      # SampleFormat uint
    ifd += struct.pack("<I", 0)                        # next IFD = 0
    return b"II*\x00" + struct.pack("<I", 8) + ifd + bps + strip


def _xps_package(fpage_xml, with_png=False, with_tiff=False):
    """Assemble a minimal valid OPC/XPS ZIP around a FixedPage payload."""
    ct = ('<?xml version="1.0" encoding="utf-8"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
          'content-types">'
          '<Default Extension="fdseq" ContentType="application/vnd.ms-package'
          '.xps-fixeddocumentsequence+xml"/>'
          '<Default Extension="fdoc" ContentType="application/vnd.ms-package'
          '.xps-fixeddocument+xml"/>'
          '<Default Extension="fpage" ContentType="application/vnd.ms-package'
          '.xps-fixedpage+xml"/>'
          '<Default Extension="rels" ContentType="application/vnd.openxml'
          'formats-package.relationships+xml"/>'
          '<Default Extension="png" ContentType="image/png"/>'
          '<Default Extension="tif" ContentType="image/tiff"/>'
          '</Types>')
    rels = ('<?xml version="1.0" encoding="utf-8"?>'
            '<Relationships xmlns="%s">'
            '<Relationship Id="R1" Target="/FixedDocSeq.fdseq" '
            'Type="http://schemas.microsoft.com/xps/2005/06/'
            'fixedrepresentation"/></Relationships>' % REL_NS)
    fdseq = ('<FixedDocumentSequence xmlns="%s">'
             '<DocumentReference Source="/Documents/1/FixedDoc.fdoc"/>'
             '</FixedDocumentSequence>' % XPS_NS)
    fdoc = ('<FixedDocument xmlns="%s">'
            '<PageContent Source="Pages/1.fpage"/></FixedDocument>' % XPS_NS)
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("FixedDocSeq.fdseq", fdseq)
        zf.writestr("Documents/1/FixedDoc.fdoc", fdoc)
        zf.writestr("Documents/1/Pages/1.fpage", fpage_xml)
        if with_png:
            zf.writestr("Resources/img.png", _png_rgb(16, 16))
        if with_tiff:
            zf.writestr("Resources/img.tif", _tiff_rgb(16, 16))
    return z.getvalue()


def xps_tiff():
    """FixedPage whose ImageBrush references a TIFF part -> xps/xpstiff.c and
    the libtiff read path (tif_getimage / tif_read), both dark in production."""
    fpage = (
        '<FixedPage Width="200" Height="200" xmlns="%s">' % XPS_NS +
        '<Path Data="M 0,0 L 200,0 200,200 0,200 Z"><Path.Fill>'
        '<ImageBrush ImageSource="/Resources/img.tif" '
        'Viewport="0,0,100,100" ViewportUnits="Absolute" '
        'TileMode="FlipX" Opacity="0.9"/></Path.Fill></Path>'
        '</FixedPage>')
    return _xps_package(fpage, with_tiff=True)


def xps_vector():
    """FixedPage of vector content: canvases (transform/clip/opacity), paths
    with complex geometry, solid/linear/radial/image/visual brushes."""
    fpage = (
        '<FixedPage Width="200" Height="200" xml:lang="en-us" xmlns="%s">' % XPS_NS +
        '<Canvas RenderTransform="1,0,0,1,0,0" Opacity="0.9">'
        '<Canvas.Clip><PathGeometry><PathFigure StartPoint="0,0" IsClosed="true">'
        '<PolyLineSegment Points="200,0 200,200 0,200"/></PathFigure>'
        '</PathGeometry></Canvas.Clip>'
        # solid fill path
        '<Path Fill="#FFCC0000" Data="M 10,10 L 90,10 90,90 10,90 Z"/>'
        # stroked, dashed path with caps/joins
        '<Path Stroke="#FF0000FF" StrokeThickness="3" StrokeDashArray="3 2" '
        'StrokeStartLineCap="Round" StrokeEndLineCap="Triangle" '
        'StrokeLineJoin="Round" Data="M 10,100 C 40,180 160,180 190,100"/>'
        # linear gradient fill via Path.Fill
        '<Path Data="M 100,10 L 190,10 190,90 100,90 Z"><Path.Fill>'
        '<LinearGradientBrush StartPoint="100,10" EndPoint="190,90">'
        '<LinearGradientBrush.GradientStops>'
        '<GradientStop Color="#FFFF0000" Offset="0"/>'
        '<GradientStop Color="#FF00FF00" Offset="0.5"/>'
        '<GradientStop Color="#FF0000FF" Offset="1"/>'
        '</LinearGradientBrush.GradientStops></LinearGradientBrush>'
        '</Path.Fill></Path>'
        # radial gradient
        '<Path Data="M 100,100 L 190,100 190,190 100,190 Z"><Path.Fill>'
        '<RadialGradientBrush Center="145,145" RadiusX="45" RadiusY="45" '
        'GradientOrigin="145,145">'
        '<RadialGradientBrush.GradientStops>'
        '<GradientStop Color="#FFFFFF00" Offset="0"/>'
        '<GradientStop Color="#FF000000" Offset="1"/>'
        '</RadialGradientBrush.GradientStops></RadialGradientBrush>'
        '</Path.Fill></Path>'
        # image brush referencing the PNG part
        '<Path Data="M 10,100 L 90,100 90,190 10,190 Z"><Path.Fill>'
        '<ImageBrush ImageSource="/Resources/img.png" '
        'Viewport="0,0,1,1" ViewportUnits="RelativeToBoundingBox" '
        'TileMode="Tile"/></Path.Fill></Path>'
        # explicit complex PathGeometry with arc + bezier segments
        '<Path Stroke="#FF008000" StrokeThickness="1"><Path.Data>'
        '<PathGeometry FillRule="EvenOdd">'
        '<PathFigure StartPoint="20,20">'
        '<ArcSegment Point="60,40" Size="20,20" RotationAngle="30" '
        'IsLargeArc="false" SweepDirection="Clockwise"/>'
        '<PolyBezierSegment Points="80,60 100,20 120,60 140,40 160,60 180,40"/>'
        '<QuadraticBezierSegment Point1="150,80" Point2="120,90"/>'
        '</PathFigure></PathGeometry></Path.Data></Path>'
        '</Canvas></FixedPage>')
    return _xps_package(fpage, with_png=True)


def xps_glyphs():
    """FixedPage with Glyphs elements (text) + opacity mask + visual brush.
    Glyphs reference a font part; even when the font fails to load the XML is
    fully parsed (expat) and the xpsglyphs dispatch runs."""
    fpage = (
        '<FixedPage Width="200" Height="200" xmlns="%s">' % XPS_NS +
        '<Glyphs Fill="#FF000000" FontUri="/Resources/font.ttf" '
        'FontRenderingEmSize="20" StyleSimulations="BoldSimulation" '
        'OriginX="10" OriginY="40" UnicodeString="Hello XPS" '
        'Indices="3,80;15;22"/>'
        '<Path Data="M 10,60 L 190,60 190,160 10,160 Z"><Path.OpacityMask>'
        '<LinearGradientBrush StartPoint="10,60" EndPoint="190,60">'
        '<LinearGradientBrush.GradientStops>'
        '<GradientStop Color="#00000000" Offset="0"/>'
        '<GradientStop Color="#FF000000" Offset="1"/>'
        '</LinearGradientBrush.GradientStops></LinearGradientBrush>'
        '</Path.OpacityMask>'
        '<Path.Fill><VisualBrush Viewport="0,0,0.5,0.5" '
        'ViewportUnits="RelativeToBoundingBox" TileMode="FlipXY">'
        '<VisualBrush.Visual><Path Fill="#FF3030FF" '
        'Data="M 0,0 L 40,0 40,40 0,40 Z"/></VisualBrush.Visual>'
        '</VisualBrush></Path.Fill></Path>'
        '</FixedPage>')
    # include a (minimal, likely-unparseable) font part so the loader path runs
    z = io.BytesIO()
    pkg = _xps_package(fpage, with_png=False)
    zin = zipfile.ZipFile(io.BytesIO(pkg), "r")
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in zin.namelist():
            zf.writestr(n, zin.read(n))
        zf.writestr("Resources/font.ttf", b"\x00\x01\x00\x00" + b"\x00" * 64)
    return z.getvalue()


# --------------------------------------------------------------------------
def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "gs_seeds"
    os.makedirs(out, exist_ok=True)
    ps_dir = os.path.join(out, "ps")        # for gstoraster / device fuzzers
    pxl_dir = os.path.join(out, "pxl")
    pcl_dir = os.path.join(out, "pcl")
    xps_dir = os.path.join(out, "xps")      # for gs_xps_fuzzer
    for name, gen in [
        ("colorspaces.ps", ps_colorspaces),
        ("color_rendering.ps", ps_color_rendering),
        ("shadings.ps", ps_shadings),
        ("transparency.ps", ps_transparency),
        ("images.ps", ps_images),
        ("image_scaling.ps", ps_image_scaling),
        ("paths.ps", ps_paths),
        ("pagedevice_params.ps", ps_pagedevice_params),
        ("halftones.ps", ps_halftones),
        ("dsc.ps", ps_dsc),
        ("fonts_text.ps", ps_fonts_text),
    ]:
        w(ps_dir, name, gen())
    for name, gen in [
        ("vector.xps", xps_vector),
        ("glyphs.xps", xps_glyphs),
        ("tiff.xps", xps_tiff),
    ]:
        w(xps_dir, name, gen())
    w(pxl_dir, "seed.bin", pclxl_seed())
    w(pcl_dir, "seed.pcl", pcl5_seed())
    total = sum(len(files) for _, _, files in os.walk(out))
    sys.stderr.write("generate_seeds.py: wrote %d seeds under %s\n"
                     % (total, out))


if __name__ == "__main__":
    main()
