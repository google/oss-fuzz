#!/bin/bash -eux
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

cd $SRC/cups

# Configure and build CUPS as a static library
./configure \
    --disable-shared \
    --enable-static \
    --without-java \
    --without-perl \
    --without-php \
    --without-python \
    --disable-gssapi \
    CC="$CC" \
    CXX="$CXX" \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CXXFLAGS" \
    LDFLAGS="$LIB_FUZZING_ENGINE"

make -j$(nproc) cups/libcups.a 2>/dev/null || make -j$(nproc)

CUPS_LIBS="$SRC/cups/cups/libcups.a"
CUPS_INCLUDE="-I$SRC/cups"

# Build fuzz_ipp
$CC $CFLAGS $CUPS_INCLUDE -o $OUT/fuzz_ipp \
    $SRC/fuzz_ipp.c $CUPS_LIBS $LIB_FUZZING_ENGINE \
    -lssl -lcrypto -lz -lpthread

# Build fuzz_ppd
$CC $CFLAGS $CUPS_INCLUDE -o $OUT/fuzz_ppd \
    $SRC/fuzz_ppd.c $CUPS_LIBS $LIB_FUZZING_ENGINE \
    -lssl -lcrypto -lz -lpthread

# Build fuzz_http
$CC $CFLAGS $CUPS_INCLUDE -o $OUT/fuzz_http \
    $SRC/fuzz_http.c $CUPS_LIBS $LIB_FUZZING_ENGINE \
    -lssl -lcrypto -lz -lpthread

# Seed corpus for IPP (use a minimal IPP/1.1 get-printer-attributes request)
IPP_SEED="$OUT/fuzz_ipp_seed_corpus.zip"
mkdir -p /tmp/ipp_seed
# Minimal IPP/1.1 (0x0101) get-printer-attributes (0x000b)
printf '\x01\x01\x00\x0b\x00\x00\x00\x01\x01\x47\x00\x12attributes-charset\x00\x05utf-8\x48\x00\x1battributes-natural-language\x00\x02en\x03' \
    > /tmp/ipp_seed/minimal_get_printer_attrs.bin
zip -j "$IPP_SEED" /tmp/ipp_seed/*.bin

# Seed corpus for PPD
PPD_SEED="$OUT/fuzz_ppd_seed_corpus.zip"
mkdir -p /tmp/ppd_seed
cat > /tmp/ppd_seed/minimal.ppd << 'EOF'
*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PCFileName: "FUZZ.PPD"
*Manufacturer: "Fuzz"
*Product: "(FuzzPrinter)"
*ModelName: "Fuzz Printer"
*NickName: "Fuzz Printer"
*ShortNickName: "Fuzz Printer"
*PSVersion: "(3010.107) 3"
*LanguageLevel: "3"
*ColorDevice: False
*DefaultColorSpace: Gray
*FileSystem: False
*Throughput: "1"
*LandscapeOrientation: Plus90
*VariablePaperSize: False
*TTRasterizer: Type42
*Default*PageSize: Letter
*PageSize Letter/Letter: "<</PageSize[612 792]>>setpagedevice"
*CloseUI: *PageSize
EOF
zip -j "$PPD_SEED" /tmp/ppd_seed/*.ppd
